#include "inprocess/elf_image.hpp"
#include "inprocess/mapped_image.hpp"
#include "inprocess/dependency_graph.hpp"
#include "process_control.hpp"
#include "ptrace_control.hpp"
#include "process_maps.hpp"
#include "remote_modules.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <dlfcn.h>
#include <elf.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <link.h>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

using LoaderError = elfloader::Error;

struct Dependency {
  void* handle = nullptr;
  std::string name;

  Dependency() = default;
  Dependency(void* value, std::string dependency_name)
      : handle(value), name(std::move(dependency_name)) {}
  Dependency(const Dependency&) = delete;
  Dependency& operator=(const Dependency&) = delete;
  Dependency(Dependency&& other) noexcept
      : handle(std::exchange(other.handle, nullptr)), name(std::move(other.name)) {}
  Dependency& operator=(Dependency&& other) noexcept {
    if (this != &other) {
      if (handle) dlclose(handle);
      handle = std::exchange(other.handle, nullptr);
      name = std::move(other.name);
    }
    return *this;
  }
  ~Dependency() { if (handle) dlclose(handle); }
};
class InProcessElf {
 public:
  enum class Stage { Relocated, Initialized };

  explicit InProcessElf(std::filesystem::path path,
                        Stage stage = Stage::Initialized)
      : path_(std::move(path)), graph_(path_), image_(path_), mapping_(image_),
        load_bias_(mapping_.load_bias()) {
    parse_dynamic();
    load_dependencies();
    mapping_.enable_executable_segments();
    relocate();
    register_unwind();
    mapping_.apply_final_protections();
    mapping_.seal_relro();
    if (stage == Stage::Initialized) run_constructors();
  }

  InProcessElf(const InProcessElf&) = delete;
  InProcessElf& operator=(const InProcessElf&) = delete;

  ~InProcessElf() {
    if (constructors_ran_) run_destructors();
    unregister_unwind();
    dependencies_.clear();
  }

  void* symbol(std::string_view name) const {
    if (!symtab_ || !strtab_) return nullptr;
    const std::size_t count = symbol_count();
    for (std::size_t index = 0; index < count; ++index) {
      const Elf64_Sym& symbol = symtab_[index];
      if (symbol.st_name >= strsz_ || symbol.st_shndx == SHN_UNDEF) continue;
      if (name == strtab_ + symbol.st_name) {
        return reinterpret_cast<void*>(symbol_address(index));
      }
    }
    return nullptr;
  }

 private:
  using UnwindRegister = void (*)(void*);
  using UnwindDeregister = void (*)(void*);

  template <typename T>
  T* at(std::uintptr_t virtual_address) const {
    return mapping_.at<T>(virtual_address);
  }


  void parse_eh_frame_header(std::uintptr_t address) {
    const auto* header = reinterpret_cast<const std::uint8_t*>(address);
    if (header[0] != 1 || header[1] != 0x1b) {
      throw LoaderError("unsupported .eh_frame_hdr encoding");
    }
    std::int32_t relative = 0;
    std::memcpy(&relative, header + 4, sizeof(relative));
    eh_frame_hdr_ = reinterpret_cast<void*>(address + 4 + relative);
  }

  void parse_dynamic() {
    const elfloader::DynamicInfo& dynamic = image_.dynamic();
    strtab_ = at<char>(dynamic.strtab);
    strsz_ = dynamic.strsz;
    symtab_ = at<Elf64_Sym>(dynamic.symtab);
    if (dynamic.hash) hash_ = at<std::uint32_t>(dynamic.hash);
    if (dynamic.gnu_hash) gnu_hash_ = at<std::uint32_t>(dynamic.gnu_hash);
    if (dynamic.rela) rela_ = at<Elf64_Rela>(dynamic.rela);
    rela_size_ = dynamic.rela_size;
    if (dynamic.jmprel) jmprel_ = at<Elf64_Rela>(dynamic.jmprel);
    jmprel_size_ = dynamic.jmprel_size;
    if (dynamic.relr) relr_ = at<Elf64_Relr>(dynamic.relr);
    relr_size_ = dynamic.relr_size;
    if (dynamic.versym) versym_ = at<Elf64_Half>(dynamic.versym);
    if (dynamic.verneed) verneed_ = at<Elf64_Verneed>(dynamic.verneed);
    verneed_count_ = dynamic.verneed_count;
    needed_offsets_ = dynamic.needed;
    init_ = dynamic.init;
    init_array_ = dynamic.init_array;
    init_array_size_ = dynamic.init_array_size;
    fini_ = dynamic.fini;
    fini_array_ = dynamic.fini_array;
    fini_array_size_ = dynamic.fini_array_size;

    for (const Elf64_Phdr& segment : image_.program_headers()) {
      if (segment.p_type == PT_GNU_EH_FRAME) {
        parse_eh_frame_header(load_bias_ + segment.p_vaddr);
      }
      if (segment.p_type == PT_TLS) {
        throw LoaderError("static TLS relocations require a TLS runtime module");
      }
    }
  }

  void load_dependencies() {
    for (const elfloader::DependencyGraph::Node* node :
         graph_.breadth_first_scope()) {
      if (node == &graph_.root() || !node->host_handle) continue;
      dependencies_.emplace_back(
          dlopen(node->path.empty() ? node->soname.c_str() : node->path.c_str(),
                 RTLD_NOW | RTLD_LOCAL),
          node->soname);
      if (!dependencies_.back().handle) {
        throw LoaderError("DT_NEEDED " + node->soname + ": " + dlerror());
      }
    }
  }

  std::size_t symbol_count() const {
    if (hash_) return hash_[1];
    if (!gnu_hash_) throw LoaderError("ELF has neither DT_HASH nor DT_GNU_HASH");
    const std::uint32_t bucket_count = gnu_hash_[0];
    const std::uint32_t symbol_offset = gnu_hash_[1];
    const std::uint32_t bloom_size = gnu_hash_[2];
    const auto* buckets = reinterpret_cast<const std::uint32_t*>(
        reinterpret_cast<const Elf64_Xword*>(gnu_hash_ + 4) + bloom_size);
    const auto* chains = buckets + bucket_count;
    std::uint32_t maximum = symbol_offset;
    for (std::uint32_t bucket = 0; bucket < bucket_count; ++bucket) {
      std::uint32_t index = buckets[bucket];
      if (index < symbol_offset) continue;
      while ((chains[index - symbol_offset] & 1U) == 0) ++index;
      maximum = std::max(maximum, index + 1);
    }
    return maximum;
  }

  std::optional<std::string> required_version(std::size_t symbol_index) const {
    if (!versym_ || !verneed_) return std::nullopt;
    const Elf64_Half version_index = versym_[symbol_index] & 0x7fffU;
    if (version_index <= 1) return std::nullopt;
    auto* need = verneed_;
    for (std::size_t i = 0; i < verneed_count_; ++i) {
      auto* auxiliary = reinterpret_cast<Elf64_Vernaux*>(
          reinterpret_cast<std::uint8_t*>(need) + need->vn_aux);
      for (std::size_t j = 0; j < need->vn_cnt; ++j) {
        if ((auxiliary->vna_other & 0x7fffU) == version_index) {
          if (auxiliary->vna_name >= strsz_) throw LoaderError("invalid version string offset");
          return std::string(strtab_ + auxiliary->vna_name);
        }
        if (auxiliary->vna_next == 0) break;
        auxiliary = reinterpret_cast<Elf64_Vernaux*>(
            reinterpret_cast<std::uint8_t*>(auxiliary) + auxiliary->vna_next);
      }
      if (need->vn_next == 0) break;
      need = reinterpret_cast<Elf64_Verneed*>(
          reinterpret_cast<std::uint8_t*>(need) + need->vn_next);
    }
    return std::nullopt;
  }

  std::uintptr_t resolve_external(std::size_t index) const {
    const Elf64_Sym& symbol = symtab_[index];
    if (symbol.st_name >= strsz_) throw LoaderError("invalid symbol name offset");
    const char* name = strtab_ + symbol.st_name;
    const auto version = required_version(index);
    void* address = nullptr;
    for (const Dependency& dependency : dependencies_) {
      address = version ? dlvsym(dependency.handle, name, version->c_str())
                        : dlsym(dependency.handle, name);
      if (address) break;
    }
    if (!address) {
      address = version ? dlvsym(RTLD_DEFAULT, name, version->c_str())
                        : dlsym(RTLD_DEFAULT, name);
    }
    if (!address && ELF64_ST_BIND(symbol.st_info) != STB_WEAK) {
      throw LoaderError("unresolved symbol: " + std::string(name) +
                        (version ? "@" + *version : ""));
    }
    return reinterpret_cast<std::uintptr_t>(address);
  }

  std::uintptr_t symbol_address(std::size_t index) const {
    const Elf64_Sym& symbol = symtab_[index];
    if (symbol.st_shndx == SHN_UNDEF) return resolve_external(index);
    std::uintptr_t value = load_bias_ + symbol.st_value;
    if (ELF64_ST_TYPE(symbol.st_info) == STT_GNU_IFUNC) {
      value = reinterpret_cast<std::uintptr_t>((*reinterpret_cast<void* (*)()>(value))());
    }
    return value;
  }

  void apply_rela(const Elf64_Rela& relocation) {
    const std::uint32_t type = ELF64_R_TYPE(relocation.r_info);
    const std::size_t symbol_index = ELF64_R_SYM(relocation.r_info);
    auto* target = at<std::uintptr_t>(relocation.r_offset);
    const std::uintptr_t addend = static_cast<std::uintptr_t>(relocation.r_addend);
    switch (type) {
      case R_X86_64_NONE: break;
      case R_X86_64_RELATIVE: *target = load_bias_ + addend; break;
      case R_X86_64_64:
      case R_X86_64_GLOB_DAT:
      case R_X86_64_JUMP_SLOT: *target = symbol_address(symbol_index) + addend; break;
      case R_X86_64_DTPMOD64:
      case R_X86_64_DTPOFF64: {
        const Elf64_Sym& symbol = symtab_[symbol_index];
        if (symbol.st_name >= strsz_) throw LoaderError("invalid TLS symbol name");
        const char* name = strtab_ + symbol.st_name;
        bool found = false;
        for (const Dependency& dependency : dependencies_) {
          void* address = dlsym(dependency.handle, name);
          if (!address) continue;
          std::size_t module_id = 0;
          void* tls_block = nullptr;
          if (dlinfo(dependency.handle, RTLD_DI_TLS_MODID, &module_id) != 0 ||
              dlinfo(dependency.handle, RTLD_DI_TLS_DATA, &tls_block) != 0 ||
              module_id == 0 || !tls_block) {
            continue;
          }
          *target = type == R_X86_64_DTPMOD64
                        ? module_id
                        : reinterpret_cast<std::uintptr_t>(address) -
                              reinterpret_cast<std::uintptr_t>(tls_block) + addend;
          found = true;
          break;
        }
        if (!found) throw LoaderError("cannot resolve delegated TLS symbol");
        break;
      }
      case R_X86_64_IRELATIVE: {
        auto resolver = reinterpret_cast<std::uintptr_t (*)()>(load_bias_ + addend);
        *target = resolver();
        break;
      }
      default: throw LoaderError("unsupported x86_64 relocation " + std::to_string(type));
    }
  }

  void apply_relr() {
    if (!relr_ || relr_size_ == 0) return;
    std::uintptr_t* where = nullptr;
    const std::size_t count = relr_size_ / sizeof(Elf64_Relr);
    for (std::size_t i = 0; i < count; ++i) {
      const Elf64_Relr entry = relr_[i];
      if ((entry & 1U) == 0) {
        where = at<std::uintptr_t>(entry);
        *where += load_bias_;
        ++where;
      } else {
        if (!where) throw LoaderError("invalid leading RELR bitmap");
        for (unsigned bit = 1; bit < 8U * sizeof(Elf64_Relr); ++bit) {
          if (entry & (Elf64_Relr{1} << bit)) where[bit - 1] += load_bias_;
        }
        where += 8U * sizeof(Elf64_Relr) - 1;
      }
    }
  }

  void relocate() {
    apply_relr();
    if (rela_size_ % sizeof(Elf64_Rela) != 0 || jmprel_size_ % sizeof(Elf64_Rela) != 0) {
      throw LoaderError("misaligned RELA table");
    }
    for (std::size_t i = 0; i < rela_size_ / sizeof(Elf64_Rela); ++i) apply_rela(rela_[i]);
    for (std::size_t i = 0; i < jmprel_size_ / sizeof(Elf64_Rela); ++i) apply_rela(jmprel_[i]);
  }

  void register_unwind() {
    if (!eh_frame_hdr_) return;
    unwind_register_ = reinterpret_cast<UnwindRegister>(dlsym(RTLD_DEFAULT, "__register_frame"));
    unwind_deregister_ = reinterpret_cast<UnwindDeregister>(dlsym(RTLD_DEFAULT, "__deregister_frame"));
    if (!unwind_register_ || !unwind_deregister_) throw LoaderError("unwind registration API unavailable");
    unwind_register_(eh_frame_hdr_);
    unwind_registered_ = true;
  }

  void unregister_unwind() noexcept {
    if (unwind_registered_) unwind_deregister_(eh_frame_hdr_);
    unwind_registered_ = false;
  }


  void run_constructors() {
    using Function = void (*)();
    if (init_) reinterpret_cast<Function>(load_bias_ + init_)();
    if (init_array_) {
      auto* functions = at<Function>(init_array_);
      for (std::size_t i = 0; i < init_array_size_ / sizeof(Function); ++i) {
        if (functions[i]) functions[i]();
      }
    }
    constructors_ran_ = true;
  }

  void run_destructors() noexcept {
    using Function = void (*)();
    try {
      if (fini_array_) {
        auto* functions = at<Function>(fini_array_);
        for (std::size_t i = fini_array_size_ / sizeof(Function); i > 0; --i) {
          if (functions[i - 1]) functions[i - 1]();
        }
      }
      if (fini_) reinterpret_cast<Function>(load_bias_ + fini_)();
    } catch (...) {
    }
    constructors_ran_ = false;
  }

  std::filesystem::path path_;
  elfloader::DependencyGraph graph_;
  elfloader::ElfImage image_;
  elfloader::MappedImage mapping_;
  std::uintptr_t load_bias_ = 0;
  const char* strtab_ = nullptr;
  std::size_t strsz_ = 0;
  const Elf64_Sym* symtab_ = nullptr;
  const std::uint32_t* hash_ = nullptr;
  const std::uint32_t* gnu_hash_ = nullptr;
  const Elf64_Half* versym_ = nullptr;
  Elf64_Verneed* verneed_ = nullptr;
  std::size_t verneed_count_ = 0;
  Elf64_Rela* rela_ = nullptr;
  std::size_t rela_size_ = 0;
  Elf64_Rela* jmprel_ = nullptr;
  std::size_t jmprel_size_ = 0;
  Elf64_Relr* relr_ = nullptr;
  std::size_t relr_size_ = 0;
  std::vector<std::size_t> needed_offsets_;
  std::vector<Dependency> dependencies_;
  std::uintptr_t init_ = 0;
  std::uintptr_t init_array_ = 0;
  std::size_t init_array_size_ = 0;
  std::uintptr_t fini_ = 0;
  std::uintptr_t fini_array_ = 0;
  std::size_t fini_array_size_ = 0;
  std::uintptr_t relro_start_ = 0;
  std::size_t relro_size_ = 0;
  void* eh_frame_hdr_ = nullptr;
  bool has_tls_ = false;
  bool constructors_ran_ = false;
  bool unwind_registered_ = false;
  UnwindRegister unwind_register_ = nullptr;
  UnwindDeregister unwind_deregister_ = nullptr;
};

std::uint64_t parse_number(std::string_view value, std::string_view field,
                           int base = 10) {
  std::uint64_t result = 0;
  const auto [end, error] = std::from_chars(
      value.data(), value.data() + value.size(), result, base);
  if (error != std::errc{} || end != value.data() + value.size()) {
    throw LoaderError(std::string(field) + " must be a valid integer");
  }
  return result;
}

long parse_positive_number(std::string_view value, std::string_view field) {
  const std::uint64_t result = parse_number(value, field);
  if (result == 0 || result > static_cast<std::uint64_t>(
                                  std::numeric_limits<long>::max())) {
    throw LoaderError(std::string(field) + " must be a positive integer");
  }
  return static_cast<long>(result);
}

std::vector<std::byte> parse_hex_bytes(std::string_view value) {
  if (value.empty() || value.size() % 2 != 0) {
    throw LoaderError("hex bytes must contain an even number of digits");
  }
  std::vector<std::byte> bytes;
  bytes.reserve(value.size() / 2);
  for (std::size_t offset = 0; offset < value.size(); offset += 2) {
    unsigned parsed = 0;
    const auto [end, error] = std::from_chars(
        value.data() + offset, value.data() + offset + 2, parsed, 16);
    if (error != std::errc{} || end != value.data() + offset + 2) {
      throw LoaderError("hex bytes contain a non-hexadecimal digit");
    }
    bytes.push_back(static_cast<std::byte>(parsed));
  }
  return bytes;
}

void print_usage(const char* program) {
  std::cerr << "usage:\n"
            << "  " << program << " [--relocate-only] ELF\n"
            << "  " << program << " --pid PID\n"
            << "  " << program << " --ptrace-attach PID\n"
            << "  " << program << " --maps PID\n"
            << "  " << program << " --modules PID\n"
            << "  " << program << " --resolve PID MODULE SYMBOL\n"
            << "  " << program << " --remote-read PID ADDRESS SIZE\n"
            << "  " << program << " --remote-write PID ADDRESS HEX_BYTES\n"
            << "  " << program
            << " --spawn [--timeout-ms MILLISECONDS] -- COMMAND [ARG...]\n";
}

}  // namespace

extern "C" int fixture_verify_events() __attribute__((weak));

int main(int argc, char** argv) {
  try {
    if (argc == 3 && std::string_view(argv[1]) == "--pid") {
      const auto pid = static_cast<pid_t>(parse_positive_number(argv[2], "PID"));
      const elfloader::ProcessInfo process = elfloader::inspect_process(pid);
      std::cout << "pid=" << process.pid << '\n'
                << "uid=" << process.uid << '\n'
                << "state=" << process.state << '\n'
                << "name=" << process.name << '\n'
                << "exe=" << process.executable.string() << '\n';
      return 0;
    }

    if (argc == 3 && std::string_view(argv[1]) == "--ptrace-attach") {
      const auto pid = static_cast<pid_t>(parse_positive_number(argv[2], "PID"));
      const elfloader::PtraceAttachResult result =
          elfloader::attach_and_detach(pid);
      std::cout << "ptrace_pid=" << result.pid << '\n'
                << "stop_signal=" << result.stop_signal << '\n'
                << "detached=1\n";
      return 0;
    }

    if (argc == 3 && std::string_view(argv[1]) == "--maps") {
      const auto pid = static_cast<pid_t>(parse_positive_number(argv[2], "PID"));
      for (const elfloader::ProcessMapEntry& entry :
           elfloader::read_process_maps(pid)) {
        std::cout << std::hex << entry.start << '-' << entry.end << ' '
                  << (entry.readable ? 'r' : '-')
                  << (entry.writable ? 'w' : '-')
                  << (entry.executable ? 'x' : '-')
                  << (entry.private_mapping ? 'p' : 's') << ' '
                  << entry.offset << ' ' << entry.device << ' ' << std::dec
                  << entry.inode;
        if (!entry.path.empty()) std::cout << ' ' << entry.path.string();
        std::cout << '\n';
      }
      return 0;
    }

    if (argc == 3 && std::string_view(argv[1]) == "--modules") {
      const auto pid = static_cast<pid_t>(parse_positive_number(argv[2], "PID"));
      for (const elfloader::RemoteModule& module :
           elfloader::list_remote_modules(pid)) {
        std::cout << "module=" << module.path.string() << " base=0x" << std::hex
                  << module.load_bias << " range=0x" << module.start << "-0x"
                  << module.end << std::dec << '\n';
      }
      return 0;
    }

    if (argc == 5 && std::string_view(argv[1]) == "--resolve") {
      const auto pid = static_cast<pid_t>(parse_positive_number(argv[2], "PID"));
      const auto symbol = elfloader::resolve_remote_symbol(pid, argv[3], argv[4]);
      if (!symbol) throw LoaderError("remote symbol not found");
      std::cout << "module=" << symbol->module.path.string() << '\n'
                << "symbol=" << symbol->name << '\n'
                << "address=0x" << std::hex << symbol->address << std::dec << '\n'
                << "size=" << symbol->size << '\n';
      return 0;
    }

    if (argc == 5 && std::string_view(argv[1]) == "--remote-read") {
      const auto pid = static_cast<pid_t>(parse_positive_number(argv[2], "PID"));
      std::string_view address_text(argv[3]);
      if (address_text.starts_with("0x") || address_text.starts_with("0X")) {
        address_text.remove_prefix(2);
      }
      const auto address = static_cast<std::uintptr_t>(
          parse_number(address_text, "address", 16));
      const std::size_t size = static_cast<std::size_t>(
          parse_positive_number(argv[4], "size"));
      const elfloader::RemoteReadResult result =
          elfloader::read_remote_memory(pid, address, size);
      std::cout << "ptrace_pid=" << result.pid << '\n'
                << "stop_signal=" << result.stop_signal << '\n'
                << "bytes_read=" << result.bytes.size() << '\n'
                << "backend=" << elfloader::memory_backend_name(result.backend)
                << '\n'
                << "data=";
      constexpr char digits[] = "0123456789abcdef";
      for (const std::byte byte : result.bytes) {
        const unsigned value = std::to_integer<unsigned>(byte);
        std::cout << digits[value >> 4] << digits[value & 0xf];
      }
      std::cout << "\ndetached=1\n";
      return 0;
    }

    if (argc == 5 && std::string_view(argv[1]) == "--remote-write") {
      const auto pid = static_cast<pid_t>(parse_positive_number(argv[2], "PID"));
      std::string_view address_text(argv[3]);
      if (address_text.starts_with("0x") || address_text.starts_with("0X")) {
        address_text.remove_prefix(2);
      }
      const auto address = static_cast<std::uintptr_t>(
          parse_number(address_text, "address", 16));
      const std::vector<std::byte> bytes = parse_hex_bytes(argv[4]);
      const elfloader::RemoteWriteResult result =
          elfloader::write_remote_memory(pid, address, bytes);
      std::cout << "ptrace_pid=" << result.pid << '\n'
                << "stop_signal=" << result.stop_signal << '\n'
                << "bytes_written=" << result.bytes_written << '\n'
                << "backend=" << elfloader::memory_backend_name(result.backend)
                << '\n'
                << "detached=1\n";
      return 0;
    }

    if (argc >= 4 && std::string_view(argv[1]) == "--spawn") {
      std::chrono::milliseconds timeout = std::chrono::seconds(5);
      int command_index = 2;
      if (argc >= 6 && std::string_view(argv[2]) == "--timeout-ms") {
        timeout = std::chrono::milliseconds(
            parse_positive_number(argv[3], "timeout"));
        command_index = 4;
      }
      if (command_index >= argc || std::string_view(argv[command_index]) != "--" ||
          command_index + 1 >= argc) {
        print_usage(argv[0]);
        return 2;
      }
      const elfloader::OwnedChildResult child =
          elfloader::run_owned_process(argv + command_index + 1, timeout);
      std::cout << "child_pid=" << child.pid << '\n'
                << "timed_out=" << (child.timed_out ? 1 : 0) << '\n'
                << "exit_code=" << child.exit_code << '\n'
                << "term_signal=" << child.term_signal << '\n';
      if (child.timed_out) return 124;
      if (child.term_signal != 0) return 128 + child.term_signal;
      return child.exit_code;
    }

    bool relocate_only = false;
    std::filesystem::path path;
    if (argc == 2) {
      path = argv[1];
    } else if (argc == 3 && std::string_view(argv[1]) == "--relocate-only") {
      relocate_only = true;
      path = argv[2];
    } else {
      print_usage(argv[0]);
      return 2;
    }

    if (relocate_only) {
      InProcessElf image(std::filesystem::canonical(path),
                         InProcessElf::Stage::Relocated);
      std::cout << "relocation_stage=0\n";
      return 0;
    }
    int probe_result = 1;
    {
      InProcessElf image(std::filesystem::canonical(path));
      using Probe = int (*)();
      auto probe = reinterpret_cast<Probe>(image.symbol("fixture_probe"));
      if (!probe) throw LoaderError("fixture_probe export not found");
      probe_result = probe();
      std::cout << "fixture_probe=" << probe_result << '\n';
    }
    const int lifecycle_result = fixture_verify_events ? fixture_verify_events() : 0;
    std::cout << "fixture_lifecycle=" << lifecycle_result << '\n';
    return probe_result == 0 && lifecycle_result == 0 ? 0 : 1;
  } catch (const std::exception& error) {
    std::cerr << "inprocess-loader: " << error.what() << '\n';
    return 1;
  }
}
