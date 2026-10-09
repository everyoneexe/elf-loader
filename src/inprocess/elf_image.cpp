#include "elf_image.hpp"

#include <bit>
#include <cstring>
#include <fstream>
#include <limits>
#include <optional>
#include <sstream>
#include <utility>

namespace elfloader {
namespace {

template <typename T>
bool valid_range(T offset, T length, T size) {
  return offset <= size && length <= size - offset;
}

std::vector<std::byte> read_file(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary | std::ios::ate);
  if (!input) throw Error("cannot open " + path.string());
  const std::streamoff size = input.tellg();
  if (size < 0) throw Error("cannot size " + path.string());
  std::vector<std::byte> bytes(static_cast<std::size_t>(size));
  input.seekg(0);
  if (!bytes.empty() &&
      !input.read(reinterpret_cast<char*>(bytes.data()), size)) {
    throw Error("cannot read " + path.string());
  }
  return bytes;
}

std::string field_error(std::string_view field, std::string_view message) {
  return std::string(field) + ": " + std::string(message);
}

}  // namespace

ElfImage::ElfImage(std::filesystem::path path)
    : bytes_(read_file(path)), logical_name_(std::move(path).string()) {
  parse();
}

ElfImage::ElfImage(std::vector<std::byte> bytes, std::string logical_name)
    : bytes_(std::move(bytes)), logical_name_(std::move(logical_name)) {
  parse();
}

std::span<const std::byte> ElfImage::file_range(std::uint64_t offset,
                                                std::uint64_t size) const {
  if (!valid_range<std::uint64_t>(offset, size, bytes_.size())) {
    throw Error("file range outside image");
  }
  return {bytes_.data() + offset, static_cast<std::size_t>(size)};
}

std::uint64_t ElfImage::virtual_to_file(std::uint64_t address,
                                        std::uint64_t size) const {
  for (const Elf64_Phdr& segment : program_headers_) {
    if (segment.p_type != PT_LOAD || address < segment.p_vaddr) continue;
    const std::uint64_t relative = address - segment.p_vaddr;
    if (relative <= segment.p_filesz && size <= segment.p_filesz - relative) {
      return segment.p_offset + relative;
    }
  }
  throw Error("virtual range has no file backing");
}

std::string_view ElfImage::dynamic_string(std::size_t offset) const {
  if (offset >= dynamic_.strsz) throw Error("dynamic string offset outside DT_STRTAB");
  const std::uint64_t string_offset =
      virtual_to_file(dynamic_.strtab + offset, dynamic_.strsz - offset);
  const auto bytes = file_range(string_offset, dynamic_.strsz - offset);
  const void* terminator = std::memchr(bytes.data(), 0, bytes.size());
  if (!terminator) throw Error("unterminated dynamic string");
  return {reinterpret_cast<const char*>(bytes.data()),
          static_cast<std::size_t>(
              static_cast<const std::byte*>(terminator) - bytes.data())};
}

void ElfImage::parse() {
  if (bytes_.size() < sizeof(Elf64_Ehdr)) throw Error("truncated ELF header");
  header_ = reinterpret_cast<const Elf64_Ehdr*>(bytes_.data());
  if (std::memcmp(header_->e_ident, ELFMAG, SELFMAG) != 0) {
    throw Error("invalid ELF magic");
  }
  if (header_->e_ident[EI_CLASS] != ELFCLASS64 ||
      header_->e_ident[EI_DATA] != ELFDATA2LSB ||
      header_->e_ident[EI_VERSION] != EV_CURRENT ||
      header_->e_version != EV_CURRENT || header_->e_machine != EM_X86_64 ||
      header_->e_type != ET_DYN) {
    throw Error("expected little-endian x86_64 ET_DYN");
  }
  if (header_->e_ehsize != sizeof(Elf64_Ehdr) ||
      header_->e_phentsize != sizeof(Elf64_Phdr) || header_->e_phnum == 0) {
    throw Error("invalid ELF header sizes");
  }
  const std::uint64_t table_size =
      static_cast<std::uint64_t>(header_->e_phnum) * sizeof(Elf64_Phdr);
  if (!valid_range<std::uint64_t>(header_->e_phoff, table_size, bytes_.size())) {
    throw Error("program-header table outside image");
  }
  program_headers_ = {
      reinterpret_cast<const Elf64_Phdr*>(bytes_.data() + header_->e_phoff),
      header_->e_phnum};

  const Elf64_Phdr* dynamic_segment = nullptr;
  bool has_load = false;
  for (const Elf64_Phdr& segment : program_headers_) {
    if (segment.p_filesz > segment.p_memsz ||
        !valid_range<std::uint64_t>(segment.p_offset, segment.p_filesz,
                                    bytes_.size())) {
      throw Error("segment file range outside image");
    }
    if (segment.p_align != 0 && !std::has_single_bit(segment.p_align)) {
      throw Error("segment alignment is not a power of two");
    }
    if (segment.p_align > 1 &&
        (segment.p_offset % segment.p_align) !=
            (segment.p_vaddr % segment.p_align)) {
      throw Error("segment offset and virtual address are incongruent");
    }
    if (segment.p_type == PT_LOAD) {
      has_load = true;
      if (segment.p_vaddr >
          std::numeric_limits<std::uint64_t>::max() - segment.p_memsz) {
        throw Error("segment virtual range overflows");
      }
      if ((segment.p_flags & PF_W) && (segment.p_flags & PF_X)) {
        throw Error("writable executable PT_LOAD is forbidden");
      }
    } else if (segment.p_type == PT_DYNAMIC) {
      if (dynamic_segment) throw Error("multiple PT_DYNAMIC segments");
      dynamic_segment = &segment;
    }
  }
  if (!has_load) throw Error("ELF has no PT_LOAD segment");
  if (!dynamic_segment) throw Error("ELF has no PT_DYNAMIC segment");
  parse_dynamic(*dynamic_segment);
}

void ElfImage::parse_dynamic(const Elf64_Phdr& segment) {
  if (segment.p_filesz % sizeof(Elf64_Dyn) != 0) {
    throw Error("PT_DYNAMIC size is not entry-aligned");
  }
  const auto bytes = file_range(segment.p_offset, segment.p_filesz);
  const auto entries = std::span{
      reinterpret_cast<const Elf64_Dyn*>(bytes.data()),
      bytes.size() / sizeof(Elf64_Dyn)};
  bool terminated = false;
  bool valid_syment = false;
  bool valid_relaent = false;
  bool valid_relrent = false;

  for (const Elf64_Dyn& entry : entries) {
    if (entry.d_tag == DT_NULL) {
      terminated = true;
      break;
    }
    switch (entry.d_tag) {
      case DT_STRTAB: dynamic_.strtab = entry.d_un.d_ptr; break;
      case DT_STRSZ: dynamic_.strsz = entry.d_un.d_val; break;
      case DT_SYMTAB: dynamic_.symtab = entry.d_un.d_ptr; break;
      case DT_SYMENT: valid_syment = entry.d_un.d_val == sizeof(Elf64_Sym); break;
      case DT_HASH: dynamic_.hash = entry.d_un.d_ptr; break;
      case DT_GNU_HASH: dynamic_.gnu_hash = entry.d_un.d_ptr; break;
      case DT_RELA: dynamic_.rela = entry.d_un.d_ptr; break;
      case DT_RELASZ: dynamic_.rela_size = entry.d_un.d_val; break;
      case DT_RELAENT: valid_relaent = entry.d_un.d_val == sizeof(Elf64_Rela); break;
      case DT_JMPREL: dynamic_.jmprel = entry.d_un.d_ptr; break;
      case DT_PLTRELSZ: dynamic_.jmprel_size = entry.d_un.d_val; break;
      case DT_PLTREL:
        if (entry.d_un.d_val != DT_RELA) throw Error("DT_REL PLT is unsupported");
        break;
      case DT_RELR: dynamic_.relr = entry.d_un.d_ptr; break;
      case DT_RELRSZ: dynamic_.relr_size = entry.d_un.d_val; break;
      case DT_RELRENT: valid_relrent = entry.d_un.d_val == sizeof(Elf64_Relr); break;
      case DT_VERSYM: dynamic_.versym = entry.d_un.d_ptr; break;
      case DT_VERNEED: dynamic_.verneed = entry.d_un.d_ptr; break;
      case DT_VERNEEDNUM: dynamic_.verneed_count = entry.d_un.d_val; break;
      case DT_VERDEF: dynamic_.verdef = entry.d_un.d_ptr; break;
      case DT_VERDEFNUM: dynamic_.verdef_count = entry.d_un.d_val; break;
      case DT_SONAME: dynamic_.soname = entry.d_un.d_val; break;
      case DT_RUNPATH: dynamic_.runpath = entry.d_un.d_val; break;
      case DT_RPATH: dynamic_.rpath = entry.d_un.d_val; break;
      case DT_NEEDED: dynamic_.needed.push_back(entry.d_un.d_val); break;
      case DT_INIT: dynamic_.init = entry.d_un.d_ptr; break;
      case DT_INIT_ARRAY: dynamic_.init_array = entry.d_un.d_ptr; break;
      case DT_INIT_ARRAYSZ: dynamic_.init_array_size = entry.d_un.d_val; break;
      case DT_FINI: dynamic_.fini = entry.d_un.d_ptr; break;
      case DT_FINI_ARRAY: dynamic_.fini_array = entry.d_un.d_ptr; break;
      case DT_FINI_ARRAYSZ: dynamic_.fini_array_size = entry.d_un.d_val; break;
      case DT_TEXTREL: throw Error("DT_TEXTREL is forbidden");
      default: break;
    }
  }
  if (!terminated) throw Error("unterminated PT_DYNAMIC table");
  if (!dynamic_.strtab || !dynamic_.strsz || !dynamic_.symtab ||
      !valid_syment || (!dynamic_.hash && !dynamic_.gnu_hash)) {
    throw Error("incomplete dynamic symbol metadata");
  }
  if ((dynamic_.rela || dynamic_.rela_size) &&
      (!dynamic_.rela || dynamic_.rela_size % sizeof(Elf64_Rela) != 0 ||
       !valid_relaent)) {
    throw Error("invalid DT_RELA table");
  }
  if ((dynamic_.jmprel || dynamic_.jmprel_size) &&
      (!dynamic_.jmprel || dynamic_.jmprel_size % sizeof(Elf64_Rela) != 0)) {
    throw Error("invalid DT_JMPREL table");
  }
  if ((dynamic_.relr || dynamic_.relr_size) &&
      (!dynamic_.relr || dynamic_.relr_size % sizeof(Elf64_Relr) != 0 ||
       !valid_relrent)) {
    throw Error("invalid DT_RELR table");
  }

  validate_dynamic_pointer(dynamic_.strtab, dynamic_.strsz, "DT_STRTAB");
  validate_dynamic_pointer(dynamic_.symtab, sizeof(Elf64_Sym), "DT_SYMTAB");
  if (dynamic_.hash) validate_dynamic_pointer(dynamic_.hash, 2 * sizeof(std::uint32_t), "DT_HASH");
  if (dynamic_.gnu_hash) validate_dynamic_pointer(dynamic_.gnu_hash, 4 * sizeof(std::uint32_t), "DT_GNU_HASH");
  if (dynamic_.rela) validate_dynamic_pointer(dynamic_.rela, dynamic_.rela_size, "DT_RELA");
  if (dynamic_.jmprel) validate_dynamic_pointer(dynamic_.jmprel, dynamic_.jmprel_size, "DT_JMPREL");
  if (dynamic_.relr) validate_dynamic_pointer(dynamic_.relr, dynamic_.relr_size, "DT_RELR");
  if (dynamic_.versym) validate_dynamic_pointer(dynamic_.versym, sizeof(Elf64_Half), "DT_VERSYM");
  if (dynamic_.verneed) validate_dynamic_pointer(dynamic_.verneed, sizeof(Elf64_Verneed), "DT_VERNEED");
  if (dynamic_.verdef) validate_dynamic_pointer(dynamic_.verdef, sizeof(Elf64_Verdef), "DT_VERDEF");
  if (dynamic_.init_array) validate_dynamic_pointer(dynamic_.init_array, dynamic_.init_array_size, "DT_INIT_ARRAY");
  if (dynamic_.fini_array) validate_dynamic_pointer(dynamic_.fini_array, dynamic_.fini_array_size, "DT_FINI_ARRAY");
  for (const std::size_t offset : dynamic_.needed) {
    (void)dynamic_string(offset);
  }
  if (dynamic_.soname) (void)dynamic_string(*dynamic_.soname);
  if (dynamic_.runpath) (void)dynamic_string(*dynamic_.runpath);
  if (dynamic_.rpath) (void)dynamic_string(*dynamic_.rpath);
}

void ElfImage::validate_dynamic_pointer(std::uint64_t address,
                                        std::uint64_t size,
                                        std::string_view field) const {
  try {
    (void)virtual_to_file(address, size);
  } catch (const Error&) {
    throw Error(field_error(field, "range has no file backing"));
  }
}

}  // namespace elfloader
