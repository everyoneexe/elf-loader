#include "elf_image.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <filesystem>
#include <functional>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace {

std::vector<std::byte> read_bytes(const std::filesystem::path& path) {
  const elfloader::ElfImage image(path);
  return {image.bytes().begin(), image.bytes().end()};
}

bool rejects(std::vector<std::byte> bytes,
             const std::function<void(std::vector<std::byte>&)>& mutate,
             const std::string& expected) {
  mutate(bytes);
  try {
    const elfloader::ElfImage image(std::move(bytes), "mutated-fixture");
    (void)image;
  } catch (const elfloader::Error& error) {
    return std::string(error.what()).find(expected) != std::string::npos;
  }
  return false;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "usage: " << argv[0] << " ELF\n";
    return 2;
  }

  const auto original = read_bytes(argv[1]);
  const elfloader::ElfImage valid(original, "valid-fixture");
  if (valid.dynamic().needed.empty() || valid.dynamic().relr_size == 0) {
    std::cerr << "valid fixture lacks expected dynamic metadata\n";
    return 1;
  }

  int failures = 0;
  failures += !rejects(original, [](auto& bytes) { bytes.resize(3); },
                       "truncated ELF header");
  failures += !rejects(original, [](auto& bytes) {
    reinterpret_cast<Elf64_Ehdr*>(bytes.data())->e_phoff =
        std::numeric_limits<Elf64_Off>::max();
  }, "program-header table outside image");
  failures += !rejects(original, [](auto& bytes) {
    auto* header = reinterpret_cast<Elf64_Ehdr*>(bytes.data());
    auto* programs = reinterpret_cast<Elf64_Phdr*>(bytes.data() + header->e_phoff);
    for (std::size_t index = 0; index < header->e_phnum; ++index) {
      if (programs[index].p_type == PT_LOAD) {
        programs[index].p_filesz = programs[index].p_memsz + 1;
        return;
      }
    }
  }, "segment file range outside image");
  failures += !rejects(original, [](auto& bytes) {
    auto* header = reinterpret_cast<Elf64_Ehdr*>(bytes.data());
    auto* programs = reinterpret_cast<Elf64_Phdr*>(bytes.data() + header->e_phoff);
    for (std::size_t index = 0; index < header->e_phnum; ++index) {
      if (programs[index].p_type == PT_LOAD) {
        programs[index].p_flags |= PF_W | PF_X;
        return;
      }
    }
  }, "writable executable PT_LOAD is forbidden");
  failures += !rejects(original, [](auto& bytes) {
    auto* header = reinterpret_cast<Elf64_Ehdr*>(bytes.data());
    auto* programs = reinterpret_cast<Elf64_Phdr*>(bytes.data() + header->e_phoff);
    for (std::size_t index = 0; index < header->e_phnum; ++index) {
      if (programs[index].p_type != PT_DYNAMIC) continue;
      auto* dynamic = reinterpret_cast<Elf64_Dyn*>(bytes.data() + programs[index].p_offset);
      const std::size_t count = programs[index].p_filesz / sizeof(Elf64_Dyn);
      for (std::size_t entry = 0; entry < count; ++entry) {
        if (dynamic[entry].d_tag == DT_STRTAB) {
          dynamic[entry].d_un.d_ptr = std::numeric_limits<Elf64_Addr>::max();
          return;
        }
      }
    }
  }, "DT_STRTAB: range has no file backing");
  failures += !rejects(original, [](auto& bytes) {
    auto* header = reinterpret_cast<Elf64_Ehdr*>(bytes.data());
    auto* programs = reinterpret_cast<Elf64_Phdr*>(bytes.data() + header->e_phoff);
    for (std::size_t index = 0; index < header->e_phnum; ++index) {
      if (programs[index].p_type != PT_DYNAMIC) continue;
      auto* dynamic = reinterpret_cast<Elf64_Dyn*>(bytes.data() + programs[index].p_offset);
      const std::size_t count = programs[index].p_filesz / sizeof(Elf64_Dyn);
      for (std::size_t entry = 0; entry < count; ++entry) {
        if (dynamic[entry].d_tag == DT_NULL) dynamic[entry].d_tag = DT_DEBUG;
      }
    }
  }, "unterminated PT_DYNAMIC table");

  if (failures != 0) {
    std::cerr << "parser regressions failed=" << failures << '\n';
    return 1;
  }
  std::cout << "parser_regressions=0\n";
  return 0;
}
