#include "elf_image.hpp"
#include "mapped_image.hpp"

#include <elf.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/mman.h>

namespace {

bool mapping_has_wx(std::uintptr_t begin, std::uintptr_t end) {
  std::ifstream maps("/proc/self/maps");
  std::string line;
  while (std::getline(maps, line)) {
    std::istringstream fields(line);
    std::string range;
    std::string permissions;
    if (!(fields >> range >> permissions)) continue;
    const std::size_t separator = range.find('-');
    if (separator == std::string::npos) continue;
    const std::uintptr_t start = std::stoull(range.substr(0, separator), nullptr, 16);
    const std::uintptr_t finish = std::stoull(range.substr(separator + 1), nullptr, 16);
    if (finish <= begin || start >= end) continue;
    if (permissions.size() >= 3 && permissions[1] == 'w' && permissions[2] == 'x') {
      return true;
    }
  }
  return false;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) return 2;
  try {
    const elfloader::ElfImage image(std::filesystem::canonical(argv[1]));
    elfloader::MappedImage mapping(image);
    mapping.enable_executable_segments();
    if (mapping.has_writable_executable_page() ||
        mapping_has_wx(mapping.load_bias() + mapping.min_vaddr(),
                       mapping.load_bias() + mapping.min_vaddr() + mapping.size())) {
      std::cerr << "W^X invariant failed before final protection\n";
      return 1;
    }
    mapping.apply_final_protections();
    mapping.seal_relro();

    bool found_relro = false;
    for (const Elf64_Phdr& segment : image.program_headers()) {
      if (segment.p_type != PT_GNU_RELRO || segment.p_memsz == 0) continue;
      found_relro = true;
      if (!mapping.range_is_read_only(segment.p_vaddr, segment.p_memsz)) {
        std::cerr << "RELRO planning invariant failed\n";
        return 1;
      }
    }
    if (!found_relro || mapping_has_wx(mapping.load_bias() + mapping.min_vaddr(),
                                       mapping.load_bias() + mapping.min_vaddr() + mapping.size())) {
      std::cerr << "final mapping invariant failed\n";
      return 1;
    }
    std::cout << "mapping_invariants=0\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "mapping-test: " << error.what() << '\n';
    return 1;
  }
}
