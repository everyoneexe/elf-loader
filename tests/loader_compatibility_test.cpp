#include "dependency_graph.hpp"
#include "elf_image.hpp"
#include "mapped_image.hpp"

#include <elf.h>
#include <filesystem>
#include <iostream>
#include <map>
#include <set>
#include <string>

int main(int argc, char** argv) {
  if (argc != 2) return 2;
  try {
    const std::filesystem::path path = std::filesystem::canonical(argv[1]);
    const elfloader::ElfImage image(path);
    const elfloader::DependencyGraph graph(path);
    elfloader::MappedImage mapping(image);

    std::set<std::uint32_t> supported{
        R_X86_64_NONE, R_X86_64_RELATIVE, R_X86_64_64,
        R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT, R_X86_64_IRELATIVE,
        R_X86_64_DTPMOD64, R_X86_64_DTPOFF64};
    std::map<std::uint32_t, std::size_t> relocation_counts;
    const auto count_relocations = [&](std::uint64_t address, std::size_t size) {
      if (!address) return;
      const std::uint64_t offset = image.virtual_to_file(address, size);
      const auto bytes = image.file_range(offset, size);
      const auto* relocations = reinterpret_cast<const Elf64_Rela*>(bytes.data());
      for (std::size_t index = 0; index < size / sizeof(Elf64_Rela); ++index) {
        ++relocation_counts[ELF64_R_TYPE(relocations[index].r_info)];
      }
    };
    count_relocations(image.dynamic().rela, image.dynamic().rela_size);
    count_relocations(image.dynamic().jmprel, image.dynamic().jmprel_size);

    bool compatible = true;
    for (const auto& [type, count] : relocation_counts) {
      std::cout << "relocation[" << type << "]=" << count << '\n';
      if (!supported.contains(type)) compatible = false;
    }
    for (const auto& node : graph.nodes()) {
      std::cout << "dependency=" << node->soname
                << (node->host_managed ? ":host" : ":custom") << '\n';
    }
    for (const Elf64_Phdr& segment : image.program_headers()) {
      if (segment.p_type == PT_TLS) {
        std::cout << "owned_tls=1\n";
        compatible = false;
      }
    }
    std::cout << "wx_pages=" << (mapping.has_writable_executable_page() ? 1 : 0)
              << '\n';
    compatible = compatible && !mapping.has_writable_executable_page();
    std::cout << "compatibility=" << (compatible ? 0 : 1) << '\n';
    return compatible ? 0 : 1;
  } catch (const std::exception& error) {
    std::cerr << "compatibility-test: " << error.what() << '\n';
    return 1;
  }
}
