#pragma once

#include <cstddef>
#include <cstdint>
#include <elf.h>
#include <filesystem>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <optional>
#include <vector>

namespace elfloader {

class Error final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

struct DynamicInfo {
  std::uint64_t strtab = 0;
  std::size_t strsz = 0;
  std::uint64_t symtab = 0;
  std::uint64_t hash = 0;
  std::uint64_t gnu_hash = 0;
  std::uint64_t rela = 0;
  std::size_t rela_size = 0;
  std::uint64_t jmprel = 0;
  std::size_t jmprel_size = 0;
  std::uint64_t relr = 0;
  std::size_t relr_size = 0;
  std::uint64_t versym = 0;
  std::uint64_t verneed = 0;
  std::size_t verneed_count = 0;
  std::uint64_t verdef = 0;
  std::size_t verdef_count = 0;
  std::optional<std::size_t> soname;
  std::optional<std::size_t> runpath;
  std::optional<std::size_t> rpath;
  std::uint64_t init = 0;
  std::uint64_t init_array = 0;
  std::size_t init_array_size = 0;
  std::uint64_t fini = 0;
  std::uint64_t fini_array = 0;
  std::size_t fini_array_size = 0;
  std::vector<std::size_t> needed;
};

class ElfImage {
 public:
  explicit ElfImage(std::filesystem::path path);
  ElfImage(std::vector<std::byte> bytes, std::string logical_name);

  const Elf64_Ehdr& header() const noexcept { return *header_; }
  std::span<const Elf64_Phdr> program_headers() const noexcept { return program_headers_; }
  const DynamicInfo& dynamic() const noexcept { return dynamic_; }
  std::span<const std::byte> bytes() const noexcept { return bytes_; }
  std::string_view logical_name() const noexcept { return logical_name_; }

  std::span<const std::byte> file_range(std::uint64_t offset,
                                        std::uint64_t size) const;
  std::uint64_t virtual_to_file(std::uint64_t address,
                                std::uint64_t size) const;
  std::string_view dynamic_string(std::size_t offset) const;

 private:
  void parse();
  void parse_dynamic(const Elf64_Phdr& segment);
  void validate_dynamic_pointer(std::uint64_t address,
                                std::uint64_t size,
                                std::string_view field) const;

  std::vector<std::byte> bytes_;
  std::string logical_name_;
  const Elf64_Ehdr* header_ = nullptr;
  std::span<const Elf64_Phdr> program_headers_;
  DynamicInfo dynamic_;
};

}  // namespace elfloader
