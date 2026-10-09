#pragma once

#include "elf_image.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace elfloader {

class MappedImage {
 public:
  explicit MappedImage(const ElfImage& image);
  MappedImage(const MappedImage&) = delete;
  MappedImage& operator=(const MappedImage&) = delete;
  ~MappedImage();

  std::uintptr_t load_bias() const noexcept { return load_bias_; }
  std::uintptr_t min_vaddr() const noexcept { return min_vaddr_; }
  std::size_t size() const noexcept { return mapping_size_; }

  template <typename T>
  T* at(std::uint64_t virtual_address, std::size_t count = 1) const {
    if (virtual_address < min_vaddr_ || count > SIZE_MAX / sizeof(T)) {
      throw Error("mapped address outside image");
    }
    const std::uint64_t offset = virtual_address - min_vaddr_;
    const std::size_t bytes = count * sizeof(T);
    if (offset > mapping_size_ || bytes > mapping_size_ - offset) {
      throw Error("mapped range outside image");
    }
    return reinterpret_cast<T*>(load_bias_ + virtual_address);
  }

  void enable_executable_segments();
  void apply_final_protections();
  void seal_relro();

  bool has_writable_executable_page() const;
  bool range_is_read_only(std::uint64_t virtual_address,
                          std::uint64_t size) const;

 private:
  struct PagePlan {
    int final_protection = 0;
    bool populated = false;
    bool relro = false;
  };

  std::size_t page_index(std::uint64_t virtual_address) const;
  void protect_run(std::size_t first, std::size_t last, int protection);

  const ElfImage& image_;
  void* mapping_ = nullptr;
  std::size_t mapping_size_ = 0;
  std::size_t page_size_ = 0;
  std::uintptr_t min_vaddr_ = 0;
  std::uintptr_t load_bias_ = 0;
  std::vector<PagePlan> pages_;
};

}  // namespace elfloader
