#include "mapped_image.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <limits>
#include <sys/mman.h>
#include <unistd.h>

namespace elfloader {
namespace {

std::uintptr_t align_down(std::uintptr_t value, std::size_t alignment) {
  return value & ~(static_cast<std::uintptr_t>(alignment) - 1);
}

std::uintptr_t align_up(std::uintptr_t value, std::size_t alignment) {
  if (value > std::numeric_limits<std::uintptr_t>::max() - (alignment - 1)) {
    throw Error("page alignment overflows");
  }
  return (value + alignment - 1) & ~(static_cast<std::uintptr_t>(alignment) - 1);
}

int segment_protection(const Elf64_Phdr& segment) {
  int protection = 0;
  if (segment.p_flags & PF_R) protection |= PROT_READ;
  if (segment.p_flags & PF_W) protection |= PROT_WRITE;
  if (segment.p_flags & PF_X) protection |= PROT_EXEC;
  return protection;
}

}  // namespace

MappedImage::MappedImage(const ElfImage& image) : image_(image) {
  const long system_page_size = sysconf(_SC_PAGESIZE);
  if (system_page_size <= 0) throw Error("sysconf(_SC_PAGESIZE) failed");
  page_size_ = static_cast<std::size_t>(system_page_size);

  min_vaddr_ = std::numeric_limits<std::uintptr_t>::max();
  std::uintptr_t max_vaddr = 0;
  for (const Elf64_Phdr& segment : image_.program_headers()) {
    if (segment.p_type != PT_LOAD) continue;
    min_vaddr_ = std::min(min_vaddr_, align_down(segment.p_vaddr, page_size_));
    max_vaddr = std::max(max_vaddr,
        align_up(segment.p_vaddr + segment.p_memsz, page_size_));
  }
  if (min_vaddr_ == std::numeric_limits<std::uintptr_t>::max() ||
      max_vaddr <= min_vaddr_) {
    throw Error("invalid PT_LOAD address span");
  }
  mapping_size_ = max_vaddr - min_vaddr_;
  pages_.resize(mapping_size_ / page_size_);

  for (const Elf64_Phdr& segment : image_.program_headers()) {
    if (segment.p_type != PT_LOAD || segment.p_memsz == 0) continue;
    const std::size_t first = page_index(align_down(segment.p_vaddr, page_size_));
    const std::size_t last = page_index(align_up(segment.p_vaddr + segment.p_memsz,
                                                 page_size_) - 1);
    const int protection = segment_protection(segment);
    for (std::size_t page = first; page <= last; ++page) {
      PagePlan& plan = pages_[page];
      if (plan.populated && plan.final_protection != protection) {
        const int merged = plan.final_protection | protection;
        if ((merged & PROT_WRITE) && (merged & PROT_EXEC)) {
          throw Error("overlapping PT_LOAD pages violate W^X");
        }
        plan.final_protection = merged;
      } else {
        plan.final_protection = protection;
      }
      plan.populated = true;
    }
  }

  for (const Elf64_Phdr& segment : image_.program_headers()) {
    if (segment.p_type != PT_GNU_RELRO || segment.p_memsz == 0) continue;
    const std::uintptr_t start = align_down(segment.p_vaddr, page_size_);
    const std::uintptr_t end = align_up(segment.p_vaddr + segment.p_memsz,
                                        page_size_);
    if (start < min_vaddr_ || end - min_vaddr_ > mapping_size_) {
      throw Error("PT_GNU_RELRO outside mapped image");
    }
    for (std::size_t page = page_index(start); page < page_index(end); ++page) {
      pages_[page].relro = true;
    }
  }

  mapping_ = mmap(nullptr, mapping_size_, PROT_NONE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapping_ == MAP_FAILED) {
    mapping_ = nullptr;
    throw Error("mmap image reservation failed: " +
                std::string(std::strerror(errno)));
  }
  load_bias_ = reinterpret_cast<std::uintptr_t>(mapping_) - min_vaddr_;

  try {
    for (std::size_t page = 0; page < pages_.size();) {
      if (!pages_[page].populated) {
        ++page;
        continue;
      }
      std::size_t end = page + 1;
      while (end < pages_.size() && pages_[end].populated) ++end;
      protect_run(page, end, PROT_READ | PROT_WRITE);
      page = end;
    }
    for (const Elf64_Phdr& segment : image_.program_headers()) {
      if (segment.p_type != PT_LOAD || segment.p_filesz == 0) continue;
      const auto source = image_.file_range(segment.p_offset, segment.p_filesz);
      std::memcpy(reinterpret_cast<void*>(load_bias_ + segment.p_vaddr),
                  source.data(), source.size());
    }
  } catch (...) {
    munmap(mapping_, mapping_size_);
    mapping_ = nullptr;
    throw;
  }
}

MappedImage::~MappedImage() {
  if (mapping_) munmap(mapping_, mapping_size_);
}

std::size_t MappedImage::page_index(std::uint64_t virtual_address) const {
  if (virtual_address < min_vaddr_ ||
      virtual_address - min_vaddr_ >= mapping_size_) {
    throw Error("virtual page outside mapped image");
  }
  return (virtual_address - min_vaddr_) / page_size_;
}

void MappedImage::protect_run(std::size_t first, std::size_t last,
                              int protection) {
  if (first >= last || last > pages_.size()) throw Error("invalid protection run");
  void* address = reinterpret_cast<void*>(
      reinterpret_cast<std::uintptr_t>(mapping_) + first * page_size_);
  if (mprotect(address, (last - first) * page_size_, protection) != 0) {
    throw Error("mprotect failed: " + std::string(std::strerror(errno)));
  }
}

void MappedImage::enable_executable_segments() {
  for (std::size_t page = 0; page < pages_.size();) {
    if (!pages_[page].populated || !(pages_[page].final_protection & PROT_EXEC)) {
      ++page;
      continue;
    }
    std::size_t end = page + 1;
    while (end < pages_.size() && pages_[end].populated &&
           (pages_[end].final_protection & PROT_EXEC)) {
      ++end;
    }
    protect_run(page, end, PROT_READ | PROT_EXEC);
    page = end;
  }
}

void MappedImage::apply_final_protections() {
  for (std::size_t page = 0; page < pages_.size();) {
    const int protection = pages_[page].populated
                               ? pages_[page].final_protection
                               : PROT_NONE;
    std::size_t end = page + 1;
    while (end < pages_.size()) {
      const int next = pages_[end].populated
                           ? pages_[end].final_protection
                           : PROT_NONE;
      if (next != protection) break;
      ++end;
    }
    protect_run(page, end, protection);
    page = end;
  }
}

void MappedImage::seal_relro() {
  for (std::size_t page = 0; page < pages_.size();) {
    if (!pages_[page].relro) {
      ++page;
      continue;
    }
    std::size_t end = page + 1;
    while (end < pages_.size() && pages_[end].relro) ++end;
    protect_run(page, end, PROT_READ);
    page = end;
  }
}

bool MappedImage::has_writable_executable_page() const {
  return std::any_of(pages_.begin(), pages_.end(), [](const PagePlan& page) {
    return page.populated && (page.final_protection & PROT_WRITE) &&
           (page.final_protection & PROT_EXEC);
  });
}

bool MappedImage::range_is_read_only(std::uint64_t virtual_address,
                                     std::uint64_t size) const {
  if (size == 0 || virtual_address < min_vaddr_ ||
      virtual_address > std::numeric_limits<std::uint64_t>::max() - size ||
      virtual_address + size - min_vaddr_ > mapping_size_) {
    return false;
  }
  const std::size_t first = page_index(align_down(virtual_address, page_size_));
  const std::size_t last = page_index(align_up(virtual_address + size,
                                               page_size_) - 1);
  for (std::size_t page = first; page <= last; ++page) {
    if (!pages_[page].relro) return false;
  }
  return true;
}

}  // namespace elfloader
