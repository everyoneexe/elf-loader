#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <sys/types.h>
#include <vector>

namespace elfloader {

struct ProcessMapEntry {
  std::uintptr_t start = 0;
  std::uintptr_t end = 0;
  std::uint64_t offset = 0;
  std::uint64_t inode = 0;
  bool readable = false;
  bool writable = false;
  bool executable = false;
  bool private_mapping = false;
  std::string device;
  std::filesystem::path path;
};

std::vector<ProcessMapEntry> read_process_maps(pid_t pid);
void validate_process_range(pid_t pid, std::uintptr_t address, std::size_t size,
                            bool require_read, bool require_write);

}  // namespace elfloader
