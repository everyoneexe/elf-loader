#include "process_maps.hpp"
#include <cstdint>

#include <iostream>
#include <sys/mman.h>
#include <unistd.h>

int main() {
  try {
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) return 1;
    void* mapping = mmap(nullptr, static_cast<std::size_t>(page_size),
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) return 1;
    const auto address = reinterpret_cast<std::uintptr_t>(mapping);
    const auto maps = elfloader::read_process_maps(getpid());
    bool found = false;
    for (const auto& entry : maps) {
      if (entry.start <= address && address < entry.end && entry.readable &&
          entry.writable) {
        found = true;
        break;
      }
    }
    elfloader::validate_process_range(getpid(), address,
                                      static_cast<std::size_t>(page_size), true,
                                      true);
    bool rejected = false;
    try {
      elfloader::validate_process_range(getpid(), 1, 1, true, false);
    } catch (const std::exception&) {
      rejected = true;
    }
    munmap(mapping, static_cast<std::size_t>(page_size));
    if (!found || !rejected) return 1;
    std::cout << "process_maps=0\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "process-maps-test: " << error.what() << '\n';
    return 1;
  }
}
