#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <vector>

namespace elfloader {

struct RemoteModule {
  std::filesystem::path path;
  std::uintptr_t load_bias = 0;
  std::uintptr_t start = 0;
  std::uintptr_t end = 0;
};

struct RemoteSymbol {
  RemoteModule module;
  std::string name;
  std::uintptr_t address = 0;
  std::uint64_t size = 0;
};

std::vector<RemoteModule> list_remote_modules(pid_t pid);
std::optional<RemoteSymbol> resolve_remote_symbol(pid_t pid,
                                                  std::string_view module,
                                                  std::string_view symbol);

}  // namespace elfloader
