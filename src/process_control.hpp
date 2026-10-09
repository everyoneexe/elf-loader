#pragma once

#include <chrono>
#include <filesystem>
#include <string>
#include <sys/types.h>

namespace elfloader {

struct ProcessInfo {
  pid_t pid = 0;
  uid_t uid = 0;
  char state = '?';
  std::string name;
  std::filesystem::path executable;
};

struct OwnedChildResult {
  pid_t pid = 0;
  bool timed_out = false;
  int exit_code = -1;
  int term_signal = 0;
};

ProcessInfo inspect_process(pid_t pid);
OwnedChildResult run_owned_process(
    char* const arguments[],
    std::chrono::milliseconds timeout = std::chrono::seconds(5));

}  // namespace elfloader
