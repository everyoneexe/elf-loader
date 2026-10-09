#include "remote_modules.hpp"

#include <filesystem>
#include <iostream>
#include <string>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char** argv) {
  if (argc != 2) return 2;
  try {
    const auto modules = elfloader::list_remote_modules(getpid());
    const std::filesystem::path executable =
        std::filesystem::canonical("/proc/self/exe");
    bool found_self = false;
    for (const auto& module : modules) {
      if (std::filesystem::equivalent(module.path, executable)) {
        found_self = module.load_bias != 0 && module.start < module.end;
      }
    }
    const auto symbol = elfloader::resolve_remote_symbol(
        getpid(), executable.filename().string(), "remote_test_export");
    if (!found_self || !symbol || symbol->address == 0 ||
        symbol->module.path != executable) {
      std::cerr << "remote module or symbol resolution failed\n";
      return 1;
    }

    const std::string pid = std::to_string(getpid());
    if (fork() == 0) {
      execl(argv[1], argv[1], "--modules", pid.c_str(), nullptr);
      _exit(3);
    }
    int status = 0;
    wait(&status);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return 1;
    std::cout << "remote_modules=0\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "remote-modules-test: " << error.what() << '\n';
    return 1;
  }
}

extern "C" __attribute__((visibility("default"))) int remote_test_export() {
  return 42;
}
