#include "process_control.hpp"

#include <stdexcept>

#include <cerrno>
#include <charconv>
#include <csignal>
#include <cstring>
#include <fstream>
#include <poll.h>
#include <spawn.h>
#include <sstream>
#include <string_view>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

extern char** environ;

namespace elfloader {
namespace {

std::filesystem::path proc_path(pid_t pid, std::string_view entry) {
  return std::filesystem::path("/proc") / std::to_string(pid) / entry;
}

uid_t parse_uid(const std::string& status) {
  std::istringstream lines(status);
  std::string line;
  while (std::getline(lines, line)) {
    if (line.rfind("Uid:", 0) != 0) continue;
    std::string_view value(line);
    value.remove_prefix(4);
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
      value.remove_prefix(1);
    }
    uid_t uid = 0;
    const auto [end, error] = std::from_chars(
        value.data(), value.data() + value.size(), uid);
    if (error == std::errc{} && end != value.data()) return uid;
    break;
  }
  throw std::runtime_error("cannot parse process UID");
}

std::string read_text(const std::filesystem::path& path) {
  std::ifstream input(path);
  if (!input) throw std::runtime_error("cannot read " + path.string());
  return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

}  // namespace

ProcessInfo inspect_process(pid_t pid) {
  if (pid <= 0) throw std::runtime_error("PID must be a positive integer");

  const std::filesystem::path base = std::filesystem::path("/proc") /
                                     std::to_string(pid);
  struct stat metadata {};
  if (stat(base.c_str(), &metadata) != 0) {
    throw std::runtime_error("cannot inspect PID " + std::to_string(pid) + ": " +
                             std::string(std::strerror(errno)));
  }

  ProcessInfo result;
  result.pid = pid;
  const std::string status = read_text(proc_path(pid, "status"));
  result.uid = parse_uid(status);

  std::istringstream lines(status);
  std::string line;
  while (std::getline(lines, line)) {
    if (line.rfind("Name:", 0) == 0) {
      result.name = line.substr(5);
      const std::size_t first = result.name.find_first_not_of(" \t");
      if (first != std::string::npos) result.name.erase(0, first);
    } else if (line.rfind("State:", 0) == 0) {
      const std::size_t first = line.find_first_not_of(" \t", 6);
      if (first != std::string::npos) result.state = line[first];
    }
  }

  std::error_code error;
  result.executable = std::filesystem::read_symlink(proc_path(pid, "exe"), error);
  if (error) {
    throw std::runtime_error("cannot read executable for PID " +
                             std::to_string(pid) + ": " + error.message());
  }
  return result;
}

OwnedChildResult run_owned_process(char* const arguments[],
                                   std::chrono::milliseconds timeout) {
  if (!arguments || !arguments[0] || arguments[0][0] == '\0') {
    throw std::runtime_error("spawn requires an executable");
  }
  if (timeout.count() <= 0) {
    throw std::runtime_error("spawn timeout must be positive");
  }

  posix_spawnattr_t attributes;
  int setup_error = posix_spawnattr_init(&attributes);
  if (setup_error != 0) {
    throw std::runtime_error("cannot initialize child attributes: " +
                             std::string(std::strerror(setup_error)));
  }
  setup_error = posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP);
  if (setup_error == 0) setup_error = posix_spawnattr_setpgroup(&attributes, 0);
  if (setup_error != 0) {
    posix_spawnattr_destroy(&attributes);
    throw std::runtime_error("cannot configure child process group: " +
                             std::string(std::strerror(setup_error)));
  }

  pid_t child = -1;
  const int spawn_error = posix_spawnp(&child, arguments[0], nullptr, &attributes,
                                       arguments, environ);
  posix_spawnattr_destroy(&attributes);
  if (spawn_error != 0) {
    throw std::runtime_error("cannot spawn " + std::string(arguments[0]) + ": " +
                             std::string(std::strerror(spawn_error)));
  }

  OwnedChildResult result;
  result.pid = child;
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  int status = 0;
  for (;;) {
    const pid_t waited = waitpid(child, &status, WNOHANG);
    if (waited == child) break;
    if (waited < 0) {
      const int saved_errno = errno;
      kill(-child, SIGKILL);
      while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
      }
      throw std::runtime_error("waitpid failed: " +
                               std::string(std::strerror(saved_errno)));
    }
    if (std::chrono::steady_clock::now() >= deadline) {
      result.timed_out = true;
      if (kill(-child, SIGTERM) != 0 && errno != ESRCH) {
        const int saved_errno = errno;
        kill(-child, SIGKILL);
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
        }
        throw std::runtime_error("cannot terminate child: " +
                                 std::string(std::strerror(saved_errno)));
      }
      const auto terminate_deadline = std::chrono::steady_clock::now() +
                                      std::chrono::milliseconds(250);
      for (;;) {
        const pid_t terminated = waitpid(child, &status, WNOHANG);
        if (terminated == child) break;
        if (terminated < 0 && errno != EINTR) {
          throw std::runtime_error("waitpid failed after timeout: " +
                                   std::string(std::strerror(errno)));
        }
        if (std::chrono::steady_clock::now() >= terminate_deadline) {
          kill(-child, SIGKILL);
          while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
          }
          break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  if (WIFEXITED(status)) result.exit_code = WEXITSTATUS(status);
  if (WIFSIGNALED(status)) result.term_signal = WTERMSIG(status);
  return result;
}

}  // namespace elfloader
