#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <spawn.h>
#include <string>
#include <string_view>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;

namespace {

struct ChildResult {
  int status = -1;
  std::string output;
  bool timed_out = false;
};

ChildResult run_child(const char* loader, const char* fixture,
                      std::chrono::milliseconds timeout) {
  int output_pipe[2]{};
  if (pipe2(output_pipe, O_CLOEXEC | O_NONBLOCK) != 0) {
    throw std::runtime_error(std::string("pipe2: ") + std::strerror(errno));
  }

  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  posix_spawn_file_actions_adddup2(&actions, output_pipe[1], STDOUT_FILENO);
  posix_spawn_file_actions_adddup2(&actions, output_pipe[1], STDERR_FILENO);
  posix_spawn_file_actions_addclose(&actions, output_pipe[0]);
  posix_spawn_file_actions_addclose(&actions, output_pipe[1]);

  std::array<char*, 3> arguments{
      const_cast<char*>(loader), const_cast<char*>(fixture), nullptr};
  pid_t child = -1;
  const int spawn_error =
      posix_spawn(&child, loader, &actions, nullptr, arguments.data(), environ);
  posix_spawn_file_actions_destroy(&actions);
  close(output_pipe[1]);
  if (spawn_error != 0) {
    close(output_pipe[0]);
    throw std::runtime_error(std::string("posix_spawn: ") +
                             std::strerror(spawn_error));
  }

  ChildResult result;
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  bool child_exited = false;
  while (!child_exited) {
    std::array<char, 512> buffer{};
    for (;;) {
      const ssize_t count = read(output_pipe[0], buffer.data(), buffer.size());
      if (count > 0) {
        result.output.append(buffer.data(), static_cast<std::size_t>(count));
        continue;
      }
      if (count == -1 && errno == EINTR) continue;
      break;
    }

    const pid_t waited = waitpid(child, &result.status, WNOHANG);
    if (waited == child) {
      child_exited = true;
      break;
    }
    if (waited == -1) {
      close(output_pipe[0]);
      throw std::runtime_error(std::string("waitpid: ") + std::strerror(errno));
    }
    if (std::chrono::steady_clock::now() >= deadline) {
      result.timed_out = true;
      kill(child, SIGKILL);
      while (waitpid(child, &result.status, 0) == -1 && errno == EINTR) {}
      child_exited = true;
      break;
    }
    pollfd descriptor{output_pipe[0], POLLIN, 0};
    (void)poll(&descriptor, 1, 10);
  }

  for (;;) {
    std::array<char, 512> buffer{};
    const ssize_t count = read(output_pipe[0], buffer.data(), buffer.size());
    if (count > 0) {
      result.output.append(buffer.data(), static_cast<std::size_t>(count));
      continue;
    }
    if (count == -1 && errno == EINTR) continue;
    break;
  }
  close(output_pipe[0]);
  return result;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 3) {
    std::cerr << "usage: " << argv[0] << " LOADER FIXTURE\n";
    return 2;
  }
  try {
    const ChildResult result =
        run_child(argv[1], argv[2], std::chrono::seconds(5));
    constexpr std::string_view expected =
        "fixture_probe=0\nfixture_lifecycle=0\n";
    if (result.timed_out || !WIFEXITED(result.status) ||
        WEXITSTATUS(result.status) != 0 || result.output != expected) {
      std::cerr << "owned process failed: timeout=" << result.timed_out
                << " status=" << result.status << "\n"
                << result.output;
      return 1;
    }
    std::cout << "owned_process=0\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "owned-process-test: " << error.what() << '\n';
    return 1;
  }
}
