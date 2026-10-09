#include "ptrace_control.hpp"

#include <cerrno>
#include <csignal>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

void wait_for_signal_child(pid_t pid, int expected_signal) {
  int status = 0;
  while (waitpid(pid, &status, 0) < 0) {
    if (errno == EINTR) continue;
    throw std::runtime_error("waitpid child: " +
                             std::string(std::strerror(errno)));
  }
  if (!WIFSIGNALED(status) || WTERMSIG(status) != expected_signal) {
    throw std::runtime_error("child did not terminate with expected signal");
  }
}

void test_library_attach() {
  const pid_t child = fork();
  if (child < 0) {
    throw std::runtime_error("fork: " + std::string(std::strerror(errno)));
  }
  if (child == 0) {
    for (;;) pause();
  }

  try {
    const elfloader::PtraceAttachResult result =
        elfloader::attach_and_detach(child);
    if (result.pid != child || result.stop_signal != SIGTRAP) {
      throw std::runtime_error("ptrace attach result mismatch");
    }
    if (kill(child, SIGTERM) != 0) {
      throw std::runtime_error("kill child: " +
                               std::string(std::strerror(errno)));
    }
    wait_for_signal_child(child, SIGTERM);
  } catch (...) {
    (void)kill(child, SIGKILL);
    while (waitpid(child, nullptr, 0) < 0 && errno == EINTR) {
    }
    throw;
  }
}

void test_cli_attach(const char* loader) {
  int tracer_pipe[2]{};
  int ready_pipe[2]{};
  int start_pipe[2]{};
  if (pipe(tracer_pipe) != 0 || pipe(ready_pipe) != 0 || pipe(start_pipe) != 0) {
    throw std::runtime_error("pipe: " + std::string(std::strerror(errno)));
  }

  const pid_t target = fork();
  if (target < 0) {
    throw std::runtime_error("fork target: " +
                             std::string(std::strerror(errno)));
  }
  if (target == 0) {
    close(tracer_pipe[1]);
    close(ready_pipe[0]);
    close(start_pipe[0]);
    close(start_pipe[1]);
    pid_t tracer = -1;
    if (read(tracer_pipe[0], &tracer, sizeof(tracer)) != sizeof(tracer) ||
        prctl(PR_SET_PTRACER, tracer, 0, 0, 0) != 0) {
      _exit(2);
    }
    const char ready = '1';
    if (write(ready_pipe[1], &ready, sizeof(ready)) != sizeof(ready)) _exit(3);
    for (;;) pause();
  }

  const pid_t tracer = fork();
  if (tracer < 0) {
    (void)kill(target, SIGKILL);
    wait_for_signal_child(target, SIGKILL);
    throw std::runtime_error("fork tracer: " +
                             std::string(std::strerror(errno)));
  }
  if (tracer == 0) {
    close(start_pipe[1]);
    close(tracer_pipe[0]);
    close(tracer_pipe[1]);
    close(ready_pipe[0]);
    close(ready_pipe[1]);
    char start = 0;
    if (read(start_pipe[0], &start, sizeof(start)) != sizeof(start)) _exit(4);
    const std::string target_text = std::to_string(target);
    execl(loader, loader, "--ptrace-attach", target_text.c_str(), nullptr);
    _exit(5);
  }

  close(tracer_pipe[0]);
  close(ready_pipe[1]);
  close(start_pipe[0]);
  if (write(tracer_pipe[1], &tracer, sizeof(tracer)) != sizeof(tracer)) {
    throw std::runtime_error("write tracer PID failed");
  }
  char ready = 0;
  if (read(ready_pipe[0], &ready, sizeof(ready)) != sizeof(ready)) {
    throw std::runtime_error("target readiness failed");
  }
  const char start = '1';
  if (write(start_pipe[1], &start, sizeof(start)) != sizeof(start)) {
    throw std::runtime_error("start tracer failed");
  }
  close(tracer_pipe[1]);
  close(ready_pipe[0]);
  close(start_pipe[1]);

  int tracer_status = 0;
  while (waitpid(tracer, &tracer_status, 0) < 0 && errno == EINTR) {
  }
  (void)kill(target, SIGTERM);
  wait_for_signal_child(target, SIGTERM);
  if (!WIFEXITED(tracer_status) || WEXITSTATUS(tracer_status) != 0) {
    throw std::runtime_error("ptrace CLI attach failed");
  }
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "usage: " << argv[0] << " LOADER\n";
    return 2;
  }
  try {
    test_library_attach();
    test_cli_attach(argv[1]);
    std::cout << "ptrace_control=0\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ptrace-control-test: " << error.what() << '\n';
    return 1;
  }
}
