#include "trace_session.hpp"

#include <atomic>
#include <cerrno>
#include <csignal>
#include <iostream>
#include <stdexcept>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

int main() {
  try {
    const pid_t child = fork();
    if (child < 0) throw std::runtime_error("fork failed");
    if (child == 0) {
      std::atomic<bool> running{true};
      std::vector<std::thread> workers;
      for (int index = 0; index < 3; ++index) {
        workers.emplace_back([&] {
          while (running.load(std::memory_order_relaxed)) std::this_thread::yield();
        });
      }
      for (;;) pause();
    }

    try {
      while (elfloader::list_process_threads(child).size() < 4) {
        std::this_thread::yield();
      }
      elfloader::TraceSession session(child);
      if (session.tids().size() < 4 || session.memory_tid() <= 0 ||
          session.leader_stop_signal() != SIGTRAP) {
        throw std::runtime_error("thread group was not fully stopped");
      }
      session.detach();
      if (kill(child, SIGTERM) != 0) throw std::runtime_error("kill failed");
      int status = 0;
      while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
      }
      if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGTERM) {
        throw std::runtime_error("thread group did not resume after detach");
      }
    } catch (...) {
      (void)kill(child, SIGKILL);
      while (waitpid(child, nullptr, 0) < 0 && errno == EINTR) {
      }
      throw;
    }
    std::cout << "trace_session=0\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "trace-session-test: " << error.what() << '\n';
    return 1;
  }
}
