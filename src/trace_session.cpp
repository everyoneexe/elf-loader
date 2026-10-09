#include "trace_session.hpp"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <sys/ptrace.h>
#include <sys/wait.h>

namespace elfloader {

std::vector<pid_t> list_process_threads(pid_t pid) {
  if (pid <= 0) throw std::runtime_error("PID must be a positive integer");
  const std::filesystem::path task =
      std::filesystem::path("/proc") / std::to_string(pid) / "task";
  std::error_code error;
  std::vector<pid_t> tids;
  for (std::filesystem::directory_iterator entries(task, error), end;
       !error && entries != end; entries.increment(error)) {
    const std::string name = entries->path().filename().string();
    pid_t tid = 0;
    const auto [last, conversion] =
        std::from_chars(name.data(), name.data() + name.size(), tid);
    if (conversion == std::errc{} && last == name.data() + name.size() &&
        tid > 0) {
      tids.push_back(tid);
    }
  }
  if (error) {
    throw std::runtime_error("cannot enumerate threads for PID " +
                             std::to_string(pid) + ": " + error.message());
  }
  std::sort(tids.begin(), tids.end());
  if (tids.empty()) throw std::runtime_error("process has no threads");
  return tids;
}

TraceSession::TraceSession(pid_t pid) : pid_(pid) {
  try {
    seize_new_threads();
    for (;;) {
      const std::vector<pid_t> current = list_process_threads(pid_);
      bool found_new = false;
      for (const pid_t tid : current) {
        if (!std::binary_search(tids_.begin(), tids_.end(), tid)) {
          found_new = true;
          break;
        }
      }
      if (!found_new) break;
      seize_new_threads();
    }
  } catch (...) {
    detach_noexcept();
    throw;
  }
}

void TraceSession::seize_new_threads() {
  const std::vector<pid_t> current = list_process_threads(pid_);
  for (const pid_t tid : current) {
    if (std::binary_search(tids_.begin(), tids_.end(), tid)) continue;
    if (ptrace(PTRACE_SEIZE, tid, nullptr, nullptr) != 0) {
      if (errno == ESRCH) continue;
      throw std::runtime_error("ptrace seize TID " + std::to_string(tid) +
                               ": " + std::string(std::strerror(errno)));
    }
    const auto position = std::lower_bound(tids_.begin(), tids_.end(), tid);
    tids_.insert(position, tid);
    if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) != 0) {
      throw std::runtime_error("ptrace interrupt TID " + std::to_string(tid) +
                               ": " + std::string(std::strerror(errno)));
    }
    int status = 0;
    pid_t waited = -1;
    do {
      waited = waitpid(tid, &status, __WALL);
    } while (waited < 0 && errno == EINTR);
    if (waited < 0) {
      throw std::runtime_error("waitpid TID " + std::to_string(tid) + ": " +
                               std::string(std::strerror(errno)));
    }
    if (!WIFSTOPPED(status)) {
      throw std::runtime_error("tracee thread did not enter ptrace stop");
    }
    if (tid == pid_) leader_stop_signal_ = WSTOPSIG(status);
  }
  if (tids_.empty()) throw std::runtime_error("could not seize any thread");
  if (leader_stop_signal_ == 0) leader_stop_signal_ = SIGTRAP;
}

TraceSession::~TraceSession() { detach_noexcept(); }

void TraceSession::detach_noexcept() noexcept {
  if (!attached_) return;
  for (auto tid = tids_.rbegin(); tid != tids_.rend(); ++tid) {
    (void)ptrace(PTRACE_DETACH, *tid, nullptr, nullptr);
  }
  attached_ = false;
}

void TraceSession::detach() {
  if (!attached_) return;
  std::string failure;
  for (auto tid = tids_.rbegin(); tid != tids_.rend(); ++tid) {
    if (ptrace(PTRACE_DETACH, *tid, nullptr, nullptr) != 0 && errno != ESRCH &&
        failure.empty()) {
      failure = "ptrace detach TID " + std::to_string(*tid) + ": " +
                std::string(std::strerror(errno));
    }
  }
  attached_ = false;
  if (!failure.empty()) throw std::runtime_error(failure);
}

}  // namespace elfloader
