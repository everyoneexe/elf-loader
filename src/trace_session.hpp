#pragma once

#include <sys/types.h>
#include <vector>

namespace elfloader {

std::vector<pid_t> list_process_threads(pid_t pid);

class TraceSession {
 public:
  explicit TraceSession(pid_t pid);
  TraceSession(const TraceSession&) = delete;
  TraceSession& operator=(const TraceSession&) = delete;
  TraceSession(TraceSession&&) = delete;
  TraceSession& operator=(TraceSession&&) = delete;
  ~TraceSession();

  pid_t memory_tid() const noexcept { return tids_.front(); }
  int leader_stop_signal() const noexcept { return leader_stop_signal_; }
  const std::vector<pid_t>& tids() const noexcept { return tids_; }
  void detach();

 private:
  void seize_new_threads();
  void detach_noexcept() noexcept;

  pid_t pid_;
  std::vector<pid_t> tids_;
  int leader_stop_signal_ = 0;
  bool attached_ = true;
};

}  // namespace elfloader
