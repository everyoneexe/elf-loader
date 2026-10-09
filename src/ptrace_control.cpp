#include "ptrace_control.hpp"
#include "process_maps.hpp"
#include "trace_session.hpp"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>
#include <sys/ptrace.h>
#include <sys/uio.h>

namespace elfloader {

const char* memory_backend_name(MemoryBackend backend) noexcept {
  return backend == MemoryBackend::ProcessVm ? "process_vm" : "ptrace";
}

PtraceAttachResult attach_and_detach(pid_t pid) {
  TraceSession tracee(pid);
  const int stop_signal = tracee.leader_stop_signal();
  tracee.detach();
  return PtraceAttachResult{pid, stop_signal};
}

RemoteWriteResult write_remote_memory(pid_t pid, std::uintptr_t address,
                                      std::span<const std::byte> bytes) {
  validate_process_range(pid, address, bytes.size(), true, true);
  TraceSession tracee(pid);
  const int stop_signal = tracee.leader_stop_signal();
  const pid_t memory_tid = tracee.memory_tid();
  iovec local{const_cast<std::byte*>(bytes.data()), bytes.size()};
  iovec remote{reinterpret_cast<void*>(address), bytes.size()};
  const ssize_t transferred = process_vm_writev(pid, &local, 1, &remote, 1, 0);
  if (transferred == static_cast<ssize_t>(bytes.size())) {
    tracee.detach();
    return RemoteWriteResult{pid, stop_signal, bytes.size(),
                             MemoryBackend::ProcessVm};
  }
  if (transferred > 0) {
    throw std::runtime_error("process_vm_writev performed a partial write");
  }
  struct WordPatch {
    std::uintptr_t address;
    long original;
    long replacement;
  };
  std::vector<WordPatch> patches;
  const std::uintptr_t word_mask = sizeof(long) - 1;
  const std::uintptr_t first_word = address & ~word_mask;
  const std::uintptr_t end = address + bytes.size();
  for (std::uintptr_t word_address = first_word; word_address < end;
       word_address += sizeof(long)) {
    errno = 0;
    const long original = ptrace(PTRACE_PEEKDATA, memory_tid,
                                 reinterpret_cast<void*>(word_address), nullptr);
    if (original == -1 && errno != 0) {
      throw std::runtime_error("ptrace read at remote address " +
                               std::to_string(word_address) + ": " +
                               std::string(std::strerror(errno)));
    }
    long replacement = original;
    const std::uintptr_t copy_begin = std::max(address, word_address);
    const std::uintptr_t copy_end =
        std::min(end, word_address + sizeof(long));
    std::memcpy(reinterpret_cast<std::byte*>(&replacement) +
                    (copy_begin - word_address),
                bytes.data() + (copy_begin - address), copy_end - copy_begin);
    patches.push_back({word_address, original, replacement});
  }

  std::size_t applied = 0;
  for (; applied < patches.size(); ++applied) {
    const WordPatch& patch = patches[applied];
    if (ptrace(PTRACE_POKEDATA, memory_tid,
               reinterpret_cast<void*>(patch.address), patch.replacement) == 0) {
      continue;
    }
    const int write_error = errno;
    while (applied > 0) {
      --applied;
      const WordPatch& rollback = patches[applied];
      (void)ptrace(PTRACE_POKEDATA, memory_tid,
                   reinterpret_cast<void*>(rollback.address), rollback.original);
    }
    throw std::runtime_error("ptrace write at remote address " +
                             std::to_string(patch.address) + ": " +
                             std::string(std::strerror(write_error)));
  }
  tracee.detach();
  return RemoteWriteResult{pid, stop_signal, bytes.size(), MemoryBackend::Ptrace};
}

RemoteReadResult read_remote_memory(pid_t pid, std::uintptr_t address,
                                    std::size_t size) {
  validate_process_range(pid, address, size, true, false);
  TraceSession tracee(pid);
  const int stop_signal = tracee.leader_stop_signal();
  const pid_t memory_tid = tracee.memory_tid();
  std::vector<std::byte> bytes(size);
  iovec local{bytes.data(), bytes.size()};
  iovec remote{reinterpret_cast<void*>(address), bytes.size()};
  const ssize_t transferred = process_vm_readv(pid, &local, 1, &remote, 1, 0);
  if (transferred == static_cast<ssize_t>(bytes.size())) {
    tracee.detach();
    return RemoteReadResult{pid, stop_signal, std::move(bytes),
                            MemoryBackend::ProcessVm};
  }
  if (transferred > 0) {
    throw std::runtime_error("process_vm_readv performed a partial read");
  }
  const std::uintptr_t word_mask = sizeof(long) - 1;
  const std::uintptr_t first_word = address & ~word_mask;
  const std::uintptr_t end = address + size;
  for (std::uintptr_t word_address = first_word; word_address < end;
       word_address += sizeof(long)) {
    errno = 0;
    const long word = ptrace(PTRACE_PEEKDATA, memory_tid,
                             reinterpret_cast<void*>(word_address), nullptr);
    if (word == -1 && errno != 0) {
      throw std::runtime_error("ptrace read at remote address " +
                               std::to_string(word_address) + ": " +
                               std::string(std::strerror(errno)));
    }
    const std::uintptr_t copy_begin = std::max(address, word_address);
    const std::uintptr_t copy_end =
        std::min(end, word_address + sizeof(long));
    std::memcpy(bytes.data() + (copy_begin - address),
                reinterpret_cast<const std::byte*>(&word) +
                    (copy_begin - word_address),
                copy_end - copy_begin);
  }
  tracee.detach();
  return RemoteReadResult{pid, stop_signal, std::move(bytes),
                          MemoryBackend::Ptrace};
}

}  // namespace elfloader
