#pragma once

#include <sys/types.h>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace elfloader {
enum class MemoryBackend { ProcessVm, Ptrace };

const char* memory_backend_name(MemoryBackend backend) noexcept;


struct PtraceAttachResult {
  pid_t pid = 0;
  int stop_signal = 0;
};

struct RemoteWriteResult {
  pid_t pid = 0;
  int stop_signal = 0;
  std::size_t bytes_written = 0;
  MemoryBackend backend = MemoryBackend::Ptrace;
};

struct RemoteReadResult {
  pid_t pid = 0;
  int stop_signal = 0;
  std::vector<std::byte> bytes;
  MemoryBackend backend = MemoryBackend::Ptrace;
};

PtraceAttachResult attach_and_detach(pid_t pid);
RemoteWriteResult write_remote_memory(pid_t pid, std::uintptr_t address,
                                      std::span<const std::byte> bytes);
RemoteReadResult read_remote_memory(pid_t pid, std::uintptr_t address,
                                    std::size_t size);

}  // namespace elfloader
