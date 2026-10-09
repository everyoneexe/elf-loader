#include "ptrace_control.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

struct SharedFixture {
  std::array<std::byte, 16> bytes;
};

struct ChildFixture {
  pid_t pid;
  std::uintptr_t address;
  int release_fd;
};

struct Command {
  pid_t pid;
  std::uintptr_t address;
};

void write_exact(int fd, const void* data, std::size_t size) {
  const auto* cursor = static_cast<const std::byte*>(data);
  while (size > 0) {
    const ssize_t count = write(fd, cursor, size);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) throw std::runtime_error("pipe write failed");
    cursor += count;
    size -= static_cast<std::size_t>(count);
  }
}

void read_exact(int fd, void* data, std::size_t size) {
  auto* cursor = static_cast<std::byte*>(data);
  while (size > 0) {
    const ssize_t count = read(fd, cursor, size);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) throw std::runtime_error("pipe read failed");
    cursor += count;
    size -= static_cast<std::size_t>(count);
  }
}

ChildFixture spawn_fixture(pid_t allowed_tracer) {
  int address_pipe[2]{};
  int release_pipe[2]{};
  if (pipe(address_pipe) != 0 || pipe(release_pipe) != 0) {
    throw std::runtime_error("pipe: " + std::string(std::strerror(errno)));
  }
  const pid_t child = fork();
  if (child < 0) {
    throw std::runtime_error("fork: " + std::string(std::strerror(errno)));
  }
  if (child == 0) {
    close(address_pipe[0]);
    close(release_pipe[1]);
    SharedFixture fixture{};
    for (std::size_t index = 0; index < fixture.bytes.size(); ++index) {
      fixture.bytes[index] = static_cast<std::byte>(index);
    }
    if (allowed_tracer > 0 &&
        prctl(PR_SET_PTRACER, allowed_tracer, 0, 0, 0) != 0) {
      _exit(2);
    }
    const std::uintptr_t address =
        reinterpret_cast<std::uintptr_t>(fixture.bytes.data());
    write_exact(address_pipe[1], &address, sizeof(address));
    char release = 0;
    read_exact(release_pipe[0], &release, sizeof(release));
    const std::array<std::byte, 5> expected{
        std::byte{0xa1}, std::byte{0xb2}, std::byte{0xc3}, std::byte{0xd4},
        std::byte{0xe5}};
    const bool prefix_ok = fixture.bytes[2] == std::byte{2};
    const bool data_ok = std::equal(expected.begin(), expected.end(),
                                    fixture.bytes.begin() + 3);
    const bool suffix_ok = fixture.bytes[8] == std::byte{8};
    _exit(prefix_ok && data_ok && suffix_ok ? 0 : 3);
  }
  close(address_pipe[1]);
  close(release_pipe[0]);
  std::uintptr_t address = 0;
  read_exact(address_pipe[0], &address, sizeof(address));
  close(address_pipe[0]);
  return {child, address, release_pipe[1]};
}

void release_and_verify(ChildFixture fixture) {
  const char release = '1';
  write_exact(fixture.release_fd, &release, sizeof(release));
  close(fixture.release_fd);
  int status = 0;
  while (waitpid(fixture.pid, &status, 0) < 0 && errno == EINTR) {
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    throw std::runtime_error("remote memory fixture mismatch");
  }
}

void test_library_read() {
  ChildFixture fixture = spawn_fixture(0);
  const elfloader::RemoteReadResult result = elfloader::read_remote_memory(
      fixture.pid, fixture.address + 3, 5);
  const std::array<std::byte, 5> expected{
      std::byte{3}, std::byte{4}, std::byte{5}, std::byte{6}, std::byte{7}};
  if (result.pid != fixture.pid || result.stop_signal != SIGTRAP ||
      result.backend != elfloader::MemoryBackend::ProcessVm ||
      !std::equal(expected.begin(), expected.end(), result.bytes.begin())) {
    throw std::runtime_error("remote read result mismatch");
  }
  const char release = '1';
  write_exact(fixture.release_fd, &release, sizeof(release));
  close(fixture.release_fd);
  int status = 0;
  while (waitpid(fixture.pid, &status, 0) < 0 && errno == EINTR) {
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 3) {
    throw std::runtime_error("read fixture unexpectedly changed");
  }
}

void test_library_write() {
  ChildFixture fixture = spawn_fixture(0);
  const std::array<std::byte, 5> replacement{
      std::byte{0xa1}, std::byte{0xb2}, std::byte{0xc3}, std::byte{0xd4},
      std::byte{0xe5}};
  const elfloader::RemoteWriteResult result = elfloader::write_remote_memory(
      fixture.pid, fixture.address + 3, replacement);
  if (result.pid != fixture.pid || result.stop_signal != SIGTRAP ||
      result.backend != elfloader::MemoryBackend::ProcessVm ||
      result.bytes_written != replacement.size()) {
    throw std::runtime_error("remote write result mismatch");
  }
  release_and_verify(fixture);
}

void test_cli_read(const char* loader) {
  int start_pipe[2]{};
  if (pipe(start_pipe) != 0) {
    throw std::runtime_error("pipe: " + std::string(std::strerror(errno)));
  }
  const pid_t tracer = fork();
  if (tracer < 0) throw std::runtime_error("fork tracer failed");
  if (tracer == 0) {
    close(start_pipe[1]);
    Command command{};
    read_exact(start_pipe[0], &command, sizeof(command));
    const std::string pid = std::to_string(command.pid);
    std::ostringstream address;
    address << "0x" << std::hex << command.address;
    execl(loader, loader, "--remote-read", pid.c_str(),
          address.str().c_str(), "5", nullptr);
    _exit(4);
  }
  close(start_pipe[0]);
  ChildFixture fixture = spawn_fixture(tracer);
  const Command command{fixture.pid, fixture.address + 3};
  write_exact(start_pipe[1], &command, sizeof(command));
  close(start_pipe[1]);
  int tracer_status = 0;
  while (waitpid(tracer, &tracer_status, 0) < 0 && errno == EINTR) {
  }
  if (!WIFEXITED(tracer_status) || WEXITSTATUS(tracer_status) != 0) {
    (void)kill(fixture.pid, SIGKILL);
    while (waitpid(fixture.pid, nullptr, 0) < 0 && errno == EINTR) {
    }
    close(fixture.release_fd);
    throw std::runtime_error("remote read CLI failed");
  }
  const char release = '1';
  write_exact(fixture.release_fd, &release, sizeof(release));
  close(fixture.release_fd);
  int status = 0;
  while (waitpid(fixture.pid, &status, 0) < 0 && errno == EINTR) {
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 3) {
    throw std::runtime_error("remote read CLI changed target memory");
  }
}

void test_cli_write(const char* loader) {
  int start_pipe[2]{};
  if (pipe(start_pipe) != 0) {
    throw std::runtime_error("pipe: " + std::string(std::strerror(errno)));
  }
  const pid_t tracer = fork();
  if (tracer < 0) throw std::runtime_error("fork tracer failed");
  if (tracer == 0) {
    close(start_pipe[1]);
    Command command{};
    read_exact(start_pipe[0], &command, sizeof(command));
    const std::string pid = std::to_string(command.pid);
    std::ostringstream address;
    address << "0x" << std::hex << command.address;
    execl(loader, loader, "--remote-write", pid.c_str(),
          address.str().c_str(), "a1b2c3d4e5", nullptr);
    _exit(4);
  }
  close(start_pipe[0]);
  ChildFixture fixture = spawn_fixture(tracer);
  const Command command{fixture.pid, fixture.address + 3};
  write_exact(start_pipe[1], &command, sizeof(command));
  close(start_pipe[1]);
  int tracer_status = 0;
  while (waitpid(tracer, &tracer_status, 0) < 0 && errno == EINTR) {
  }
  if (!WIFEXITED(tracer_status) || WEXITSTATUS(tracer_status) != 0) {
    (void)kill(fixture.pid, SIGKILL);
    while (waitpid(fixture.pid, nullptr, 0) < 0 && errno == EINTR) {
    }
    close(fixture.release_fd);
    throw std::runtime_error("remote write CLI failed");
  }
  release_and_verify(fixture);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) return 2;
  try {
    test_library_read();
    test_library_write();
    test_cli_read(argv[1]);
    test_cli_write(argv[1]);
    std::cout << "remote_memory=0\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "remote-memory-test: " << error.what() << '\n';
    return 1;
  }
}
