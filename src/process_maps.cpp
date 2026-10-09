#include "process_maps.hpp"

#include <charconv>
#include <fstream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string_view>

namespace elfloader {
namespace {

std::uint64_t parse_integer(std::string_view value, int base,
                            std::string_view field) {
  std::uint64_t result = 0;
  const auto [end, error] = std::from_chars(
      value.data(), value.data() + value.size(), result, base);
  if (error != std::errc{} || end != value.data() + value.size()) {
    throw std::runtime_error("invalid " + std::string(field) +
                             " in process maps");
  }
  return result;
}

ProcessMapEntry parse_line(const std::string& line) {
  std::istringstream fields(line);
  std::string range;
  std::string permissions;
  std::string offset;
  std::string device;
  std::string inode;
  if (!(fields >> range >> permissions >> offset >> device >> inode)) {
    throw std::runtime_error("malformed process maps entry");
  }
  const std::size_t separator = range.find('-');
  if (separator == std::string::npos || permissions.size() != 4) {
    throw std::runtime_error("malformed process maps range or permissions");
  }

  ProcessMapEntry entry;
  entry.start = static_cast<std::uintptr_t>(
      parse_integer(std::string_view(range).substr(0, separator), 16, "start"));
  entry.end = static_cast<std::uintptr_t>(
      parse_integer(std::string_view(range).substr(separator + 1), 16, "end"));
  if (entry.start >= entry.end) {
    throw std::runtime_error("invalid process maps address range");
  }
  entry.offset = parse_integer(offset, 16, "offset");
  entry.inode = parse_integer(inode, 10, "inode");
  entry.readable = permissions[0] == 'r';
  entry.writable = permissions[1] == 'w';
  entry.executable = permissions[2] == 'x';
  entry.private_mapping = permissions[3] == 'p';
  entry.device = std::move(device);

  std::string path;
  std::getline(fields, path);
  const std::size_t first = path.find_first_not_of(' ');
  if (first != std::string::npos) entry.path = path.substr(first);
  return entry;
}

}  // namespace

std::vector<ProcessMapEntry> read_process_maps(pid_t pid) {
  if (pid <= 0) throw std::runtime_error("PID must be a positive integer");
  const std::filesystem::path path =
      std::filesystem::path("/proc") / std::to_string(pid) / "maps";
  std::ifstream input(path);
  if (!input) throw std::runtime_error("cannot read " + path.string());

  std::vector<ProcessMapEntry> result;
  std::string line;
  while (std::getline(input, line)) result.push_back(parse_line(line));
  if (result.empty()) throw std::runtime_error("process maps is empty");
  return result;
}

void validate_process_range(pid_t pid, std::uintptr_t address, std::size_t size,
                            bool require_read, bool require_write) {
  if (address == 0) throw std::runtime_error("remote address must be nonzero");
  if (size == 0) throw std::runtime_error("remote range must be nonempty");
  if (address > std::numeric_limits<std::uintptr_t>::max() - size) {
    throw std::runtime_error("remote address range overflows");
  }

  const std::uintptr_t end = address + size;
  std::uintptr_t cursor = address;
  for (const ProcessMapEntry& entry : read_process_maps(pid)) {
    if (entry.end <= cursor) continue;
    if (entry.start > cursor) break;
    if ((require_read && !entry.readable) ||
        (require_write && !entry.writable)) {
      throw std::runtime_error("remote range lacks required map permissions");
    }
    cursor = std::min(end, entry.end);
    if (cursor == end) return;
  }
  throw std::runtime_error("remote range is not fully mapped");
}

}  // namespace elfloader
