#include "remote_modules.hpp"

#include "inprocess/elf_image.hpp"
#include "process_maps.hpp"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <elf.h>
#include <map>

namespace elfloader {
namespace {

std::size_t symbol_count(const ElfImage& image) {
  const DynamicInfo& dynamic = image.dynamic();
  if (dynamic.hash) {
    const auto offset = image.virtual_to_file(dynamic.hash, 2 * sizeof(std::uint32_t));
    std::uint32_t words[2]{};
    std::memcpy(words, image.file_range(offset, sizeof(words)).data(), sizeof(words));
    return words[1];
  }
  const auto header_offset =
      image.virtual_to_file(dynamic.gnu_hash, 4 * sizeof(std::uint32_t));
  std::uint32_t header[4]{};
  std::memcpy(header, image.file_range(header_offset, sizeof(header)).data(),
              sizeof(header));
  const std::uint32_t bucket_count = header[0];
  const std::uint32_t symbol_offset = header[1];
  const std::uint32_t bloom_size = header[2];
  const std::uint64_t buckets_address = dynamic.gnu_hash + sizeof(header) +
                                        bloom_size * sizeof(Elf64_Xword);
  const auto buckets_offset = image.virtual_to_file(
      buckets_address, bucket_count * sizeof(std::uint32_t));
  const auto buckets_bytes = image.file_range(
      buckets_offset, bucket_count * sizeof(std::uint32_t));
  std::uint32_t maximum = symbol_offset;
  for (std::uint32_t bucket = 0; bucket < bucket_count; ++bucket) {
    std::uint32_t index = 0;
    std::memcpy(&index, buckets_bytes.data() + bucket * sizeof(index), sizeof(index));
    if (index < symbol_offset) continue;
    for (;;) {
      const std::uint64_t chain_address =
          buckets_address + bucket_count * sizeof(std::uint32_t) +
          (index - symbol_offset) * sizeof(std::uint32_t);
      const auto chain_offset = image.virtual_to_file(chain_address, sizeof(std::uint32_t));
      std::uint32_t chain = 0;
      std::memcpy(&chain, image.file_range(chain_offset, sizeof(chain)).data(),
                  sizeof(chain));
      ++index;
      if (chain & 1U) break;
    }
    maximum = std::max(maximum, index);
  }
  return maximum;
}

}  // namespace

std::vector<RemoteModule> list_remote_modules(pid_t pid) {
  struct Aggregate {
    std::uintptr_t start = UINTPTR_MAX;
    std::uintptr_t end = 0;
    std::uintptr_t load_bias = UINTPTR_MAX;
  };
  std::map<std::filesystem::path, Aggregate> aggregates;
  for (const ProcessMapEntry& entry : read_process_maps(pid)) {
    if (entry.path.empty() || entry.path.string().front() == '[' ||
        entry.inode == 0) {
      continue;
    }
    Aggregate& aggregate = aggregates[entry.path];
    aggregate.start = std::min(aggregate.start, entry.start);
    aggregate.end = std::max(aggregate.end, entry.end);
    if (entry.start >= entry.offset) {
      aggregate.load_bias =
          std::min(aggregate.load_bias,
                   entry.start - static_cast<std::uintptr_t>(entry.offset));
    }
  }

  std::vector<RemoteModule> result;
  for (const auto& [path, aggregate] : aggregates) {
    if (aggregate.load_bias == UINTPTR_MAX) continue;
    try {
      const ElfImage image(path);
      result.push_back({path, aggregate.load_bias, aggregate.start, aggregate.end});
    } catch (const std::exception&) {
    }
  }
  return result;
}

std::optional<RemoteSymbol> resolve_remote_symbol(pid_t pid,
                                                  std::string_view module,
                                                  std::string_view symbol) {
  for (const RemoteModule& candidate : list_remote_modules(pid)) {
    if (candidate.path.filename() != module && candidate.path.string() != module) {
      continue;
    }
    const ElfImage image(candidate.path);
    const DynamicInfo& dynamic = image.dynamic();
    const std::size_t count = symbol_count(image);
    const auto symbols_offset = image.virtual_to_file(
        dynamic.symtab, count * sizeof(Elf64_Sym));
    const auto symbols = image.file_range(symbols_offset, count * sizeof(Elf64_Sym));
    for (std::size_t index = 0; index < count; ++index) {
      Elf64_Sym entry{};
      std::memcpy(&entry, symbols.data() + index * sizeof(entry), sizeof(entry));
      if (entry.st_name >= dynamic.strsz || entry.st_shndx == SHN_UNDEF) continue;
      if (image.dynamic_string(entry.st_name) != symbol) continue;
      const unsigned visibility = ELF64_ST_VISIBILITY(entry.st_other);
      if (visibility == STV_HIDDEN || visibility == STV_INTERNAL) continue;
      return RemoteSymbol{candidate, std::string(symbol),
                          candidate.load_bias + entry.st_value, entry.st_size};
    }
    return std::nullopt;
  }
  return std::nullopt;
}

}  // namespace elfloader
