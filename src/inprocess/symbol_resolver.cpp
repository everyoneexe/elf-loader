#include "symbol_resolver.hpp"

#include <cstring>
#include <dlfcn.h>
#include <vector>

namespace elfloader {
namespace {

const Elf64_Sym* symbol_table(const ElfImage& image) {
  const DynamicInfo& dynamic = image.dynamic();
  const std::uint64_t offset = image.virtual_to_file(dynamic.symtab, sizeof(Elf64_Sym));
  return reinterpret_cast<const Elf64_Sym*>(image.file_range(offset, sizeof(Elf64_Sym)).data());
}

const char* string_table(const ElfImage& image) {
  const DynamicInfo& dynamic = image.dynamic();
  const std::uint64_t offset = image.virtual_to_file(dynamic.strtab, dynamic.strsz);
  return reinterpret_cast<const char*>(image.file_range(offset, dynamic.strsz).data());
}

const void* virtual_pointer(const ElfImage& image, std::uint64_t address,
                            std::uint64_t size) {
  const std::uint64_t offset = image.virtual_to_file(address, size);
  return image.file_range(offset, size).data();
}

std::size_t symbol_count(const ElfImage& image) {
  const DynamicInfo& dynamic = image.dynamic();
  if (dynamic.hash) {
    const auto* hash = static_cast<const std::uint32_t*>(
        virtual_pointer(image, dynamic.hash, 2 * sizeof(std::uint32_t)));
    return hash[1];
  }
  const auto* header = static_cast<const std::uint32_t*>(
      virtual_pointer(image, dynamic.gnu_hash, 4 * sizeof(std::uint32_t)));
  const std::uint32_t bucket_count = header[0];
  const std::uint32_t symbol_offset = header[1];
  const std::uint32_t bloom_size = header[2];
  const auto* buckets = reinterpret_cast<const std::uint32_t*>(
      reinterpret_cast<const Elf64_Xword*>(header + 4) + bloom_size);
  const auto* chains = buckets + bucket_count;
  std::uint32_t maximum = symbol_offset;
  for (std::uint32_t bucket = 0; bucket < bucket_count; ++bucket) {
    std::uint32_t index = buckets[bucket];
    if (index < symbol_offset) continue;
    while ((chains[index - symbol_offset] & 1U) == 0) ++index;
    maximum = std::max(maximum, index + 1);
  }
  return maximum;
}

}  // namespace

std::uint32_t SymbolResolver::sysv_hash(std::string_view name) {
  std::uint32_t hash = 0;
  for (const unsigned char character : name) {
    hash = (hash << 4) + character;
    const std::uint32_t high = hash & 0xf0000000U;
    if (high) hash ^= high >> 24;
    hash &= ~high;
  }
  return hash;
}

std::uint32_t SymbolResolver::gnu_hash(std::string_view name) {
  std::uint32_t hash = 5381;
  for (const unsigned char character : name) hash = hash * 33 + character;
  return hash;
}

std::optional<std::string> SymbolResolver::defined_version(
    const ElfImage& image, std::size_t symbol_index) {
  const DynamicInfo& dynamic = image.dynamic();
  if (!dynamic.versym || !dynamic.verdef) return std::nullopt;
  const auto* versions = static_cast<const Elf64_Half*>(
      virtual_pointer(image, dynamic.versym,
                      (symbol_index + 1) * sizeof(Elf64_Half)));
  const Elf64_Half wanted = versions[symbol_index] & 0x7fffU;
  if (wanted <= 1) return std::nullopt;

  auto* definition = static_cast<const Elf64_Verdef*>(
      virtual_pointer(image, dynamic.verdef, sizeof(Elf64_Verdef)));
  for (std::size_t index = 0; index < dynamic.verdef_count; ++index) {
    if ((definition->vd_ndx & 0x7fffU) == wanted) {
      const auto* auxiliary = reinterpret_cast<const Elf64_Verdaux*>(
          reinterpret_cast<const std::byte*>(definition) + definition->vd_aux);
      return std::string(image.dynamic_string(auxiliary->vda_name));
    }
    if (definition->vd_next == 0) break;
    definition = reinterpret_cast<const Elf64_Verdef*>(
        reinterpret_cast<const std::byte*>(definition) + definition->vd_next);
  }
  return std::nullopt;
}

std::optional<SymbolMatch> SymbolResolver::lookup_node(
    const DependencyGraph::Node& node, std::string_view name,
    std::optional<std::string_view> version) const {
  if (node.host_managed) {
    void* address = version ? dlvsym(node.host_handle, std::string(name).c_str(),
                                    std::string(*version).c_str())
                            : dlsym(node.host_handle, std::string(name).c_str());
    if (!address) return std::nullopt;
    return SymbolMatch{&node, nullptr, 0, address};
  }

  const ElfImage& image = *node.image;
  const DynamicInfo& dynamic = image.dynamic();
  const Elf64_Sym* symbols = symbol_table(image);
  const char* strings = string_table(image);
  const std::size_t count = symbol_count(image);
  std::vector<std::size_t> candidates;

  if (dynamic.gnu_hash) {
    const auto* header = static_cast<const std::uint32_t*>(
        virtual_pointer(image, dynamic.gnu_hash, 4 * sizeof(std::uint32_t)));
    const std::uint32_t bucket_count = header[0];
    const std::uint32_t symbol_offset = header[1];
    const std::uint32_t bloom_size = header[2];
    const std::uint32_t bloom_shift = header[3];
    const auto* bloom = reinterpret_cast<const Elf64_Xword*>(header + 4);
    const auto* buckets = reinterpret_cast<const std::uint32_t*>(bloom + bloom_size);
    const auto* chains = buckets + bucket_count;
    const std::uint32_t hash = gnu_hash(name);
    const Elf64_Xword word = bloom[(hash / 64U) % bloom_size];
    const Elf64_Xword mask = (Elf64_Xword{1} << (hash % 64U)) |
                             (Elf64_Xword{1} << ((hash >> bloom_shift) % 64U));
    if ((word & mask) == mask) {
      std::uint32_t index = buckets[hash % bucket_count];
      if (index >= symbol_offset) {
        for (;;) {
          const std::uint32_t chain = chains[index - symbol_offset];
          if ((chain | 1U) == (hash | 1U)) candidates.push_back(index);
          if (chain & 1U) break;
          ++index;
        }
      }
    }
  } else {
    const auto* hash = static_cast<const std::uint32_t*>(
        virtual_pointer(image, dynamic.hash, 2 * sizeof(std::uint32_t)));
    const std::uint32_t bucket_count = hash[0];
    const auto* buckets = hash + 2;
    const auto* chains = buckets + bucket_count;
    for (std::uint32_t index = buckets[sysv_hash(name) % bucket_count];
         index != STN_UNDEF; index = chains[index]) {
      candidates.push_back(index);
    }
  }

  for (const std::size_t index : candidates) {
    if (index >= count) throw Error("dynamic hash references symbol outside table");
    const Elf64_Sym& symbol = symbols[index];
    if (symbol.st_name >= dynamic.strsz || symbol.st_shndx == SHN_UNDEF ||
        std::string_view(strings + symbol.st_name) != name) {
      continue;
    }
    const unsigned binding = ELF64_ST_BIND(symbol.st_info);
    const unsigned visibility = ELF64_ST_VISIBILITY(symbol.st_other);
    if ((binding != STB_GLOBAL && binding != STB_WEAK && binding != STB_GNU_UNIQUE) ||
        visibility == STV_HIDDEN || visibility == STV_INTERNAL) {
      continue;
    }
    const auto definition_version = defined_version(image, index);
    if (version && (!definition_version || *definition_version != *version)) continue;
    void* address = nullptr;
    if (node.host_handle) {
      address = version ? dlvsym(node.host_handle, std::string(name).c_str(),
                                 std::string(*version).c_str())
                        : dlsym(node.host_handle, std::string(name).c_str());
    }
    return SymbolMatch{&node, &symbol, index, address};
  }
  return std::nullopt;
}

std::optional<SymbolMatch> SymbolResolver::lookup(
    std::string_view name, std::optional<std::string_view> version) const {
  std::optional<SymbolMatch> weak;
  for (const DependencyGraph::Node* node : graph_.breadth_first_scope()) {
    auto result = lookup_node(*node, name, version);
    if (!result) continue;
    if (!result->symbol || ELF64_ST_BIND(result->symbol->st_info) != STB_WEAK) {
      return result;
    }
    if (!weak) weak = result;
  }
  return weak;
}

}  // namespace elfloader
