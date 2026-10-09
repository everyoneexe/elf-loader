#pragma once

#include "dependency_graph.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace elfloader {

struct SymbolMatch {
  const DependencyGraph::Node* owner = nullptr;
  const Elf64_Sym* symbol = nullptr;
  std::size_t index = 0;
  void* address = nullptr;
};

class SymbolResolver {
 public:
  explicit SymbolResolver(const DependencyGraph& graph) : graph_(graph) {}

  std::optional<SymbolMatch> lookup(std::string_view name,
                                    std::optional<std::string_view> version =
                                        std::nullopt) const;

 private:
  std::optional<SymbolMatch> lookup_node(const DependencyGraph::Node& node,
                                         std::string_view name,
                                         std::optional<std::string_view> version) const;
  static std::uint32_t sysv_hash(std::string_view name);
  static std::uint32_t gnu_hash(std::string_view name);
  static std::optional<std::string> defined_version(const ElfImage& image,
                                                    std::size_t symbol_index);

  const DependencyGraph& graph_;
};

}  // namespace elfloader
