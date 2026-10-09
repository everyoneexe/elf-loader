#pragma once

#include "elf_image.hpp"

#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace elfloader {

class DependencyGraph {
 public:
  struct Node {
    std::filesystem::path path;
    std::string soname;
    std::shared_ptr<ElfImage> image;
    std::vector<Node*> dependencies;
    bool host_managed = false;
    void* host_handle = nullptr;
  };

  explicit DependencyGraph(std::filesystem::path root);
  DependencyGraph(const DependencyGraph&) = delete;
  DependencyGraph& operator=(const DependencyGraph&) = delete;
  ~DependencyGraph();

  const Node& root() const noexcept { return *root_; }
  std::vector<const Node*> breadth_first_scope() const;
  const std::vector<std::unique_ptr<Node>>& nodes() const noexcept { return nodes_; }

 private:
  Node* add_custom(const std::filesystem::path& path);
  Node* add_host(std::string_view soname);
  Node* resolve_dependency(Node& parent, std::string_view soname);
  std::filesystem::path find_dependency(const Node& parent,
                                        std::string_view soname) const;
  std::vector<std::filesystem::path> search_paths(const Node& parent) const;
  static bool host_runtime(std::string_view soname);

  Node* root_ = nullptr;
  std::vector<std::unique_ptr<Node>> nodes_;
  std::unordered_map<std::string, Node*> by_soname_;
  std::unordered_map<std::string, Node*> by_path_;
};

}  // namespace elfloader
