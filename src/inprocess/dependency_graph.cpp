#include "dependency_graph.hpp"

#include <cstdlib>
#include <dlfcn.h>
#include <queue>
#include <sstream>
#include <unordered_set>

namespace elfloader {
namespace {

std::vector<std::string> split_paths(std::string_view value) {
  std::vector<std::string> result;
  std::size_t start = 0;
  while (start <= value.size()) {
    const std::size_t separator = value.find(':', start);
    const std::size_t end = separator == std::string_view::npos ? value.size() : separator;
    if (end > start) result.emplace_back(value.substr(start, end - start));
    if (separator == std::string_view::npos) break;
    start = separator + 1;
  }
  return result;
}

std::string expand_origin(std::string value, const std::filesystem::path& origin) {
  constexpr std::string_view token = "$ORIGIN";
  std::size_t position = 0;
  while ((position = value.find(token, position)) != std::string::npos) {
    value.replace(position, token.size(), origin.string());
    position += origin.string().size();
  }
  return value;
}

std::string canonical_key(const std::filesystem::path& path) {
  return std::filesystem::canonical(path).string();
}

}  // namespace

DependencyGraph::DependencyGraph(std::filesystem::path root) {
  root_ = add_custom(std::filesystem::canonical(std::move(root)));
  for (const auto& node : nodes_) {
    if (node.get() == root_ || node->host_managed) continue;
    node->host_handle = dlopen(node->path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!node->host_handle) {
      throw Error("DT_NEEDED " + node->soname + ": " + dlerror());
    }
  }
}

DependencyGraph::~DependencyGraph() {
  for (auto node = nodes_.rbegin(); node != nodes_.rend(); ++node) {
    if ((*node)->host_handle) dlclose((*node)->host_handle);
  }
}

bool DependencyGraph::host_runtime(std::string_view soname) {
  return soname == "libc.so.6" || soname == "libm.so.6" ||
         soname == "libstdc++.so.6" || soname == "libgcc_s.so.1" ||
         soname == "ld-linux-x86-64.so.2" || soname == "libdl.so.2" ||
         soname == "libpthread.so.0" || soname == "librt.so.1";
}

DependencyGraph::Node* DependencyGraph::add_host(std::string_view soname) {
  const auto existing = by_soname_.find(std::string(soname));
  if (existing != by_soname_.end()) return existing->second;
  void* handle = dlopen(std::string(soname).c_str(), RTLD_NOW | RTLD_LOCAL);
  if (!handle) throw Error("DT_NEEDED " + std::string(soname) + ": " + dlerror());
  auto node = std::make_unique<Node>();
  node->soname = soname;
  node->host_managed = true;
  node->host_handle = handle;
  Node* result = node.get();
  nodes_.push_back(std::move(node));
  by_soname_.emplace(result->soname, result);
  return result;
}

DependencyGraph::Node* DependencyGraph::add_custom(const std::filesystem::path& path) {
  const std::string path_key = canonical_key(path);
  const auto by_path = by_path_.find(path_key);
  if (by_path != by_path_.end()) return by_path->second;

  auto image = std::make_shared<ElfImage>(path_key);
  std::string soname = path.filename().string();
  if (image->dynamic().soname) {
    soname = image->dynamic_string(*image->dynamic().soname);
  }
  const auto by_name = by_soname_.find(soname);
  if (by_name != by_soname_.end()) {
    by_path_.emplace(path_key, by_name->second);
    return by_name->second;
  }

  auto node = std::make_unique<Node>();
  node->path = path_key;
  node->soname = std::move(soname);
  node->image = std::move(image);
  Node* result = node.get();
  nodes_.push_back(std::move(node));
  by_path_.emplace(path_key, result);
  by_soname_.emplace(result->soname, result);

  for (const std::size_t offset : result->image->dynamic().needed) {
    result->dependencies.push_back(
        resolve_dependency(*result, result->image->dynamic_string(offset)));
  }
  return result;
}

DependencyGraph::Node* DependencyGraph::resolve_dependency(Node& parent,
                                                            std::string_view soname) {
  const auto existing = by_soname_.find(std::string(soname));
  if (existing != by_soname_.end()) return existing->second;
  if (host_runtime(soname)) return add_host(soname);
  return add_custom(find_dependency(parent, soname));
}

std::vector<std::filesystem::path> DependencyGraph::search_paths(
    const Node& parent) const {
  std::vector<std::filesystem::path> paths;
  const auto add = [&](std::string_view list) {
    for (std::string entry : split_paths(list)) {
      paths.emplace_back(expand_origin(std::move(entry), parent.path.parent_path()));
    }
  };
  if (parent.image->dynamic().runpath) {
    add(parent.image->dynamic_string(*parent.image->dynamic().runpath));
  } else if (parent.image->dynamic().rpath) {
    add(parent.image->dynamic_string(*parent.image->dynamic().rpath));
  }
  if (const char* environment = std::getenv("LD_LIBRARY_PATH")) add(environment);
  paths.push_back(parent.path.parent_path());
  paths.emplace_back("/usr/lib");
  paths.emplace_back("/usr/lib64");
  paths.emplace_back("/lib");
  paths.emplace_back("/lib64");
  return paths;
}

std::filesystem::path DependencyGraph::find_dependency(
    const Node& parent, std::string_view soname) const {
  if (soname.find('/') != std::string_view::npos) {
    const std::filesystem::path direct(soname);
    if (std::filesystem::is_regular_file(direct)) return direct;
  }
  for (const std::filesystem::path& directory : search_paths(parent)) {
    const std::filesystem::path candidate = directory / soname;
    std::error_code error;
    if (std::filesystem::is_regular_file(candidate, error)) return candidate;
  }
  throw Error("DT_NEEDED " + std::string(soname) + ": not found");
}

std::vector<const DependencyGraph::Node*> DependencyGraph::breadth_first_scope() const {
  std::vector<const Node*> result;
  std::queue<const Node*> queue;
  std::unordered_set<const Node*> visited;
  queue.push(root_);
  while (!queue.empty()) {
    const Node* node = queue.front();
    queue.pop();
    if (!visited.insert(node).second) continue;
    result.push_back(node);
    for (const Node* dependency : node->dependencies) queue.push(dependency);
  }
  return result;
}

}  // namespace elfloader
