#include "dependency_graph.hpp"
#include "symbol_resolver.hpp"

#include <filesystem>
#include <iostream>
#include <set>
#include <string>

extern "C" int optional_fixture_symbol() __attribute__((weak));

int main(int argc, char** argv) {
  if (argc != 3) return 2;
  try {
    const elfloader::DependencyGraph graph(std::filesystem::canonical(argv[1]));
    const elfloader::SymbolResolver resolver(graph);
    const auto scope = graph.breadth_first_scope();

    std::set<std::string> sonames;
    for (const auto* node : scope) sonames.insert(node->soname);
    if (!sonames.contains("libtarget.so") ||
        !sonames.contains("libfixturedep.so") ||
        sonames.size() != scope.size()) {
      std::cerr << "graph deduplication failed\n";
      return 1;
    }

    const auto old_version = resolver.lookup("versioned_value", "FIXTURE_1.0");
    const auto new_version = resolver.lookup("versioned_value", "FIXTURE_2.0");
    const auto missing = resolver.lookup("fixture_symbol_that_does_not_exist");
    const auto weak_missing = resolver.lookup("optional_fixture_symbol");
    const auto host = resolver.lookup("__cxa_throw", "CXXABI_1.3");
    if (!old_version || !new_version || missing || weak_missing || !host ||
        optional_fixture_symbol != nullptr || !old_version->symbol ||
        !new_version->symbol || old_version->index == new_version->index ||
        !old_version->address || !new_version->address) {
      std::cerr << "graph symbol resolution failed\n";
      return 1;
    }

    const elfloader::DependencyGraph diamond(
        std::filesystem::canonical(argv[2]));
    const auto diamond_scope = diamond.breadth_first_scope();
    std::size_t leaf_count = 0;
    for (const auto* node : diamond_scope) {
      if (node->soname == "libdiamond_leaf.so") ++leaf_count;
    }
    if (leaf_count != 1) {
      std::cerr << "diamond SONAME deduplication failed\n";
      return 1;
    }

    std::cout << "graph_nodes=" << scope.size() << '\n'
              << "graph_resolution=0\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "graph-test: " << error.what() << '\n';
    return 1;
  }
}
