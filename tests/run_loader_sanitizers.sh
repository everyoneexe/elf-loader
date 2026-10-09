#!/bin/bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build/fixtures"
SAN="$ROOT/build/sanitizers"
CXX="${CXX:-g++}"
COMMON=(
  -std=c++20 -O1 -g -Wall -Wextra -Wpedantic -Werror
  -fsanitize=address,undefined -fno-omit-frame-pointer
  -I"$ROOT/src" -I"$ROOT/src/inprocess"
)

mkdir -p "$SAN"

"$CXX" "${COMMON[@]}" -o "$SAN/parser" \
  "$ROOT/tests/loader_parser_test.cpp" \
  "$ROOT/src/inprocess/elf_image.cpp"
"$CXX" "${COMMON[@]}" -o "$SAN/mapping" \
  "$ROOT/tests/loader_mapping_test.cpp" \
  "$ROOT/src/inprocess/elf_image.cpp" \
  "$ROOT/src/inprocess/mapped_image.cpp"
"$CXX" "${COMMON[@]}" -o "$SAN/graph" \
  "$ROOT/tests/loader_graph_test.cpp" \
  "$ROOT/src/inprocess/elf_image.cpp" \
  "$ROOT/src/inprocess/dependency_graph.cpp" \
  "$ROOT/src/inprocess/symbol_resolver.cpp" -ldl
"$CXX" "${COMMON[@]}" -o "$SAN/process-control" \
  "$ROOT/tests/process_control_test.cpp" \
  "$ROOT/src/process_control.cpp"
"$CXX" "${COMMON[@]}" -o "$SAN/process-maps" \
  "$ROOT/tests/process_maps_test.cpp" \
  "$ROOT/src/process_maps.cpp"
"$CXX" "${COMMON[@]}" -pthread -o "$SAN/trace-session" \
  "$ROOT/tests/trace_session_test.cpp" \
  "$ROOT/src/trace_session.cpp"
"$CXX" "${COMMON[@]}" -o "$SAN/ptrace-control" \
  "$ROOT/tests/ptrace_control_test.cpp" \
  "$ROOT/src/ptrace_control.cpp" "$ROOT/src/process_maps.cpp" \
  "$ROOT/src/trace_session.cpp"
"$CXX" "${COMMON[@]}" -o "$SAN/remote-memory" \
  "$ROOT/tests/remote_memory_test.cpp" \
  "$ROOT/src/ptrace_control.cpp" "$ROOT/src/process_maps.cpp" \
  "$ROOT/src/trace_session.cpp"
"$CXX" "${COMMON[@]}" -rdynamic -o "$SAN/remote-modules" \
  "$ROOT/tests/remote_modules_test.cpp" \
  "$ROOT/src/remote_modules.cpp" "$ROOT/src/process_maps.cpp" \
  "$ROOT/src/inprocess/elf_image.cpp"

export ASAN_OPTIONS="detect_leaks=1:halt_on_error=1"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"
export LD_LIBRARY_PATH="$BUILD${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

"$SAN/parser" "$BUILD/libtarget.so"
"$SAN/mapping" "$BUILD/libtarget.so"
"$SAN/graph" "$BUILD/libtarget.so" "$BUILD/libdiamond_root.so"
"$SAN/process-control"
"$SAN/process-maps"
"$SAN/trace-session"
"$SAN/ptrace-control" "$ROOT/build/elf-loader"
"$SAN/remote-memory" "$ROOT/build/elf-loader"
"$SAN/remote-modules" "$ROOT/build/elf-loader"

echo "sanitizers=0"
