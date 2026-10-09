#!/bin/bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build/fixtures"
TOOLS="$ROOT/build"
LOADER="$TOOLS/elf-loader"
FIXTURE="$BUILD/libtarget.so"
DIAMOND="$BUILD/libdiamond_root.so"
ITERATIONS="${LOADER_STRESS_ITERATIONS:-100}"

export LD_LIBRARY_PATH="$BUILD${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

"$TOOLS/parser-test" "$FIXTURE"
"$TOOLS/mapping-test" "$FIXTURE"
"$TOOLS/graph-test" "$FIXTURE" "$DIAMOND"
"$TOOLS/process-control-test"
"$TOOLS/process-maps-test"
"$TOOLS/trace-session-test"
"$TOOLS/ptrace-control-test" "$LOADER"
"$TOOLS/remote-memory-test" "$LOADER"
"$TOOLS/remote-modules-test" "$LOADER"
"$TOOLS/owned-process-test" "$LOADER" "$FIXTURE"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
printf 'bad' > "$TMP_DIR/bad.so"
if "$LOADER" "$TMP_DIR/bad.so" >"$TMP_DIR/bad.out" 2>"$TMP_DIR/bad.err"; then
  echo "malformed ELF unexpectedly succeeded" >&2
  exit 1
fi
grep -F 'truncated ELF header' "$TMP_DIR/bad.err" >/dev/null

cp "$FIXTURE" "$TMP_DIR/libtarget.so"
if LD_LIBRARY_PATH="$TMP_DIR" "$LOADER" "$TMP_DIR/libtarget.so" \
    >"$TMP_DIR/missing.out" 2>"$TMP_DIR/missing.err"; then
  echo "missing dependency unexpectedly succeeded" >&2
  exit 1
fi
grep -F 'DT_NEEDED libfixturedep.so: not found' "$TMP_DIR/missing.err" >/dev/null

declare -r EXPECTED=$'fixture_probe=0\nfixture_lifecycle=0'
for ((iteration = 1; iteration <= ITERATIONS; ++iteration)); do
  output="$($LOADER "$FIXTURE")"
  if [[ "$output" != "$EXPECTED" ]]; then
    printf 'stress iteration %d failed:\n%s\n' "$iteration" "$output" >&2
    exit 1
  fi
done

printf 'negative_scenarios=0\nstress_iterations=%d\nstress_failures=0\nrelease_suite=0\n' \
  "$ITERATIONS"
