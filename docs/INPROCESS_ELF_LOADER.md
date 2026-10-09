# In-process user-space ELF loader

## Architecture milestone: validated image and page plan

The first full-loader milestone is complete:

- `src/inprocess/elf_image.{hpp,cpp}` owns file bytes and exposes only
  validated ELF/program-header/dynamic-table views. It rejects arithmetic
  overflow, invalid alignment, incongruent segment offsets, RWX segments,
  `DT_TEXTREL`, unterminated dynamic tables and strings, and dynamic ranges
  without file backing before mapping occurs.
- `src/inprocess/mapped_image.{hpp,cpp}` builds a per-page protection
  plan, reserves the entire span as `PROT_NONE`, opens populated runs as RW for
  copying and relocation, enables resolver code as RX, applies final segment
  permissions, and seals GNU RELRO read-only.
- `src/loader.cpp` now consumes these components; duplicate
  parser and mapper implementations were removed.
- `tests/loader_parser_test.cpp` mutates the fixture to exercise malformed
  header, segment, W^X, dynamic-pointer, and termination failures.
- `tests/loader_mapping_test.cpp` verifies the page plan, GNU RELRO coverage,
  and absence of writable-executable mappings through `/proc/self/maps`.

The milestone gate is `make clean && make loader-test`. Expected proof:

```text
parser_regressions=0
mapping_invariants=0
fixture_probe=0
fixture_lifecycle=0
```

## Architecture milestone: dependency graph and symbol scope

The second full-loader milestone is complete:

- `ElfImage` now validates and exposes `DT_SONAME`, `DT_RUNPATH`, `DT_RPATH`,
  `DT_VERDEF`, and `DT_VERDEFNUM` in addition to version requirements.
- `DependencyGraph` recursively discovers non-runtime dependencies, expands
  `$ORIGIN`, follows RUNPATH/RPATH and `LD_LIBRARY_PATH`, deduplicates canonical
  paths and SONAMEs, and constructs breadth-first lookup scope without looping
  on dependency cycles.
- glibc runtime objects remain explicitly host-managed; application fixtures
  are represented as custom graph nodes and materialized for the transitional
  relocation backend.
- `SymbolResolver` implements GNU and SysV hash lookup, breadth-first graph
  scope, strong-over-weak selection, hidden/internal filtering, GNU version
  definition matching, and versioned host lookup through `dlvsym`.
- The diamond fixture proves one `libdiamond_leaf.so` graph node is reused by
  both branches. The graph test also selects both `FIXTURE_1.0` and
  `FIXTURE_2.0`, rejects a missing symbol, validates an unresolved weak symbol,
  and exercises a missing dependency failure.

The clean milestone gate now reports:

```text
parser_regressions=0
mapping_invariants=0
graph_nodes=7
graph_resolution=0
fixture_probe=0
fixture_lifecycle=0
```

The dependency graph is complete as metadata and scope infrastructure. Full
custom mapping of every non-runtime graph node is the next milestone; the
current transitional backend still asks glibc to materialize those dependency
objects before root-image relocation.

## Isolated CS2 compatibility mode

`make loader-compatibility-test` validates `cs2.so` without executing its
constructor or touching another process. The report builds the dependency
graph using RUNPATH, `LD_LIBRARY_PATH`, and standard `/usr/lib`, `/usr/lib64`,
`/lib`, and `/lib64` search roots; inventories relocation types; checks owned
TLS and W^X; then runs the complete relocation, unwind-registration, final
protection, and RELRO stages with constructors suppressed.

Direct use:

```bash
./tools/loader/inprocess-loader --relocate-only ./cs2.so
```

Current observed gate:

```text
relocation[1]=3
relocation[6]=157
relocation[7]=2686
relocation[8]=710
wx_pages=0
compatibility=0
relocation_stage=0
```

This proves that the current `cs2.so` can be parsed, dependency-resolved,
mapped, relocated, unwind-registered, protected, RELRO-sealed, and released in
an isolated process. It deliberately does not invoke `ragelin_ctor`: that
constructor installs a crash handler, creates a detached thread, and starts a
bootstrap that requires loaded CS2 modules such as `libclient.so`, SDL3, and
Vulkan. Therefore this mode is a loader compatibility test, not evidence of
live game hook installation or an external-process manual mapper.

`src/loader.cpp` is a Linux/x86_64 ELF relocator and process-inspection CLI. It
maps one `ET_DYN` image into its own process; reads `/proc` identity and maps;
inventories mapped ELF modules; resolves file-backed dynamic symbols; and
performs exact remote-memory reads and writes. Remote transactions stop every
discovered thread with `PTRACE_SEIZE`/`PTRACE_INTERRUPT`, prefer
`process_vm_readv`/`process_vm_writev`, and fall back to ptrace word operations.
It does not execute remote code, inject an ELF, conceal mappings, or contain
application-specific integration.

## Build and run

```bash
make test
```

The target fixture is generated at `build/fixtures/libtarget.so`. The test
passes only when both lines report zero:

```text
fixture_probe=0
fixture_lifecycle=0
```

`fixture_probe` exercises delegated TLS, a local GNU IFUNC, RELA and packed RELR,
a `FIXTURE_1.0` versioned dependency symbol, and a caught C++ exception.
`fixture_lifecycle` verifies constructor order `101, 202` and reverse destructor
order `202, 101`.

## Release validation

Run the publication gate without building the game artifact:

```bash
make release-test
make sanitizers
```

`release-test` runs parser mutation regressions, W^X/RELRO mapping checks,
graph/version/weak-symbol checks, process-control and maps checks, thread-group
stop/cleanup checks, remote read/write checks, module/symbol checks, a child
process harness, negative scenarios, and repeated fixture lifecycles.
`LOADER_STRESS_ITERATIONS` controls the repetition count and defaults to 100:

```bash
LOADER_STRESS_ITERATIONS=1000 make release-test
```

The child-process paths own the process group they create through `posix_spawn`,
enforce a configurable deadline, propagate normal exit or signal status, and
terminate the owned process group on timeout. Remote operations validate map
permissions and may target a non-child process when Linux authorization permits.
They stop the discovered thread group, reject partial `process_vm` transfers,
fall back to ptrace when the fast backend transfers no bytes, and always attempt
to detach. Ptrace writes preserve bytes outside unaligned ranges and roll back
previously written words if a later word write fails.

GitHub Actions runs both the release suite and ASan/UBSan workflow from
`.github/workflows/elf-loader.yml`.

### Publication boundary

Verified claims include in-process ELF loading, PID/map/module inspection,
file-backed remote dynamic-symbol resolution, complete discovered-thread-group
stops, exact remote-memory reads and writes, and owned child orchestration. This
repository does not implement ptrace-policy bypass, remote thread execution,
concealment, or external-process ELF injection. `--relocate-only` remains
constructor-suppressed compatibility validation.

## Mapping transaction

1. Validate ELF64, little-endian, x86_64, `ET_DYN`, program headers, and segment
   file bounds.
2. Reserve one anonymous RW image and copy each `PT_LOAD` segment. Anonymous
   zero-fill supplies BSS.
3. Parse `PT_DYNAMIC`, `PT_GNU_RELRO`, `PT_GNU_EH_FRAME`, and dynamic tables.
4. Open `DT_NEEDED` dependencies with `RTLD_NOW | RTLD_LOCAL`.
5. Mark executable segments RX before invoking IFUNC resolvers. No segment is
   writable and executable simultaneously.
6. Apply packed RELR, RELA, PLT/GOT, GNU symbol versions, weak symbols, local
   IFUNC, and delegated dependency TLS relocations.
7. Register the mapped `.eh_frame` with libgcc, apply final `PT_LOAD`
   protections, and seal `PT_GNU_RELRO` read-only.
8. Invoke `DT_INIT` and `DT_INIT_ARRAY` in forward order.
9. On normal destruction, invoke `DT_FINI_ARRAY` in reverse order, invoke
   `DT_FINI`, deregister unwind metadata, close dependencies, and unmap the
   image.

Construction uses RAII. A failure before constructors releases opened
`DT_NEEDED` handles and the anonymous image without publishing a callable
object. After constructors complete, normal destruction runs the deterministic
finalizer sequence before releasing the mapping.

## Supported contract

- `R_X86_64_RELATIVE`, `R_X86_64_64`, `R_X86_64_GLOB_DAT`,
  `R_X86_64_JUMP_SLOT`, `R_X86_64_IRELATIVE`, `R_X86_64_DTPMOD64`, and
  `R_X86_64_DTPOFF64`.
- RELA and packed RELR tables.
- SysV or GNU dynamic symbol hashes.
- `DT_VERSYM` and `DT_VERNEED` lookup through `dlvsym`.
- GNU IFUNC symbols defined by the custom-mapped image.
- TLS symbols owned by normal dynamic-linker-managed `DT_NEEDED` modules.
- `.eh_frame` registration through `__register_frame` and
  `__deregister_frame`.
- W^X segment transitions and `PT_GNU_RELRO` sealing.

## Deliberate boundary

The core rejects a mapped image that owns `PT_TLS`. Creating a new TLS module
requires integration with the process dynamic linker's module-ID and dynamic
thread-vector lifecycle; emulating that privately would not make
`__tls_get_addr` recognize the image. The fixture therefore places
`thread_local` storage in `libfixturedep.so`, loaded as a normal `DT_NEEDED`
module, while the custom-mapped target carries and resolves the TLS relocations.

The core also does not publish a synthetic `link_map`, implement audit
namespaces, support lazy binding, or recursively custom-map dependencies.
`DT_NEEDED` objects remain the system dynamic linker's responsibility. These
boundaries keep the custom image transaction correct without pretending to be
a complete replacement for glibc `ld.so`.
