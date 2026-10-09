# AGENT.md

## Project purpose and vision

`elf-loader` aims to become a comprehensive, production-quality, open-source
ELF toolkit for Linux: one coherent project for parsing, validation, loading,
linking, relocation, inspection, debugging, instrumentation, compatibility
analysis, process interaction, testing, and lifecycle management.

“General-purpose” means that features should be reusable across architectures,
distributions, toolchains, libc implementations, binaries, shared objects, and
operational contexts instead of being tied to one person, organization, game,
application, or proprietary deployment. The long-term goal is broad ELF
coverage with explicit capability detection and accurately documented platform
support—not an unsupported claim of universal behavior.

Feature scope is evaluated by technical merit, maintainability, interoperability,
testability, and relevance to Linux ELF tooling. A capability is not excluded
merely because it is dual-use or can alter another process. The project remains
open-source, transparent, and intended for engineering, research, debugging,
observability, compatibility, security analysis, incident response, testing,
and administration. Operating-system authorization and applicable law remain
the operator's responsibility; the project does not implement authorization or
security-policy bypasses.

## Scope expansion priorities

Growth should favor complete, interoperable ELF capabilities rather than a
collection of unrelated commands. New work should advance one or more of:

- additional Linux architectures and ABI variants;
- broader ELF file types, program headers, sections, dynamic tags, relocation
  families, symbol models, TLS models, and versioning schemes;
- robust static and dynamic inspection APIs;
- loader, linker, debugger, profiler, and instrumentation use cases;
- namespace, container, libc, kernel, compiler, and distribution compatibility;
- stable library APIs in addition to auditable CLI interfaces;
- deterministic transactions, rollback, lifecycle, and resource ownership;
- fuzzing, malformed-input corpora, conformance fixtures, cross-toolchain tests,
  sanitizer gates, and representative CI environments;
- precise diagnostics and machine-readable output for automation.

Breadth must not create duplicated parsers, competing abstractions, silent
fallbacks, or weakly tested compatibility claims. Reuse validated core models
and keep every supported capability covered by executable tests and current
documentation.

## Development principles

All changes must:

- serve a documented, general-purpose Linux ELF use case;
- remain suitable for public source review, reproducible builds, and open
  collaboration;
- avoid assumptions tied to a particular person, organization, game,
  application, or proprietary deployment;
- preserve and accurately report operating-system authorization and
  process-ownership behavior;
- prefer transparent behavior, clear diagnostics, deterministic cleanup, and
  auditable interfaces;
- document security boundaries, required privileges, side effects, failure
  modes, and unsupported behavior;
- reject malformed or unsupported input safely instead of guessing;
- include meaningful verification for newly supported behavior;
- keep source code, tests, documentation, and CLI contracts consistent.

## Testing requirements

Every feature, bug fix, compatibility extension, and behavior change must add
or update test files. A change is not complete when only the implementation is
written.

Tests must:

- cover the public, observable behavior introduced or changed;
- include relevant success, malformed-input, boundary, error, timeout, and
  cleanup paths;
- add a regression case for every fixed bug when the failure can be reproduced
  deterministically;
- verify security and lifecycle invariants such as W^X, RELRO, ownership,
  resource release, process reaping, and deterministic constructor/destructor
  order when affected;
- use isolated synthetic fixtures instead of personal, proprietary, or
  application-specific artifacts;
- be deterministic, independent, and suitable for local and CI execution;
- avoid tests that only check implementation details, source text, forwarding,
  or that a function does not throw;
- be connected to the appropriate `Makefile` target and CI/release or sanitizer
  gate where applicable;
- keep existing tests updated when a documented public contract changes.

The changed runtime path must also be exercised directly after tests pass.
Compilation alone, mocks alone, or an unexecuted test file is not sufficient
verification. If an environment-dependent path cannot run in CI, provide the
closest deterministic fixture and document the exact unverified limitation.

## Compatibility

Features should be implemented broadly and portably within the project's stated
Linux ELF scope. Compatibility work should:

- use documented Linux, ELF, and libc interfaces where available;
- avoid unnecessary distribution-, kernel-, compiler-, or libc-specific
  assumptions;
- detect platform capabilities and fail with actionable errors when a required
  capability is unavailable;
- preserve backward-compatible public behavior unless a clean, documented
  migration is required for correctness or security;
- test representative supported environments and edge cases;
- state exact supported architectures, ABI constraints, toolchain requirements,
  and deliberate limitations rather than claiming universal compatibility.

Compatibility must never be achieved by weakening validation, memory safety,
W^X, RELRO, authorization checks, ownership rules, or lifecycle cleanup.

## Process interaction and authorization

The project may support both read-only and state-changing process interaction,
including tracing, debugging, register inspection or modification, remote
memory operations, remote execution primitives, and loader/linker integration.
These capabilities are evaluated by their technical contracts rather than
excluded because they are dual-use.

Features that can stop or modify a process must:

- expose explicit, documented target-selection behavior;
- use Linux credential, capability, namespace, and ptrace interfaces as
  implemented by the operating system rather than silently circumventing them;
- report operations that can pause, alter, crash, or terminate a target;
- define whether target state is persistent, restored, or transactionally
  rolled back;
- clean up trace relationships and owned resources deterministically on
  success, failure, timeout, interruption, and exceptions;
- produce actionable diagnostics for permission failures and unsupported
  kernels;
- include tests using synthetic, owned child processes. Automated tests must
  never mutate unrelated existing processes;
- document state mutations, required privileges, races, architecture-specific
  behavior, and recovery limitations.

The project does not impose an artificial read-only or child-only product
boundary. Existing non-child processes may be supported when Linux permits the
requested operation. Broad capability does not require target-specific code,
stealth behavior, credential bypasses, or undocumented side effects; those are
separate design choices and are not prerequisites for a comprehensive ELF
toolkit.

## Review requirements

Before merging a feature, reviewers must verify:

1. its general-purpose Linux ELF use case and technical contract are documented;
2. authorization, target-selection, and process-ownership behavior are
   explicit;
3. state-changing process operations declare mutations and restore or clean up
   target state according to their documented contract;
4. malformed input and partial failure leave no leaked resources or unintended
   altered external state;
5. tests exercise observable behavior, boundaries, timeout/error paths,
   cleanup, and permission failures using owned synthetic targets;
6. documentation accurately describes support and limitations;
7. the implementation does not introduce person- or application-specific
   targeting.
