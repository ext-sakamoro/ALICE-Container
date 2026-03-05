# Changelog

All notable changes to ALICE-Container will be documented in this file.

## [0.2.1] - 2026-03-04

### Added
- `ffi` — 45 `extern "C"` functions (`ac_ctr_*` prefix) for Unity/UE5/C consumers
- `bindings/unity/AliceContainer.cs` — 45 DllImport + 5 RAII handles
- `bindings/ue5/AliceContainer.h` — 45 extern C + 5 RAII types
- 12 FFI tests (null safety, config lifecycle, quota helpers, version)

### Fixed
- `examples/scheduler_demo.rs` — `min_quota_percent`/`max_quota_percent` → `min_quota_us`/`max_quota_us`

## [0.2.0] - 2026-02-23

### Added
- `container` — `ContainerConfig`, `Container` lifecycle (create, start, stop, destroy)
- `cgroup` — Direct cgroup v2 control via `/sys/fs/cgroup` (cpu, memory, io, pids)
- `namespace` — `NamespaceFlags`, `unshare(2)`, UID/GID mapping
- `rootfs` — `pivot_root(2)` based root filesystem isolation
- `scheduler` — Dynamic CPU quota adjustment for latency-sensitive workloads
- `io_uring` — (feature `io_uring`) io_uring async I/O support (Linux 5.6+)
- `clone3` — (feature `clone3`) `clone3(2)` with `CLONE_INTO_CGROUP` (Linux 5.7+)
- `psi` — (feature `psi`) Pressure Stall Information monitoring (Linux 4.20+)
- `analytics_bridge` — (feature `analytics`) ALICE-Analytics container metrics
- `db_bridge` — (feature `db`) ALICE-DB container state persistence
- `crypto_bridge` — (feature `crypto`) ALICE-Crypto container secret management
- `sync_bridge` — (feature `sync`) Container sync events
- `prelude` module for convenience imports
- 23 unit tests
