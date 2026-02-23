# Contributing to ALICE-Container

## Build

```bash
cargo build
```

## Test

```bash
cargo test --lib --tests
```

Note: examples may have compilation issues independent of the library.

## Lint

```bash
cargo clippy --lib --tests -- -W clippy::all
cargo fmt -- --check
cargo doc --no-deps 2>&1 | grep warning
```

## Optional Features

```bash
# All advanced Linux features
cargo build --features full

# Individual features
cargo build --features io_uring    # io_uring (Linux 5.6+)
cargo build --features clone3      # clone3 (Linux 5.7+)
cargo build --features psi         # PSI monitoring (Linux 4.20+)

# ALICE ecosystem bridges
cargo build --features "analytics,db,crypto"
```

## Design Constraints

- **Direct kernel control**: cgroup v2 and namespace manipulation via syscalls, no Docker/Podman/systemd dependency.
- **Linux-only syscalls**: `unshare(2)`, `pivot_root(2)`, `clone3(2)` — guarded by `#[cfg(target_os = "linux")]`.
- **Microsecond scheduling**: dynamic `cpu.max` quota adjustment for latency-sensitive workloads.
- **`no_std` core**: base types work without `std`; syscall features require `std`.
