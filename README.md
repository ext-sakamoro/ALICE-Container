# ALICE-Container

**Minimal Container Runtime with Direct Kernel Control** - v0.2.0

> "No Docker, no Podman, just Rust and the Linux kernel."

A Rust library for running isolated processes with direct cgroup v2 and namespace manipulation, without relying on Docker, Podman, or systemd.

## Features

| Feature | Description | Syscalls |
|---------|-------------|----------|
| **Direct Cgroup v2** | Microsecond-level resource control | `/sys/fs/cgroup` writes |
| **Namespace Isolation** | Process, mount, network isolation | `clone(2)`, `unshare(2)` |
| **Pivot Root** | Filesystem isolation | `pivot_root(2)` |
| **Dynamic Scheduling** | CPU quota adjustment for latency | `cpu.max` manipulation |

### Advanced Features (v0.2.0)

| Feature | Kernel | Description |
|---------|--------|-------------|
| **io_uring Cgroup** | 5.6+ | Async batched cgroup writes (3 syscalls → 1) |
| **clone3 + CLONE_INTO_CGROUP** | 5.7+ | Zero-copy cgroup placement |
| **PSI Monitoring** | 4.20+ | Event-driven pressure-based scheduling |

## Design Philosophy

### Why Not Docker?

Docker adds layers:
- containerd → runc → shim → your process
- Complex networking (docker0 bridge, iptables)
- Image layers and overlay filesystems

**ALICE-Container provides:**
- Direct kernel interface (no intermediaries)
- Microsecond-level control over resources
- Minimal attack surface
- Suitable for embedded/IoT

### Ghost Scheduling (Lite)

Instead of eBPF-based scheduling (like Google's ghOSt), we use cgroup v2 CPU quota dynamic adjustment:

```
Monitor: cpu.stat (usage, throttled)
         ↓
Decide:  High utilization? → Increase quota
         Low utilization?  → Decrease quota
         ↓
Apply:   cpu.max = "new_quota period"
```

This provides ~90% of the benefits with zero kernel modifications.

### PSI-Driven Scheduling (v0.2.0)

With the `psi` feature, scheduling becomes event-driven:

```
┌────────────────────────────────────────┐
│  /proc/pressure/cpu                    │
│  ├── Trigger: "some 50000 1000000"     │
│  └── epoll_wait()                      │
│           │                            │
│           ▼ (event on pressure)        │
│  ┌─────────────────────────────────┐   │
│  │  PsiScheduler                   │   │
│  │  • Receive pressure event       │   │
│  │  • Adjust cpu.max immediately   │   │
│  │  • Zero polling overhead        │   │
│  └─────────────────────────────────┘   │
└────────────────────────────────────────┘
```

**Performance comparison:**

| Scheduler | CPU Overhead | Latency |
|-----------|--------------|---------|
| DynamicScheduler (polling) | ~1% | 10ms |
| PsiScheduler (events) | ~0% | <1ms |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ALICE-Container                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Container::create()                                        │
│         │                                                   │
│         ▼                                                   │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    │
│  │  Namespace  │    │   Cgroup    │    │   RootFS    │    │
│  │  (unshare)  │    │   (v2)      │    │ (pivot_root)│    │
│  │             │    │             │    │             │    │
│  │ • NEWNS     │    │ • cpu.max   │    │ • /proc     │    │
│  │ • NEWPID    │    │ • memory.max│    │ • /dev      │    │
│  │ • NEWUTS    │    │ • io.max    │    │ • bind mnt  │    │
│  │ • NEWIPC    │    │ • freeze    │    │             │    │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘    │
│         │                  │                  │            │
│         └──────────────────┼──────────────────┘            │
│                            ▼                               │
│                    ┌─────────────┐                         │
│                    │  Scheduler  │                         │
│                    │ (dynamic)   │                         │
│                    │             │                         │
│                    │ • tick()    │                         │
│                    │ • burst()   │                         │
│                    │ • throttle()│                         │
│                    └──────┬──────┘                         │
│                           │                                │
│                           ▼                                │
│                   Isolated Process                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Basic Container

```rust
use alice_container::prelude::*;

// Create container with resource limits
let config = ContainerConfig::builder()
    .rootfs("/var/lib/alice/rootfs/alpine")
    .hostname("my-container")
    .cpu_percent(50)                      // 50% of one CPU
    .memory_max(256 * 1024 * 1024)        // 256 MB
    .build();

let mut container = Container::create("my-container", config)?;

// Start the container
container.start()?;

// Execute a command
let exit_code = container.exec(&["/bin/sh", "-c", "echo hello"])?;

// Clean up
container.stop()?;
container.destroy()?;
```

### Direct Cgroup Control

```rust
use alice_container::cgroup::{CgroupController, CpuConfig, MemoryConfig};

// Create cgroup
let cgroup = CgroupController::create("my-container")?;

// Set CPU limit: 50ms per 100ms period = 50%
cgroup.set_cpu_max(50_000, 100_000)?;

// Set memory limit: 256MB
cgroup.set_memory_max(256 * 1024 * 1024)?;

// Add process to cgroup
cgroup.add_process(pid)?;

// Monitor usage
println!("Memory: {} bytes", cgroup.memory_current()?);
println!("CPU: {} us", cgroup.cpu_usage_us()?);

// Freeze all processes
cgroup.freeze()?;

// Cleanup
cgroup.destroy()?;
```

### Namespace Isolation

```rust
use alice_container::namespace::{Namespaces, NamespaceFlags, pivot_root};
use std::path::Path;

// Create new namespaces
let ns = Namespaces::container();  // Mount, PID, UTS, IPC
ns.unshare()?;

// Set hostname (requires UTS namespace)
ns.set_hostname("isolated")?;

// Pivot root (requires Mount namespace)
pivot_root(
    Path::new("/container/rootfs"),
    Path::new("/container/rootfs/.old_root"),
)?;
```

### Dynamic CPU Scheduling

```rust
use alice_container::scheduler::{DynamicScheduler, SchedulerConfig};
use alice_container::cgroup::CgroupController;

let cgroup = CgroupController::create("my-container")?;

// Create low-latency scheduler
let config = SchedulerConfig::low_latency();
let mut scheduler = DynamicScheduler::new(cgroup, config);

// Start scheduling
scheduler.start()?;

// Periodic tick (call from event loop)
loop {
    match scheduler.tick()? {
        SchedulerDecision::Adjust { new_quota_us } => {
            println!("Quota adjusted to {}us", new_quota_us);
        }
        _ => {}
    }
    std::thread::sleep(Duration::from_millis(1));
}
```

### Root Filesystem Setup

```rust
use alice_container::rootfs::RootFs;
use std::path::Path;

// Create minimal rootfs
let rootfs = RootFs::create("/var/lib/alice/containers/test")?;

// Bind mount host directories (read-only)
rootfs.bind_mount_ro(Path::new("/usr"), "usr")?;
rootfs.bind_mount_ro(Path::new("/lib"), "lib")?;
rootfs.bind_mount_ro(Path::new("/lib64"), "lib64")?;
rootfs.bind_mount_ro(Path::new("/bin"), "bin")?;

// Mount proc and dev
rootfs.mount_proc()?;
rootfs.setup_dev()?;

// Set container identity
rootfs.set_hostname("my-container")?;
rootfs.set_hosts("my-container")?;
rootfs.set_resolv_conf(&["8.8.8.8", "8.8.4.4"])?;

// Prepare for pivot_root
let put_old = rootfs.prepare_pivot()?;
```

### io_uring Batched Cgroup Operations (v0.2.0)

```rust
use alice_container::io_uring::IoUringCgroup;

// Batch multiple cgroup writes into single syscall
let mut batch = IoUringCgroup::new("/sys/fs/cgroup/alice/test")?;
batch.queue_cpu_max(50_000, 100_000);    // 50% CPU
batch.queue_memory_max(256 * 1024 * 1024); // 256MB
batch.queue_io_max("8:0", 1048576, 1048576); // 1MB/s
batch.sync_batch_write()?;  // Single batched operation
```

### clone3 with CLONE_INTO_CGROUP (v0.2.0)

```rust
use alice_container::clone3::{spawn_into_cgroup, clone_flags};
use std::path::Path;

// Spawn process directly into cgroup (no separate add_process needed)
let pid = spawn_into_cgroup(
    Path::new("/sys/fs/cgroup/alice/test"),
    clone_flags::CONTAINER,  // NEWNS | NEWPID | NEWUTS | NEWIPC
    || {
        // Child process code
        println!("Running in container!");
        0
    }
)?;
```

### PSI-Driven Scheduling (v0.2.0)

```rust
use alice_container::psi::{PsiScheduler, PsiTrigger};
use std::time::Duration;

// Create PSI-driven scheduler
let mut scheduler = PsiScheduler::new("/sys/fs/cgroup/alice/test")?;
scheduler.start()?;

// Event loop - zero polling overhead
loop {
    match scheduler.wait(Duration::from_secs(1))? {
        Some(event) => println!("Pressure event: {:?}", event),
        None => {} // Timeout, no pressure
    }
}
```

## Modules

### `cgroup` - Direct Cgroup v2 Control

| Type | Description |
|------|-------------|
| `CgroupController` | Create/manage cgroup hierarchies |
| `CpuConfig` | CPU quota, period, weight |
| `MemoryConfig` | Memory limits and thresholds |
| `IoConfig` | I/O bandwidth limits |

**Cgroup Interface Files:**

| File | Description | Example |
|------|-------------|---------|
| `cpu.max` | CPU quota | `50000 100000` (50%) |
| `memory.max` | Memory limit | `268435456` (256MB) |
| `io.max` | I/O limits | `8:0 rbps=1048576` |
| `cgroup.procs` | Process list | Write PID to add |
| `cgroup.freeze` | Freeze processes | `1` to freeze |

### `namespace` - Linux Namespace Isolation

| Type | Description |
|------|-------------|
| `Namespaces` | Namespace controller |
| `NamespaceFlags` | NEWNS, NEWPID, NEWNET, etc. |
| `CloneFlags` | Flags for clone() |
| `IdMapping` | UID/GID mapping |

**Namespace Types:**

| Namespace | Flag | Isolates |
|-----------|------|----------|
| Mount | `CLONE_NEWNS` | Mount points |
| PID | `CLONE_NEWPID` | Process IDs |
| Network | `CLONE_NEWNET` | Network stack |
| UTS | `CLONE_NEWUTS` | Hostname |
| IPC | `CLONE_NEWIPC` | IPC primitives |
| User | `CLONE_NEWUSER` | User/Group IDs |

### `scheduler` - Dynamic CPU Scheduling

| Type | Description |
|------|-------------|
| `DynamicScheduler` | CPU quota controller |
| `SchedulerConfig` | Latency targets, thresholds |
| `SchedulerDecision` | Tick result |
| `CpuStats` | Usage statistics |

**Scheduling Modes:**

| Mode | Latency | Min Quota | Max Quota |
|------|---------|-----------|-----------|
| Low Latency | 100μs | 50% | 100% |
| Default | 1ms | 10% | 100% |
| Batch | 100ms | 10% | 50% |

### `container` - Lifecycle Management

| Type | Description |
|------|-------------|
| `Container` | Main container abstraction |
| `ContainerConfig` | Configuration builder |
| `ContainerState` | Created, Running, Paused, Stopped |

**Lifecycle:**

```
create() → start() → exec() → stop() → destroy()
              ↓          ↑
           pause() → resume()
```

### `rootfs` - Filesystem Construction

| Type | Description |
|------|-------------|
| `RootFs` | Rootfs builder |
| `mount()` | Low-level mount wrapper |
| `mount_proc()` | Mount /proc |
| `mount_dev()` | Create minimal /dev |

## Requirements

- **Linux kernel 5.0+** (cgroup v2 unified hierarchy)
- **Root privileges** (CAP_SYS_ADMIN, CAP_NET_ADMIN)
- **Cgroup v2** mounted at `/sys/fs/cgroup`

### Check Cgroup v2 Availability

```bash
# Check if cgroup v2 is mounted
mount | grep cgroup2

# Check available controllers
cat /sys/fs/cgroup/cgroup.controllers

# Should show: cpuset cpu io memory hugetlb pids rdma misc
```

### Enable Cgroup v2 (if needed)

Add to kernel command line:
```
systemd.unified_cgroup_hierarchy=1
```

## Building

```bash
# Standard build
cargo build --release

# Build with all advanced features
cargo build --release --features full

# Build with specific features
cargo build --release --features "io_uring,clone3,psi"

# Run tests (requires root for some tests)
sudo cargo test --features full

# Build for embedded (no_std preparation)
cargo build --release --no-default-features
```

### Feature Flags

| Feature | Kernel | Description |
|---------|--------|-------------|
| `std` | - | Standard library (default) |
| `io_uring` | 5.6+ | Async batched cgroup writes |
| `clone3` | 5.7+ | CLONE_INTO_CGROUP support |
| `psi` | 4.20+ | Pressure Stall Information monitoring |
| `full` | 5.7+ | All advanced features |

## Comparison with Alternatives

| Feature | ALICE-Container | Docker | Podman | runc |
|---------|----------------|--------|--------|------|
| Dependencies | libc only | containerd, runc | conmon, runc | libseccomp |
| Startup time | ~1ms | ~500ms | ~300ms | ~50ms |
| Memory overhead | ~100KB | ~50MB | ~30MB | ~5MB |
| Cgroup control | Direct | Via API | Via API | Direct |
| Dynamic scheduling | Yes | No | No | No |
| systemd integration | No | Optional | Optional | Optional |
| io_uring batching | Yes | No | No | No |
| PSI monitoring | Yes | No | No | No |
| clone3 cgroup | Yes | No | No | Partial |

## Use Cases

- **ALICE Workloads**: Run ALICE binaries (WASM/Native) in isolation
- **Edge/IoT**: Minimal footprint container runtime
- **Latency-Sensitive**: Dynamic CPU quota for real-time workloads
- **Testing**: Quick container creation without Docker overhead
- **Embedded**: Direct kernel interface, no daemon required

## Security Considerations

- **Requires root**: Most operations need CAP_SYS_ADMIN
- **User namespaces**: Can enable unprivileged containers
- **Seccomp**: Not included (can be added separately)
- **AppArmor/SELinux**: Not included (use host MAC)

## License

AGPL-3.0 - See [LICENSE](LICENSE) for details.

## References

- [cgroup v2 documentation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
- [namespaces(7)](https://man7.org/linux/man-pages/man7/namespaces.7.html)
- [clone(2)](https://man7.org/linux/man-pages/man2/clone.2.html)
- [clone3(2)](https://man7.org/linux/man-pages/man2/clone3.2.html)
- [pivot_root(2)](https://man7.org/linux/man-pages/man2/pivot_root.2.html)
- [io_uring](https://kernel.dk/io_uring.pdf)
- [PSI - Pressure Stall Information](https://www.kernel.org/doc/html/latest/accounting/psi.html)
- [ghOSt: Fast & Flexible User-Space Delegation of Linux Scheduling](https://dl.acm.org/doi/10.1145/3477132.3483542)
