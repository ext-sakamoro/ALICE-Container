//! C-ABI FFI for Unity / UE5 / C consumers
//!
//! All functions use the `ac_ctr_*` prefix (ALICE-Container).
//! Opaque pointers are heap-allocated via `Box::into_raw` / `Box::from_raw`.
//!
//! ## Ownership Rules
//!
//! | Function suffix | Semantics |
//! |-----------------|-----------|
//! | `_new` / `_create` | Caller owns the returned pointer |
//! | `_free` | Drop without side-effects (leak cgroup) |
//! | `_destroy` | Stop + cleanup + drop (consumes pointer) |
//!
//! ## Error Convention
//!
//! Functions returning `i32`: 0 = success, -1 = error.
//! Functions returning pointers: null = error.

#![allow(clippy::missing_safety_doc)]

use core::ffi::{c_char, c_int};
use std::ffi::{CStr, CString};
use std::sync::OnceLock;

use crate::cgroup::CgroupController;
use crate::container::{Container, ContainerConfig};
use crate::scheduler::{
    percent_from_quota, quota_from_percent, DynamicScheduler, SchedulerConfig, SchedulerDecision,
};

// ============================================================================
// Memory Management
// ============================================================================

/// Free a string returned by this library.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_string_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

// ============================================================================
// ContainerConfig
// ============================================================================

/// Create a default `ContainerConfig`.
#[no_mangle]
pub extern "C" fn ac_ctr_config_new() -> *mut ContainerConfig {
    Box::into_raw(Box::new(ContainerConfig::default()))
}

/// Free a `ContainerConfig`.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_config_free(ptr: *mut ContainerConfig) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr));
    }
}

/// Set hostname.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_config_set_hostname(
    ptr: *mut ContainerConfig,
    hostname: *const c_char,
) {
    if ptr.is_null() || hostname.is_null() {
        return;
    }
    if let Ok(s) = CStr::from_ptr(hostname).to_str() {
        (*ptr).hostname = s.to_string();
    }
}

/// Set CPU percentage (1-100 per core, >100 for multi-core).
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_config_set_cpu_percent(ptr: *mut ContainerConfig, percent: u32) {
    if ptr.is_null() {
        return;
    }
    (*ptr).cpu = crate::cgroup::CpuConfig::from_percent(percent);
}

/// Set CPU quota in microseconds.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_config_set_cpu_quota_us(ptr: *mut ContainerConfig, quota_us: u64) {
    if ptr.is_null() {
        return;
    }
    (*ptr).cpu.quota_us = quota_us;
}

/// Set memory limit in bytes.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_config_set_memory_max(ptr: *mut ContainerConfig, bytes: u64) {
    if ptr.is_null() {
        return;
    }
    (*ptr).memory = crate::cgroup::MemoryConfig::with_limit(bytes);
}

/// Enable or disable network namespace.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_config_set_network(ptr: *mut ContainerConfig, enable: bool) {
    if ptr.is_null() {
        return;
    }
    (*ptr).network = enable;
    if enable {
        (*ptr).namespaces = (*ptr)
            .namespaces
            .union(crate::namespace::NamespaceFlags::NEWNET);
    }
}

/// Set read-only root filesystem.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_config_set_readonly(ptr: *mut ContainerConfig, readonly: bool) {
    if ptr.is_null() {
        return;
    }
    (*ptr).readonly_rootfs = readonly;
}

// ============================================================================
// Container Lifecycle
// ============================================================================

/// Create a container. Consumes the config pointer.
///
/// Returns null on error.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_container_create(
    id: *const c_char,
    config: *mut ContainerConfig,
) -> *mut Container {
    if id.is_null() || config.is_null() {
        return std::ptr::null_mut();
    }
    let id_str = match CStr::from_ptr(id).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let cfg = *Box::from_raw(config);
    match Container::create(id_str, cfg) {
        Ok(c) => Box::into_raw(Box::new(c)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Drop a container without destroying the cgroup.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_container_free(ptr: *mut Container) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr));
    }
}

/// Start the container. Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_container_start(ptr: *mut Container) -> c_int {
    if ptr.is_null() {
        return -1;
    }
    match (*ptr).start() {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Stop the container. Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_container_stop(ptr: *mut Container) -> c_int {
    if ptr.is_null() {
        return -1;
    }
    match (*ptr).stop() {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Pause the container. Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_container_pause(ptr: *mut Container) -> c_int {
    if ptr.is_null() {
        return -1;
    }
    match (*ptr).pause() {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Resume a paused container. Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_container_resume(ptr: *mut Container) -> c_int {
    if ptr.is_null() {
        return -1;
    }
    match (*ptr).resume() {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Execute a command. Returns exit code, or -1 on error.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_container_exec(
    ptr: *mut Container,
    argv: *const *const c_char,
    argc: c_int,
) -> c_int {
    if ptr.is_null() || argv.is_null() || argc <= 0 {
        return -1;
    }
    let mut cmd: Vec<&str> = Vec::with_capacity(argc as usize);
    for i in 0..argc as usize {
        let arg = *argv.add(i);
        if arg.is_null() {
            return -1;
        }
        match CStr::from_ptr(arg).to_str() {
            Ok(s) => cmd.push(s),
            Err(_) => return -1,
        }
    }
    (*ptr).exec(&cmd).unwrap_or(-1)
}

/// Destroy the container (stop + remove cgroup). Consumes the pointer.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_container_destroy(ptr: *mut Container) -> c_int {
    if ptr.is_null() {
        return -1;
    }
    let container = *Box::from_raw(ptr);
    match container.destroy() {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Get container ID. Caller must free with `ac_ctr_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_container_id(ptr: *const Container) -> *mut c_char {
    if ptr.is_null() {
        return std::ptr::null_mut();
    }
    match CString::new((*ptr).id()) {
        Ok(cs) => cs.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Get container state: 0=Created, 1=Running, 2=Paused, 3=Stopped.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_container_state(ptr: *const Container) -> u8 {
    if ptr.is_null() {
        return 255;
    }
    match (*ptr).state() {
        crate::container::ContainerState::Created => 0,
        crate::container::ContainerState::Running => 1,
        crate::container::ContainerState::Paused => 2,
        crate::container::ContainerState::Stopped => 3,
    }
}

/// Get init PID, or -1 if not running.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_container_pid(ptr: *const Container) -> i64 {
    if ptr.is_null() {
        return -1;
    }
    match (*ptr).pid() {
        Some(pid) => pid as i64,
        None => -1,
    }
}

/// Get current memory usage in bytes (0 on error).
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_container_memory_usage(ptr: *const Container) -> u64 {
    if ptr.is_null() {
        return 0;
    }
    (*ptr).memory_usage().unwrap_or(0)
}

/// Get current CPU usage in microseconds (0 on error).
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_container_cpu_usage(ptr: *const Container) -> u64 {
    if ptr.is_null() {
        return 0;
    }
    (*ptr).cpu_usage().unwrap_or(0)
}

// ============================================================================
// CgroupController
// ============================================================================

/// Create a new cgroup. Returns null on error.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_cgroup_create(name: *const c_char) -> *mut CgroupController {
    if name.is_null() {
        return std::ptr::null_mut();
    }
    let name_str = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    match CgroupController::create(name_str) {
        Ok(c) => Box::into_raw(Box::new(c)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Open an existing cgroup. Returns null on error.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_cgroup_open(name: *const c_char) -> *mut CgroupController {
    if name.is_null() {
        return std::ptr::null_mut();
    }
    let name_str = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    match CgroupController::open(name_str) {
        Ok(c) => Box::into_raw(Box::new(c)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Drop a cgroup handle without destroying the cgroup directory.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_cgroup_free(ptr: *mut CgroupController) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr));
    }
}

/// Destroy the cgroup (kill processes + remove directory). Consumes the pointer.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_cgroup_destroy(ptr: *mut CgroupController) -> c_int {
    if ptr.is_null() {
        return -1;
    }
    let cgroup = *Box::from_raw(ptr);
    match cgroup.destroy() {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Set CPU quota (microseconds) and period. Returns 0 on success.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_cgroup_set_cpu_max(
    ptr: *mut CgroupController,
    quota_us: u64,
    period_us: u64,
) -> c_int {
    if ptr.is_null() {
        return -1;
    }
    match (*ptr).set_cpu_max(quota_us, period_us) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Set memory limit in bytes. Returns 0 on success.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_cgroup_set_memory_max(
    ptr: *mut CgroupController,
    bytes: u64,
) -> c_int {
    if ptr.is_null() {
        return -1;
    }
    match (*ptr).set_memory_max(bytes) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Add a process to the cgroup. Returns 0 on success.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_cgroup_add_process(ptr: *mut CgroupController, pid: u32) -> c_int {
    if ptr.is_null() {
        return -1;
    }
    match (*ptr).add_process(pid) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Freeze all processes. Returns 0 on success.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_cgroup_freeze(ptr: *mut CgroupController) -> c_int {
    if ptr.is_null() {
        return -1;
    }
    match (*ptr).freeze() {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Unfreeze all processes. Returns 0 on success.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_cgroup_unfreeze(ptr: *mut CgroupController) -> c_int {
    if ptr.is_null() {
        return -1;
    }
    match (*ptr).unfreeze() {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Kill all processes. Returns 0 on success.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_cgroup_kill_all(ptr: *mut CgroupController) -> c_int {
    if ptr.is_null() {
        return -1;
    }
    match (*ptr).kill_all() {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Get current memory usage in bytes (0 on error).
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_cgroup_memory_current(ptr: *const CgroupController) -> u64 {
    if ptr.is_null() {
        return 0;
    }
    (*ptr).memory_current().unwrap_or(0)
}

/// Get current CPU usage in microseconds (0 on error).
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_cgroup_cpu_usage_us(ptr: *const CgroupController) -> u64 {
    if ptr.is_null() {
        return 0;
    }
    (*ptr).cpu_usage_us().unwrap_or(0)
}

// ============================================================================
// DynamicScheduler
// ============================================================================

/// Create a scheduler. Opens the named cgroup internally.
///
/// `mode`: 0 = default, 1 = low_latency, 2 = batch.
/// Returns null on error.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_scheduler_new(
    cgroup_name: *const c_char,
    mode: u8,
) -> *mut DynamicScheduler {
    if cgroup_name.is_null() {
        return std::ptr::null_mut();
    }
    let name = match CStr::from_ptr(cgroup_name).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let cgroup = match CgroupController::open(name) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    let config = match mode {
        1 => SchedulerConfig::low_latency(),
        2 => SchedulerConfig::batch(),
        _ => SchedulerConfig::default(),
    };
    Box::into_raw(Box::new(DynamicScheduler::new(cgroup, config)))
}

/// Free a scheduler.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_scheduler_free(ptr: *mut DynamicScheduler) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr));
    }
}

/// Start the scheduler. Returns 0 on success.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_scheduler_start(ptr: *mut DynamicScheduler) -> c_int {
    if ptr.is_null() {
        return -1;
    }
    match (*ptr).start() {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Stop the scheduler. Returns 0 on success.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_scheduler_stop(ptr: *mut DynamicScheduler) -> c_int {
    if ptr.is_null() {
        return -1;
    }
    match (*ptr).stop() {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Perform one tick. Returns decision: 0=Idle, 1=TooSoon, 2=Maintain, 3=Adjust.
/// Returns 255 on error.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_scheduler_tick(ptr: *mut DynamicScheduler) -> u8 {
    if ptr.is_null() {
        return 255;
    }
    match (*ptr).tick() {
        Ok(SchedulerDecision::Idle) => 0,
        Ok(SchedulerDecision::TooSoon) => 1,
        Ok(SchedulerDecision::Maintain) => 2,
        Ok(SchedulerDecision::Adjust { .. }) => 3,
        Err(_) => 255,
    }
}

/// Force burst mode (maximize quota). Returns 0 on success.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_scheduler_burst(ptr: *mut DynamicScheduler) -> c_int {
    if ptr.is_null() {
        return -1;
    }
    match (*ptr).burst_mode() {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Force throttle mode (minimize quota). Returns 0 on success.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_scheduler_throttle(ptr: *mut DynamicScheduler) -> c_int {
    if ptr.is_null() {
        return -1;
    }
    match (*ptr).throttle() {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Get current quota in microseconds.
#[no_mangle]
pub unsafe extern "C" fn ac_ctr_scheduler_current_quota(ptr: *const DynamicScheduler) -> u64 {
    if ptr.is_null() {
        return 0;
    }
    (*ptr).current_quota()
}

// ============================================================================
// Utility
// ============================================================================

/// Calculate CPU quota from percentage.
#[no_mangle]
pub extern "C" fn ac_ctr_quota_from_percent(cpu_percent: u32, period_us: u64) -> u64 {
    quota_from_percent(cpu_percent, period_us)
}

/// Calculate CPU percentage from quota.
#[no_mangle]
pub extern "C" fn ac_ctr_percent_from_quota(quota_us: u64, period_us: u64) -> u32 {
    percent_from_quota(quota_us, period_us)
}

/// Library version string. Do NOT free the returned pointer.
#[no_mangle]
pub extern "C" fn ac_ctr_version() -> *const c_char {
    static VERSION: OnceLock<CString> = OnceLock::new();
    VERSION
        .get_or_init(|| {
            CString::new(env!("CARGO_PKG_VERSION"))
                .unwrap_or_else(|_| CString::new("0.0.0").unwrap())
        })
        .as_ptr()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_lifecycle() {
        unsafe {
            let config = ac_ctr_config_new();
            assert!(!config.is_null());
            ac_ctr_config_set_cpu_percent(config, 50);
            assert_eq!((*config).cpu.quota_us, 50_000);
            ac_ctr_config_set_memory_max(config, 256 * 1024 * 1024);
            assert_eq!((*config).memory.max, 256 * 1024 * 1024);
            ac_ctr_config_set_readonly(config, true);
            assert!((*config).readonly_rootfs);
            ac_ctr_config_free(config);
        }
    }

    #[test]
    fn test_config_hostname() {
        unsafe {
            let config = ac_ctr_config_new();
            let name = c"test-host".as_ptr();
            ac_ctr_config_set_hostname(config, name);
            assert_eq!((*config).hostname, "test-host");
            ac_ctr_config_free(config);
        }
    }

    #[test]
    fn test_config_network() {
        unsafe {
            let config = ac_ctr_config_new();
            ac_ctr_config_set_network(config, true);
            assert!((*config).network);
            ac_ctr_config_free(config);
        }
    }

    #[test]
    fn test_config_cpu_quota_us() {
        unsafe {
            let config = ac_ctr_config_new();
            ac_ctr_config_set_cpu_quota_us(config, 75_000);
            assert_eq!((*config).cpu.quota_us, 75_000);
            ac_ctr_config_free(config);
        }
    }

    #[test]
    fn test_null_safety_config() {
        unsafe {
            ac_ctr_config_free(std::ptr::null_mut());
            ac_ctr_config_set_hostname(std::ptr::null_mut(), c"x".as_ptr());
            ac_ctr_config_set_cpu_percent(std::ptr::null_mut(), 50);
            ac_ctr_config_set_memory_max(std::ptr::null_mut(), 1024);
            ac_ctr_config_set_network(std::ptr::null_mut(), true);
            ac_ctr_config_set_readonly(std::ptr::null_mut(), true);
            ac_ctr_config_set_cpu_quota_us(std::ptr::null_mut(), 1000);
        }
    }

    #[test]
    fn test_null_safety_container() {
        unsafe {
            assert!(ac_ctr_container_create(std::ptr::null(), std::ptr::null_mut()).is_null());
            ac_ctr_container_free(std::ptr::null_mut());
            assert_eq!(ac_ctr_container_start(std::ptr::null_mut()), -1);
            assert_eq!(ac_ctr_container_stop(std::ptr::null_mut()), -1);
            assert_eq!(ac_ctr_container_pause(std::ptr::null_mut()), -1);
            assert_eq!(ac_ctr_container_resume(std::ptr::null_mut()), -1);
            assert_eq!(ac_ctr_container_destroy(std::ptr::null_mut()), -1);
            assert!(ac_ctr_container_id(std::ptr::null()).is_null());
            assert_eq!(ac_ctr_container_state(std::ptr::null()), 255);
            assert_eq!(ac_ctr_container_pid(std::ptr::null()), -1);
            assert_eq!(ac_ctr_container_memory_usage(std::ptr::null()), 0);
            assert_eq!(ac_ctr_container_cpu_usage(std::ptr::null()), 0);
        }
    }

    #[test]
    fn test_null_safety_exec() {
        unsafe {
            assert_eq!(
                ac_ctr_container_exec(std::ptr::null_mut(), std::ptr::null(), 0),
                -1
            );
        }
    }

    #[test]
    fn test_null_safety_cgroup() {
        unsafe {
            assert!(ac_ctr_cgroup_create(std::ptr::null()).is_null());
            assert!(ac_ctr_cgroup_open(std::ptr::null()).is_null());
            ac_ctr_cgroup_free(std::ptr::null_mut());
            assert_eq!(ac_ctr_cgroup_destroy(std::ptr::null_mut()), -1);
            assert_eq!(ac_ctr_cgroup_set_cpu_max(std::ptr::null_mut(), 0, 0), -1);
            assert_eq!(ac_ctr_cgroup_set_memory_max(std::ptr::null_mut(), 0), -1);
            assert_eq!(ac_ctr_cgroup_add_process(std::ptr::null_mut(), 0), -1);
            assert_eq!(ac_ctr_cgroup_freeze(std::ptr::null_mut()), -1);
            assert_eq!(ac_ctr_cgroup_unfreeze(std::ptr::null_mut()), -1);
            assert_eq!(ac_ctr_cgroup_kill_all(std::ptr::null_mut()), -1);
            assert_eq!(ac_ctr_cgroup_memory_current(std::ptr::null()), 0);
            assert_eq!(ac_ctr_cgroup_cpu_usage_us(std::ptr::null()), 0);
        }
    }

    #[test]
    fn test_null_safety_scheduler() {
        unsafe {
            assert!(ac_ctr_scheduler_new(std::ptr::null(), 0).is_null());
            ac_ctr_scheduler_free(std::ptr::null_mut());
            assert_eq!(ac_ctr_scheduler_start(std::ptr::null_mut()), -1);
            assert_eq!(ac_ctr_scheduler_stop(std::ptr::null_mut()), -1);
            assert_eq!(ac_ctr_scheduler_tick(std::ptr::null_mut()), 255);
            assert_eq!(ac_ctr_scheduler_burst(std::ptr::null_mut()), -1);
            assert_eq!(ac_ctr_scheduler_throttle(std::ptr::null_mut()), -1);
            assert_eq!(ac_ctr_scheduler_current_quota(std::ptr::null()), 0);
        }
    }

    #[test]
    fn test_quota_helpers() {
        assert_eq!(ac_ctr_quota_from_percent(50, 100_000), 50_000);
        assert_eq!(ac_ctr_quota_from_percent(100, 100_000), 100_000);
        assert_eq!(ac_ctr_percent_from_quota(50_000, 100_000), 50);
        assert_eq!(ac_ctr_percent_from_quota(100_000, 100_000), 100);
    }

    #[test]
    fn test_version() {
        let ptr = ac_ctr_version();
        assert!(!ptr.is_null());
        let v = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert!(v.starts_with("0."));
    }

    #[test]
    fn test_string_free_null() {
        unsafe {
            ac_ctr_string_free(std::ptr::null_mut());
        }
    }
}
