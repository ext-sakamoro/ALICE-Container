// ALICE-Container Unity C# Bindings
// 45 DllImport + 5 RAII handles
//
// Usage:
//   using var config = AliceContainer.ConfigNew();
//   AliceContainer.ConfigSetCpuPercent(config, 50);
//   AliceContainer.ConfigSetMemoryMax(config, 256 * 1024 * 1024);
//   using var container = AliceContainer.ContainerCreate("test", config);
//   // config is consumed — do not use after ContainerCreate

using System;
using System.Runtime.InteropServices;

namespace Alice.Container
{
    // ========================================================================
    // RAII Handles
    // ========================================================================

    /// Opaque handle to ContainerConfig. Consumed by ContainerCreate.
    public sealed class ConfigHandle : SafeHandle
    {
        public ConfigHandle() : base(IntPtr.Zero, true) { }
        public override bool IsInvalid => handle == IntPtr.Zero;
        protected override bool ReleaseHandle()
        {
            AliceContainer.ac_ctr_config_free(handle);
            return true;
        }
        /// Mark as consumed (ContainerCreate takes ownership).
        internal void Consume() => SetHandleAsInvalid();
    }

    /// Opaque handle to Container.
    public sealed class ContainerHandle : SafeHandle
    {
        public ContainerHandle() : base(IntPtr.Zero, true) { }
        public override bool IsInvalid => handle == IntPtr.Zero;
        protected override bool ReleaseHandle()
        {
            AliceContainer.ac_ctr_container_free(handle);
            return true;
        }
    }

    /// Opaque handle to CgroupController.
    public sealed class CgroupHandle : SafeHandle
    {
        public CgroupHandle() : base(IntPtr.Zero, true) { }
        public override bool IsInvalid => handle == IntPtr.Zero;
        protected override bool ReleaseHandle()
        {
            AliceContainer.ac_ctr_cgroup_free(handle);
            return true;
        }
    }

    /// Opaque handle to DynamicScheduler.
    public sealed class SchedulerHandle : SafeHandle
    {
        public SchedulerHandle() : base(IntPtr.Zero, true) { }
        public override bool IsInvalid => handle == IntPtr.Zero;
        protected override bool ReleaseHandle()
        {
            AliceContainer.ac_ctr_scheduler_free(handle);
            return true;
        }
    }

    /// Owned string from the library.
    public sealed class StringHandle : SafeHandle
    {
        public StringHandle() : base(IntPtr.Zero, true) { }
        public override bool IsInvalid => handle == IntPtr.Zero;
        protected override bool ReleaseHandle()
        {
            AliceContainer.ac_ctr_string_free(handle);
            return true;
        }
        public override string ToString() =>
            IsInvalid ? null : Marshal.PtrToStringAnsi(handle);
    }

    // ========================================================================
    // Container State
    // ========================================================================

    public enum ContainerState : byte
    {
        Created  = 0,
        Running  = 1,
        Paused   = 2,
        Stopped  = 3,
        Invalid  = 255,
    }

    // ========================================================================
    // Scheduler Decision
    // ========================================================================

    public enum SchedulerDecision : byte
    {
        Idle     = 0,
        TooSoon  = 1,
        Maintain = 2,
        Adjust   = 3,
        Error    = 255,
    }

    // ========================================================================
    // Native Bindings (45 functions)
    // ========================================================================

    public static class AliceContainer
    {
        private const string Lib = "alice_container";

        // --- Memory Management (1) ---

        [DllImport(Lib)] public static extern void ac_ctr_string_free(IntPtr ptr);

        // --- ContainerConfig (8) ---

        [DllImport(Lib)] public static extern ConfigHandle ac_ctr_config_new();
        [DllImport(Lib)] public static extern void ac_ctr_config_free(IntPtr ptr);
        [DllImport(Lib)] public static extern void ac_ctr_config_set_hostname(ConfigHandle ptr, [MarshalAs(UnmanagedType.LPUTF8Str)] string hostname);
        [DllImport(Lib)] public static extern void ac_ctr_config_set_cpu_percent(ConfigHandle ptr, uint percent);
        [DllImport(Lib)] public static extern void ac_ctr_config_set_cpu_quota_us(ConfigHandle ptr, ulong quotaUs);
        [DllImport(Lib)] public static extern void ac_ctr_config_set_memory_max(ConfigHandle ptr, ulong bytes);
        [DllImport(Lib)] public static extern void ac_ctr_config_set_network(ConfigHandle ptr, [MarshalAs(UnmanagedType.U1)] bool enable);
        [DllImport(Lib)] public static extern void ac_ctr_config_set_readonly(ConfigHandle ptr, [MarshalAs(UnmanagedType.U1)] bool readOnly);

        // --- Container Lifecycle (13) ---

        [DllImport(Lib)] public static extern ContainerHandle ac_ctr_container_create([MarshalAs(UnmanagedType.LPUTF8Str)] string id, IntPtr config);
        [DllImport(Lib)] public static extern void ac_ctr_container_free(IntPtr ptr);
        [DllImport(Lib)] public static extern int ac_ctr_container_start(ContainerHandle ptr);
        [DllImport(Lib)] public static extern int ac_ctr_container_stop(ContainerHandle ptr);
        [DllImport(Lib)] public static extern int ac_ctr_container_pause(ContainerHandle ptr);
        [DllImport(Lib)] public static extern int ac_ctr_container_resume(ContainerHandle ptr);
        [DllImport(Lib)] public static extern int ac_ctr_container_exec(ContainerHandle ptr, IntPtr argv, int argc);
        [DllImport(Lib)] public static extern int ac_ctr_container_destroy(IntPtr ptr);
        [DllImport(Lib)] public static extern StringHandle ac_ctr_container_id(ContainerHandle ptr);
        [DllImport(Lib)] public static extern ContainerState ac_ctr_container_state(ContainerHandle ptr);
        [DllImport(Lib)] public static extern long ac_ctr_container_pid(ContainerHandle ptr);
        [DllImport(Lib)] public static extern ulong ac_ctr_container_memory_usage(ContainerHandle ptr);
        [DllImport(Lib)] public static extern ulong ac_ctr_container_cpu_usage(ContainerHandle ptr);

        // --- CgroupController (12) ---

        [DllImport(Lib)] public static extern CgroupHandle ac_ctr_cgroup_create([MarshalAs(UnmanagedType.LPUTF8Str)] string name);
        [DllImport(Lib)] public static extern CgroupHandle ac_ctr_cgroup_open([MarshalAs(UnmanagedType.LPUTF8Str)] string name);
        [DllImport(Lib)] public static extern void ac_ctr_cgroup_free(IntPtr ptr);
        [DllImport(Lib)] public static extern int ac_ctr_cgroup_destroy(IntPtr ptr);
        [DllImport(Lib)] public static extern int ac_ctr_cgroup_set_cpu_max(CgroupHandle ptr, ulong quotaUs, ulong periodUs);
        [DllImport(Lib)] public static extern int ac_ctr_cgroup_set_memory_max(CgroupHandle ptr, ulong bytes);
        [DllImport(Lib)] public static extern int ac_ctr_cgroup_add_process(CgroupHandle ptr, uint pid);
        [DllImport(Lib)] public static extern int ac_ctr_cgroup_freeze(CgroupHandle ptr);
        [DllImport(Lib)] public static extern int ac_ctr_cgroup_unfreeze(CgroupHandle ptr);
        [DllImport(Lib)] public static extern int ac_ctr_cgroup_kill_all(CgroupHandle ptr);
        [DllImport(Lib)] public static extern ulong ac_ctr_cgroup_memory_current(CgroupHandle ptr);
        [DllImport(Lib)] public static extern ulong ac_ctr_cgroup_cpu_usage_us(CgroupHandle ptr);

        // --- DynamicScheduler (8) ---

        [DllImport(Lib)] public static extern SchedulerHandle ac_ctr_scheduler_new([MarshalAs(UnmanagedType.LPUTF8Str)] string cgroupName, byte mode);
        [DllImport(Lib)] public static extern void ac_ctr_scheduler_free(IntPtr ptr);
        [DllImport(Lib)] public static extern int ac_ctr_scheduler_start(SchedulerHandle ptr);
        [DllImport(Lib)] public static extern int ac_ctr_scheduler_stop(SchedulerHandle ptr);
        [DllImport(Lib)] public static extern SchedulerDecision ac_ctr_scheduler_tick(SchedulerHandle ptr);
        [DllImport(Lib)] public static extern int ac_ctr_scheduler_burst(SchedulerHandle ptr);
        [DllImport(Lib)] public static extern int ac_ctr_scheduler_throttle(SchedulerHandle ptr);
        [DllImport(Lib)] public static extern ulong ac_ctr_scheduler_current_quota(SchedulerHandle ptr);

        // --- Utility (3) ---

        [DllImport(Lib)] public static extern ulong ac_ctr_quota_from_percent(uint cpuPercent, ulong periodUs);
        [DllImport(Lib)] public static extern uint ac_ctr_percent_from_quota(ulong quotaUs, ulong periodUs);
        [DllImport(Lib)] public static extern IntPtr ac_ctr_version();

        // --- Helpers ---

        /// Create a container (takes ownership of config).
        public static ContainerHandle CreateContainer(string id, ConfigHandle config)
        {
            var raw = config.DangerousGetHandle();
            config.Consume();
            return ac_ctr_container_create(id, raw);
        }

        /// Destroy a container (stops + removes cgroup). Invalidates the handle.
        public static int DestroyContainer(ContainerHandle container)
        {
            var raw = container.DangerousGetHandle();
            container.SetHandleAsInvalid();
            return ac_ctr_container_destroy(raw);
        }

        /// Destroy a cgroup. Invalidates the handle.
        public static int DestroyCgroup(CgroupHandle cgroup)
        {
            var raw = cgroup.DangerousGetHandle();
            cgroup.SetHandleAsInvalid();
            return ac_ctr_cgroup_destroy(raw);
        }

        /// Get library version string.
        public static string Version()
        {
            var ptr = ac_ctr_version();
            return Marshal.PtrToStringAnsi(ptr);
        }
    }
}
