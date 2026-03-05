// ALICE-Container UE5 C++ Bindings
// 45 extern "C" + 5 RAII types
//
// Usage:
//   auto config = alice::ConfigPtr::Create();
//   ac_ctr_config_set_cpu_percent(config.get(), 50);
//   ac_ctr_config_set_memory_max(config.get(), 256 * 1024 * 1024);
//   auto container = alice::ContainerPtr::Create("test", config.release());
//   ac_ctr_container_start(container.get());

#pragma once

#include <cstdint>
#include <cstring>
#include <memory>

// ============================================================================
// Opaque Types
// ============================================================================

struct AliceContainerConfig;
struct AliceContainer;
struct AliceCgroupController;
struct AliceDynamicScheduler;

// ============================================================================
// Container State
// ============================================================================

enum class AliceContainerState : uint8_t
{
    Created  = 0,
    Running  = 1,
    Paused   = 2,
    Stopped  = 3,
    Invalid  = 255,
};

// ============================================================================
// Scheduler Decision
// ============================================================================

enum class AliceSchedulerDecision : uint8_t
{
    Idle     = 0,
    TooSoon  = 1,
    Maintain = 2,
    Adjust   = 3,
    Error    = 255,
};

// ============================================================================
// C-ABI (45 functions)
// ============================================================================

extern "C"
{
    // --- Memory Management (1) ---
    void     ac_ctr_string_free(char* ptr);

    // --- ContainerConfig (8) ---
    AliceContainerConfig* ac_ctr_config_new();
    void     ac_ctr_config_free(AliceContainerConfig* ptr);
    void     ac_ctr_config_set_hostname(AliceContainerConfig* ptr, const char* hostname);
    void     ac_ctr_config_set_cpu_percent(AliceContainerConfig* ptr, uint32_t percent);
    void     ac_ctr_config_set_cpu_quota_us(AliceContainerConfig* ptr, uint64_t quota_us);
    void     ac_ctr_config_set_memory_max(AliceContainerConfig* ptr, uint64_t bytes);
    void     ac_ctr_config_set_network(AliceContainerConfig* ptr, bool enable);
    void     ac_ctr_config_set_readonly(AliceContainerConfig* ptr, bool readonly);

    // --- Container Lifecycle (13) ---
    AliceContainer* ac_ctr_container_create(const char* id, AliceContainerConfig* config);
    void     ac_ctr_container_free(AliceContainer* ptr);
    int32_t  ac_ctr_container_start(AliceContainer* ptr);
    int32_t  ac_ctr_container_stop(AliceContainer* ptr);
    int32_t  ac_ctr_container_pause(AliceContainer* ptr);
    int32_t  ac_ctr_container_resume(AliceContainer* ptr);
    int32_t  ac_ctr_container_exec(AliceContainer* ptr, const char** argv, int32_t argc);
    int32_t  ac_ctr_container_destroy(AliceContainer* ptr);
    char*    ac_ctr_container_id(const AliceContainer* ptr);
    uint8_t  ac_ctr_container_state(const AliceContainer* ptr);
    int64_t  ac_ctr_container_pid(const AliceContainer* ptr);
    uint64_t ac_ctr_container_memory_usage(const AliceContainer* ptr);
    uint64_t ac_ctr_container_cpu_usage(const AliceContainer* ptr);

    // --- CgroupController (12) ---
    AliceCgroupController* ac_ctr_cgroup_create(const char* name);
    AliceCgroupController* ac_ctr_cgroup_open(const char* name);
    void     ac_ctr_cgroup_free(AliceCgroupController* ptr);
    int32_t  ac_ctr_cgroup_destroy(AliceCgroupController* ptr);
    int32_t  ac_ctr_cgroup_set_cpu_max(AliceCgroupController* ptr, uint64_t quota_us, uint64_t period_us);
    int32_t  ac_ctr_cgroup_set_memory_max(AliceCgroupController* ptr, uint64_t bytes);
    int32_t  ac_ctr_cgroup_add_process(AliceCgroupController* ptr, uint32_t pid);
    int32_t  ac_ctr_cgroup_freeze(AliceCgroupController* ptr);
    int32_t  ac_ctr_cgroup_unfreeze(AliceCgroupController* ptr);
    int32_t  ac_ctr_cgroup_kill_all(AliceCgroupController* ptr);
    uint64_t ac_ctr_cgroup_memory_current(const AliceCgroupController* ptr);
    uint64_t ac_ctr_cgroup_cpu_usage_us(const AliceCgroupController* ptr);

    // --- DynamicScheduler (8) ---
    AliceDynamicScheduler* ac_ctr_scheduler_new(const char* cgroup_name, uint8_t mode);
    void     ac_ctr_scheduler_free(AliceDynamicScheduler* ptr);
    int32_t  ac_ctr_scheduler_start(AliceDynamicScheduler* ptr);
    int32_t  ac_ctr_scheduler_stop(AliceDynamicScheduler* ptr);
    uint8_t  ac_ctr_scheduler_tick(AliceDynamicScheduler* ptr);
    int32_t  ac_ctr_scheduler_burst(AliceDynamicScheduler* ptr);
    int32_t  ac_ctr_scheduler_throttle(AliceDynamicScheduler* ptr);
    uint64_t ac_ctr_scheduler_current_quota(const AliceDynamicScheduler* ptr);

    // --- Utility (3) ---
    uint64_t    ac_ctr_quota_from_percent(uint32_t cpu_percent, uint64_t period_us);
    uint32_t    ac_ctr_percent_from_quota(uint64_t quota_us, uint64_t period_us);
    const char* ac_ctr_version();
}

// ============================================================================
// RAII Wrappers (C++)
// ============================================================================

namespace alice
{

// --- String ---
struct StringDeleter
{
    void operator()(char* p) const noexcept { if (p) ac_ctr_string_free(p); }
};
using StringPtr = std::unique_ptr<char, StringDeleter>;

// --- Config ---
struct ConfigDeleter
{
    void operator()(AliceContainerConfig* p) const noexcept { if (p) ac_ctr_config_free(p); }
};
struct ConfigPtr : std::unique_ptr<AliceContainerConfig, ConfigDeleter>
{
    using Base = std::unique_ptr<AliceContainerConfig, ConfigDeleter>;
    using Base::Base;

    static ConfigPtr Create()
    {
        return ConfigPtr(ac_ctr_config_new());
    }
};

// --- Container ---
struct ContainerDeleter
{
    void operator()(AliceContainer* p) const noexcept { if (p) ac_ctr_container_free(p); }
};
struct ContainerPtr : std::unique_ptr<AliceContainer, ContainerDeleter>
{
    using Base = std::unique_ptr<AliceContainer, ContainerDeleter>;
    using Base::Base;

    /// Create a container. Takes ownership of config (raw pointer).
    static ContainerPtr Create(const char* id, AliceContainerConfig* config)
    {
        return ContainerPtr(ac_ctr_container_create(id, config));
    }

    /// Destroy the container (stop + remove cgroup). Releases the pointer.
    int32_t Destroy()
    {
        return ac_ctr_container_destroy(release());
    }

    AliceContainerState State() const
    {
        return static_cast<AliceContainerState>(ac_ctr_container_state(get()));
    }

    StringPtr Id() const
    {
        return StringPtr(ac_ctr_container_id(get()));
    }
};

// --- Cgroup ---
struct CgroupDeleter
{
    void operator()(AliceCgroupController* p) const noexcept { if (p) ac_ctr_cgroup_free(p); }
};
struct CgroupPtr : std::unique_ptr<AliceCgroupController, CgroupDeleter>
{
    using Base = std::unique_ptr<AliceCgroupController, CgroupDeleter>;
    using Base::Base;

    static CgroupPtr Create(const char* name)
    {
        return CgroupPtr(ac_ctr_cgroup_create(name));
    }

    static CgroupPtr Open(const char* name)
    {
        return CgroupPtr(ac_ctr_cgroup_open(name));
    }

    /// Destroy the cgroup. Releases the pointer.
    int32_t Destroy()
    {
        return ac_ctr_cgroup_destroy(release());
    }
};

// --- Scheduler ---
struct SchedulerDeleter
{
    void operator()(AliceDynamicScheduler* p) const noexcept { if (p) ac_ctr_scheduler_free(p); }
};
struct SchedulerPtr : std::unique_ptr<AliceDynamicScheduler, SchedulerDeleter>
{
    using Base = std::unique_ptr<AliceDynamicScheduler, SchedulerDeleter>;
    using Base::Base;

    /// mode: 0=Default, 1=LowLatency, 2=Batch
    static SchedulerPtr Create(const char* cgroup_name, uint8_t mode = 0)
    {
        return SchedulerPtr(ac_ctr_scheduler_new(cgroup_name, mode));
    }

    AliceSchedulerDecision Tick()
    {
        return static_cast<AliceSchedulerDecision>(ac_ctr_scheduler_tick(get()));
    }
};

// --- Helpers ---

inline const char* Version() { return ac_ctr_version(); }

} // namespace alice
