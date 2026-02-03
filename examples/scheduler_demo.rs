//! Dynamic CPU Scheduler Example
//!
//! Demonstrates dynamic CPU quota adjustment based on utilization.
//! Requires Linux with cgroup v2 and root privileges.
//!
//! ```bash
//! sudo cargo run --example scheduler_demo
//! ```

use alice_container::prelude::*;

fn main() {
    println!("=== ALICE-Container Dynamic Scheduler Demo ===\n");

    // Show scheduler configuration options
    println!("Available scheduler configs:\n");

    let configs = [
        ("Low Latency", SchedulerConfig::low_latency()),
        ("Default", SchedulerConfig::default()),
        ("Batch", SchedulerConfig::batch()),
    ];

    for (name, config) in &configs {
        println!("  {} Mode:", name);
        println!("    Target latency: {} us", config.target_latency_us);
        println!("    Min quota:      {}%", config.min_quota_percent);
        println!("    Max quota:      {}%", config.max_quota_percent);
        println!("    Period:         {} us", config.period_us);
        println!();
    }

    #[cfg(target_os = "linux")]
    {
        println!("--- Live Scheduler Demo ---\n");
        match CgroupController::create("alice-sched-demo") {
            Ok(cgroup) => {
                let config = SchedulerConfig::low_latency();
                let mut scheduler = DynamicScheduler::new(cgroup, config);

                match scheduler.start() {
                    Ok(_) => {
                        println!("Scheduler started.");
                        // Single tick demonstration
                        match scheduler.tick() {
                            Ok(decision) => println!("Tick result: {:?}", decision),
                            Err(e) => println!("Tick error: {:?}", e),
                        }
                    }
                    Err(e) => println!("Start error: {:?}", e),
                }
            }
            Err(e) => println!("Failed to create cgroup: {:?}", e),
        }
    }

    #[cfg(not(target_os = "linux"))]
    println!("Live scheduler demo requires Linux with cgroup v2 and root privileges.");
}
