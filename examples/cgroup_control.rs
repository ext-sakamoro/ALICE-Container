//! Direct Cgroup v2 Control Example
//!
//! Demonstrates cgroup creation, resource limits, and monitoring.
//! Requires Linux with cgroup v2 and root privileges.
//!
//! ```bash
//! sudo cargo run --example cgroup_control
//! ```

use alice_container::prelude::*;

fn main() {
    println!("=== ALICE-Container Cgroup Control Demo ===\n");

    #[cfg(target_os = "linux")]
    linux_demo();

    #[cfg(not(target_os = "linux"))]
    println!("This example requires Linux with cgroup v2.\n\
              Showing API overview instead:\n\n\
              // Create cgroup\n\
              let cgroup = CgroupController::create(\"my-container\")?;\n\n\
              // Set CPU limit: 50% of one CPU\n\
              cgroup.set_cpu_max(50_000, 100_000)?;\n\n\
              // Set memory limit: 256MB\n\
              cgroup.set_memory_max(256 * 1024 * 1024)?;\n\n\
              // Add process\n\
              cgroup.add_process(pid)?;\n\n\
              // Monitor\n\
              println!(\"Memory: {{}} bytes\", cgroup.memory_current()?);\n\
              println!(\"CPU: {{}} us\", cgroup.cpu_usage_us()?);\n\n\
              // Freeze / Unfreeze\n\
              cgroup.freeze()?;\n\
              cgroup.unfreeze()?;\n\n\
              // Cleanup\n\
              cgroup.destroy()?;");
}

#[cfg(target_os = "linux")]
fn linux_demo() {
    match CgroupController::create("alice-example") {
        Ok(cgroup) => {
            println!("Created cgroup: alice-example");

            if let Err(e) = cgroup.set_cpu_max(50_000, 100_000) {
                println!("Set CPU max: {:?}", e);
            } else {
                println!("CPU limit: 50% (50ms/100ms)");
            }

            if let Err(e) = cgroup.set_memory_max(256 * 1024 * 1024) {
                println!("Set memory max: {:?}", e);
            } else {
                println!("Memory limit: 256MB");
            }

            match cgroup.memory_current() {
                Ok(mem) => println!("Current memory: {} bytes", mem),
                Err(e) => println!("Read memory: {:?}", e),
            }

            match cgroup.cpu_usage_us() {
                Ok(cpu) => println!("CPU usage: {} us", cpu),
                Err(e) => println!("Read CPU: {:?}", e),
            }

            if let Err(e) = cgroup.destroy() {
                println!("Cleanup: {:?}", e);
            } else {
                println!("\nCgroup destroyed successfully.");
            }
        }
        Err(e) => {
            println!("Failed to create cgroup (need root?): {:?}", e);
        }
    }
}
