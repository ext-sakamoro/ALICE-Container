use criterion::{black_box, criterion_group, criterion_main, Criterion};
use alice_container::prelude::*;

fn bench_container_config_build(c: &mut Criterion) {
    c.bench_function("container_config_build", |b| {
        b.iter(|| {
            ContainerConfig::builder()
                .cpu_quota_us(black_box(50_000))
                .memory_max(black_box(256 * 1024 * 1024))
                .build()
        })
    });
}

fn bench_scheduler_config(c: &mut Criterion) {
    c.bench_function("scheduler_config_low_latency", |b| {
        b.iter(|| black_box(SchedulerConfig::low_latency()))
    });

    c.bench_function("scheduler_config_batch", |b| {
        b.iter(|| black_box(SchedulerConfig::batch()))
    });
}

fn bench_namespace_flags(c: &mut Criterion) {
    c.bench_function("namespace_flags_container", |b| {
        b.iter(|| {
            let flags = NamespaceFlags::NEWNS
                | NamespaceFlags::NEWPID
                | NamespaceFlags::NEWUTS
                | NamespaceFlags::NEWIPC;
            black_box(flags)
        })
    });
}

#[cfg(target_os = "linux")]
fn bench_cgroup_create_destroy(c: &mut Criterion) {
    c.bench_function("cgroup_create_destroy", |b| {
        let mut i = 0u64;
        b.iter(|| {
            i += 1;
            let name = format!("bench-{}", i);
            if let Ok(cg) = CgroupController::create(&name) {
                let _ = cg.destroy();
            }
        })
    });
}

#[cfg(target_os = "linux")]
fn bench_cgroup_write_cpu(c: &mut Criterion) {
    if let Ok(cg) = CgroupController::create("bench-cpu-write") {
        c.bench_function("cgroup_set_cpu_max", |b| {
            b.iter(|| {
                let _ = cg.set_cpu_max(black_box(50_000), black_box(100_000));
            })
        });
        let _ = cg.destroy();
    }
}

#[cfg(not(target_os = "linux"))]
fn bench_cgroup_create_destroy(_c: &mut Criterion) {}

#[cfg(not(target_os = "linux"))]
fn bench_cgroup_write_cpu(_c: &mut Criterion) {}

criterion_group!(
    benches,
    bench_container_config_build,
    bench_scheduler_config,
    bench_namespace_flags,
    bench_cgroup_create_destroy,
    bench_cgroup_write_cpu,
);
criterion_main!(benches);
