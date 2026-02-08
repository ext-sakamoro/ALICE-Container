//! ALICE-Container × ALICE-Analytics Bridge
//!
//! Container resource usage metrics: unique containers (HLL),
//! CPU/memory utilization quantiles (DDSketch), scheduling anomalies (MAD).

use alice_analytics::prelude::*;

/// Container resource metrics collector.
pub struct ContainerMetrics {
    /// Unique container estimation.
    pub unique_containers: HyperLogLog,
    /// CPU usage quantiles (percent × 100).
    pub cpu_usage: DDSketch,
    /// Memory usage quantiles (bytes).
    pub memory_usage: DDSketch,
    /// Container start frequency.
    pub start_freq: CountMinSketch,
    /// CPU anomaly detection.
    pub cpu_anomaly: MadDetector,
    /// Total samples.
    pub total_samples: u64,
}

impl ContainerMetrics {
    /// Create a new container metrics collector.
    pub fn new() -> Self {
        Self {
            unique_containers: HyperLogLog::new(),
            cpu_usage: DDSketch::new(0.01),
            memory_usage: DDSketch::new(0.01),
            start_freq: CountMinSketch::new(),
            cpu_anomaly: MadDetector::new(3.0),
            total_samples: 0,
        }
    }

    /// Record container resource sample.
    pub fn record_sample(&mut self, container_id: &[u8], cpu_pct: f64, memory_bytes: f64) {
        self.unique_containers.insert_bytes(container_id);
        self.cpu_usage.insert(cpu_pct);
        self.memory_usage.insert(memory_bytes);
        self.cpu_anomaly.observe(cpu_pct);
        self.total_samples += 1;
    }

    /// Record a container start event.
    pub fn record_start(&mut self, container_id: &[u8]) {
        self.unique_containers.insert_bytes(container_id);
        self.start_freq.insert_bytes(container_id);
    }

    /// Estimated unique container count.
    pub fn unique_count(&self) -> f64 { self.unique_containers.cardinality() }
    /// P99 CPU usage.
    pub fn p99_cpu(&self) -> f64 { self.cpu_usage.quantile(0.99) }
    /// P50 CPU usage.
    pub fn p50_cpu(&self) -> f64 { self.cpu_usage.quantile(0.50) }
    /// P99 memory usage.
    pub fn p99_memory(&self) -> f64 { self.memory_usage.quantile(0.99) }
    /// Check if CPU usage is anomalous.
    pub fn is_cpu_anomaly(&mut self, cpu_pct: f64) -> bool { self.cpu_anomaly.is_anomaly(cpu_pct) }
}

impl Default for ContainerMetrics {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_metrics() {
        let mut m = ContainerMetrics::new();
        for i in 0..50 {
            let id = format!("container-{}", i % 5);
            m.record_sample(id.as_bytes(), 10.0 + i as f64, 1024.0 * 1024.0 * (50.0 + i as f64));
            m.record_start(id.as_bytes());
        }
        assert!(m.unique_count() >= 3.0);
        assert!(m.p50_cpu() > 0.0);
        assert!(m.p99_memory() > m.p50_cpu());
        assert_eq!(m.total_samples, 50);
    }
}
