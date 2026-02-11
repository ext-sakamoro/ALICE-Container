//! ALICE-Container × ALICE-DB bridge
//!
//! Container resource time-series persistence for observability.
//!
//! Author: Moroya Sakamoto

use alice_db::AliceDB;

/// Container resource usage record
#[derive(Debug, Clone, Copy)]
pub struct ContainerRecord {
    pub container_id: u64,
    pub timestamp_ms: u64,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub io_read_bytes: u64,
    pub io_write_bytes: u64,
}

impl ContainerRecord {
    /// Serialize to 40-byte binary for DB insertion
    pub fn to_bytes(&self) -> [u8; 40] {
        let mut buf = [0u8; 40];
        buf[0..8].copy_from_slice(&self.container_id.to_le_bytes());
        buf[8..16].copy_from_slice(&self.timestamp_ms.to_le_bytes());
        buf[16..20].copy_from_slice(&self.cpu_percent.to_le_bytes());
        buf[20..28].copy_from_slice(&self.memory_bytes.to_le_bytes());
        buf[28..36].copy_from_slice(&self.io_read_bytes.to_le_bytes());
        buf[36..40].copy_from_slice(&(self.io_write_bytes as u32).to_le_bytes());
        buf
    }

    /// Deserialize from 40-byte binary
    pub fn from_bytes(buf: &[u8; 40]) -> Self {
        Self {
            container_id: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            timestamp_ms: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            cpu_percent: f32::from_le_bytes(buf[16..20].try_into().unwrap()),
            memory_bytes: u64::from_le_bytes(buf[20..28].try_into().unwrap()),
            io_read_bytes: u64::from_le_bytes(buf[28..36].try_into().unwrap()),
            io_write_bytes: u32::from_le_bytes(buf[36..40].try_into().unwrap()) as u64,
        }
    }
}

/// Container metrics DB sink
pub struct ContainerDbSink {
    db: AliceDB,
    pub records_stored: u64,
}

impl ContainerDbSink {
    pub fn new(db: AliceDB) -> Self {
        Self { db, records_stored: 0 }
    }

    /// Store a single container resource record
    pub fn store_record(&mut self, record: &ContainerRecord) {
        let key = Self::make_key(record.container_id, record.timestamp_ms);
        let value = record.to_bytes();
        self.db.put(&key, &value);
        self.records_stored += 1;
    }

    /// Store a batch of records
    pub fn store_batch(&mut self, records: &[ContainerRecord]) {
        for record in records {
            self.store_record(record);
        }
    }

    /// Query records for a container in a time range
    pub fn query_container(&self, container_id: u64, from_ms: u64, to_ms: u64) -> Vec<ContainerRecord> {
        let start = Self::make_key(container_id, from_ms);
        let end = Self::make_key(container_id, to_ms);
        self.db
            .range(&start, &end)
            .filter_map(|(_k, v)| {
                if v.len() == 40 {
                    Some(ContainerRecord::from_bytes(v[..40].try_into().unwrap()))
                } else {
                    None
                }
            })
            .collect()
    }

    fn make_key(container_id: u64, timestamp_ms: u64) -> [u8; 16] {
        let mut key = [0u8; 16];
        key[0..8].copy_from_slice(&container_id.to_be_bytes());
        key[8..16].copy_from_slice(&timestamp_ms.to_be_bytes());
        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_serialization() {
        let record = ContainerRecord {
            container_id: 42,
            timestamp_ms: 1000,
            cpu_percent: 55.5,
            memory_bytes: 1024 * 1024,
            io_read_bytes: 4096,
            io_write_bytes: 2048,
        };
        let bytes = record.to_bytes();
        let restored = ContainerRecord::from_bytes(&bytes);
        assert_eq!(restored.container_id, 42);
        assert!((restored.cpu_percent - 55.5).abs() < 0.01);
        assert_eq!(restored.memory_bytes, 1024 * 1024);
    }
}
