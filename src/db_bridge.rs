//! ALICE-Container × ALICE-DB bridge
//!
//! Container resource time-series persistence for observability.
//!
//! Author: Moroya Sakamoto

use alice_db::AliceDB;

/// Error type for DB bridge operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbBridgeError {
    /// Record buffer has incorrect length (expected 40 bytes)
    InvalidBufferLength { expected: usize, got: usize },
}

impl core::fmt::Display for DbBridgeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DbBridgeError::InvalidBufferLength { expected, got } => {
                write!(
                    f,
                    "invalid buffer length: expected {} bytes, got {}",
                    expected, got
                )
            }
        }
    }
}

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

    /// Deserialize from 40-byte binary.
    ///
    /// Returns `Err` if `buf` does not have exactly 40 bytes.
    pub fn from_bytes(buf: &[u8; 40]) -> Result<Self, DbBridgeError> {
        // Each sub-slice length is a compile-time constant that exactly matches the target
        // integer type, so try_into() on these fixed-size ranges is infallible. We use
        // expect() with an explicit message to document the invariant, but the slice
        // bounds on a [u8; 40] are guaranteed by the type system.
        Ok(Self {
            container_id: u64::from_le_bytes(
                buf[0..8].try_into().expect("slice is exactly 8 bytes"),
            ),
            timestamp_ms: u64::from_le_bytes(
                buf[8..16].try_into().expect("slice is exactly 8 bytes"),
            ),
            cpu_percent: f32::from_le_bytes(
                buf[16..20].try_into().expect("slice is exactly 4 bytes"),
            ),
            memory_bytes: u64::from_le_bytes(
                buf[20..28].try_into().expect("slice is exactly 8 bytes"),
            ),
            io_read_bytes: u64::from_le_bytes(
                buf[28..36].try_into().expect("slice is exactly 8 bytes"),
            ),
            io_write_bytes: u32::from_le_bytes(
                buf[36..40].try_into().expect("slice is exactly 4 bytes"),
            ) as u64,
        })
    }

    /// Deserialize from a variable-length byte slice.
    ///
    /// Returns `Err(DbBridgeError::InvalidBufferLength)` if `buf` is not exactly 40 bytes.
    pub fn try_from_slice(buf: &[u8]) -> Result<Self, DbBridgeError> {
        let arr: &[u8; 40] = buf
            .try_into()
            .map_err(|_| DbBridgeError::InvalidBufferLength {
                expected: 40,
                got: buf.len(),
            })?;
        Self::from_bytes(arr)
    }
}

/// Container metrics DB sink
pub struct ContainerDbSink {
    db: AliceDB,
    pub records_stored: u64,
}

impl ContainerDbSink {
    pub fn new(db: AliceDB) -> Self {
        Self {
            db,
            records_stored: 0,
        }
    }

    /// Store a single container resource record.
    ///
    /// Returns `Err` if the underlying DB write fails.
    pub fn store_record(&mut self, record: &ContainerRecord) -> Result<(), DbBridgeError> {
        let key = Self::make_key(record.container_id, record.timestamp_ms);
        let value = record.to_bytes();
        self.db.put(&key, &value);
        self.records_stored += 1;
        Ok(())
    }

    /// Store a batch of records.
    ///
    /// Stops and returns the first error encountered.
    pub fn store_batch(&mut self, records: &[ContainerRecord]) -> Result<(), DbBridgeError> {
        for record in records {
            self.store_record(record)?;
        }
        Ok(())
    }

    /// Query records for a container in a time range.
    ///
    /// Silently skips any DB entries that do not deserialize correctly (e.g., corrupt data).
    pub fn query_container(
        &self,
        container_id: u64,
        from_ms: u64,
        to_ms: u64,
    ) -> Vec<ContainerRecord> {
        let start = Self::make_key(container_id, from_ms);
        let end = Self::make_key(container_id, to_ms);
        self.db
            .range(&start, &end)
            .filter_map(|(_k, v)| ContainerRecord::try_from_slice(v).ok())
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
        let restored = ContainerRecord::from_bytes(&bytes).expect("deserialization must succeed");
        assert_eq!(restored.container_id, 42);
        assert!((restored.cpu_percent - 55.5).abs() < 0.01);
        assert_eq!(restored.memory_bytes, 1024 * 1024);
    }

    #[test]
    fn test_try_from_slice_invalid_length() {
        let short = [0u8; 20];
        assert!(ContainerRecord::try_from_slice(&short).is_err());

        let long = [0u8; 50];
        assert!(ContainerRecord::try_from_slice(&long).is_err());
    }

    #[test]
    fn test_try_from_slice_exact_length() {
        let record = ContainerRecord {
            container_id: 1,
            timestamp_ms: 500,
            cpu_percent: 25.0,
            memory_bytes: 512,
            io_read_bytes: 128,
            io_write_bytes: 64,
        };
        let bytes = record.to_bytes();
        let restored =
            ContainerRecord::try_from_slice(&bytes).expect("exact 40 bytes must succeed");
        assert_eq!(restored.container_id, 1);
    }
}
