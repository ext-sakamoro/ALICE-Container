//! ALICE-Container × ALICE-Sync bridge
//!
//! Lockstep container state synchronization for distributed orchestration.
//!
//! Author: Moroya Sakamoto

/// Container lifecycle status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContainerStatus {
    Created = 0,
    Running = 1,
    Paused = 2,
    Stopped = 3,
    Failed = 4,
}

/// Container deployment state (synchronized across edge nodes)
#[derive(Debug, Clone)]
pub struct ContainerState {
    pub container_id: u64,
    pub image_hash: [u8; 32],
    pub status: ContainerStatus,
    pub cpu_limit_us: u64,
    pub memory_limit: u64,
}

/// Compact 18-byte event for ALICE-Sync event diffing
///
/// Layout: [container_id: 8B][status: 1B][cpu_limit_hi: 4B][mem_limit_hi: 4B][checksum: 1B]
#[derive(Debug, Clone, Copy)]
pub struct ContainerSyncEvent {
    pub data: [u8; 18],
}

/// Encode container state into an 18-byte sync event
pub fn encode_container_event(state: &ContainerState) -> ContainerSyncEvent {
    let mut data = [0u8; 18];
    data[0..8].copy_from_slice(&state.container_id.to_le_bytes());
    data[8] = state.status as u8;
    // Store upper 32 bits of limits (sufficient for orchestration)
    data[9..13].copy_from_slice(&(state.cpu_limit_us as u32).to_le_bytes());
    data[13..17].copy_from_slice(&((state.memory_limit >> 20) as u32).to_le_bytes()); // MB granularity
    // Simple checksum
    let mut cksum: u8 = 0;
    for &b in &data[0..17] {
        cksum = cksum.wrapping_add(b);
    }
    data[17] = cksum;
    ContainerSyncEvent { data }
}

/// Decode an 18-byte sync event back to container state
pub fn decode_container_event(event: &ContainerSyncEvent) -> Result<ContainerState, &'static str> {
    let data = &event.data;
    // Verify checksum
    let mut cksum: u8 = 0;
    for &b in &data[0..17] {
        cksum = cksum.wrapping_add(b);
    }
    if cksum != data[17] {
        return Err("Checksum mismatch");
    }

    let container_id = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let status = match data[8] {
        0 => ContainerStatus::Created,
        1 => ContainerStatus::Running,
        2 => ContainerStatus::Paused,
        3 => ContainerStatus::Stopped,
        4 => ContainerStatus::Failed,
        _ => return Err("Invalid status"),
    };
    let cpu_limit_us = u32::from_le_bytes(data[9..13].try_into().unwrap()) as u64;
    let memory_limit = (u32::from_le_bytes(data[13..17].try_into().unwrap()) as u64) << 20;

    Ok(ContainerState {
        container_id,
        image_hash: [0u8; 32], // Not stored in compact event
        status,
        cpu_limit_us,
        memory_limit,
    })
}

/// Deterministic world hash for desync detection across nodes
pub fn container_world_hash(states: &[ContainerState]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325; // FNV-1a offset basis
    for state in states {
        hash ^= state.container_id;
        hash = hash.wrapping_mul(0x100000001b3);
        hash ^= state.status as u64;
        hash = hash.wrapping_mul(0x100000001b3);
        hash ^= state.cpu_limit_us;
        hash = hash.wrapping_mul(0x100000001b3);
        hash ^= state.memory_limit;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> ContainerState {
        ContainerState {
            container_id: 1,
            image_hash: [0xAB; 32],
            status: ContainerStatus::Running,
            cpu_limit_us: 100_000,
            memory_limit: 256 * 1024 * 1024, // 256 MB
        }
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let state = test_state();
        let event = encode_container_event(&state);
        let decoded = decode_container_event(&event).unwrap();
        assert_eq!(decoded.container_id, 1);
        assert_eq!(decoded.status, ContainerStatus::Running);
    }

    #[test]
    fn test_checksum_tamper() {
        let state = test_state();
        let mut event = encode_container_event(&state);
        event.data[0] ^= 0xFF; // Tamper
        assert!(decode_container_event(&event).is_err());
    }

    #[test]
    fn test_world_hash_deterministic() {
        let states = vec![test_state(), test_state()];
        let h1 = container_world_hash(&states);
        let h2 = container_world_hash(&states);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_world_hash_changes() {
        let s1 = vec![test_state()];
        let mut s2_state = test_state();
        s2_state.status = ContainerStatus::Stopped;
        let s2 = vec![s2_state];
        assert_ne!(container_world_hash(&s1), container_world_hash(&s2));
    }
}
