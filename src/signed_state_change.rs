//! `signed_state_change` — tamper-evident container lifecycle audit trail.
//!
//! Container runtimes are a prime attack surface for privileged escalation
//! and post-compromise persistence. Every state-changing event (create,
//! start, exec, stop, delete, image-pull, cgroup-update, seccomp-update,
//! namespace-attach) is captured in an `Ed25519`-signed record chained
//! via `prev_hash → hash` so incident responders can prove what actually
//! ran on a host.
//!
//! # Regulatory alignment
//!
//! - **`SOX` §404** — infrastructure changes to systems that touch
//!   financial reporting require traceable authorization records.
//! - **`HIPAA Security Rule` §164.308(a)(1)(ii)(D)** — information
//!   system activity review; container spawn / exec is a required
//!   monitoring point.
//! - **`FedRAMP` `AU-2`, `AU-3`, `CM-6`** — audit events, content of
//!   audit records, configuration settings.
//! - **`PCI-DSS` v4.0 §10.2, §10.6** — audit log requirements for
//!   privileged access and daily review.
//! - **`SOC2 CC6.6`, `CC7.2`** — logical access boundaries and
//!   detection of anomalies.
//! - **`NIST SP 800-190`** — application container security guide,
//!   `§4.1` runtime monitoring recommendations.
//!
//! Cryptographic primitives are provided by `alice-blockchain` (`Ed25519`).

#![allow(
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::too_many_arguments,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation
)]

use alice_blockchain::signature::{KeyPair, PublicKey, Signature};

// ---------------------------------------------------------------------------
// ContainerEventKind
// ---------------------------------------------------------------------------

/// The container lifecycle event captured in the trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContainerEventKind {
    /// A container was created (namespace + cgroup allocated, not yet
    /// running).
    Created,
    /// The container process was started.
    Started,
    /// A new command was executed inside a running container.
    Exec,
    /// The container process stopped.
    Stopped,
    /// The container was deleted (resources released).
    Deleted,
    /// A container image was pulled.
    ImagePulled,
    /// A cgroup limit / weight was updated.
    CgroupUpdated,
    /// A seccomp profile was loaded or updated.
    SeccompUpdated,
    /// A namespace was attached or detached.
    NamespaceAttach,
}

impl ContainerEventKind {
    /// Short code used in canonical serialization.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Created => "CREATE",
            Self::Started => "START",
            Self::Exec => "EXEC",
            Self::Stopped => "STOP",
            Self::Deleted => "DEL",
            Self::ImagePulled => "PULL",
            Self::CgroupUpdated => "CG",
            Self::SeccompUpdated => "SECCP",
            Self::NamespaceAttach => "NSATT",
        }
    }
}

// ---------------------------------------------------------------------------
// StateChangeRecord
// ---------------------------------------------------------------------------

/// One container lifecycle event ready to be signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateChangeRecord {
    /// Monotonic sequence number.
    pub seq: u64,
    /// Kind of event.
    pub kind: ContainerEventKind,
    /// Unix nanosecond timestamp.
    pub timestamp_ns: u64,
    /// Container identifier (`c-1234`, `web-nginx`).
    pub container_id: String,
    /// Container image identifier (SHA-256 hex, `nginx:1.25`).
    pub image: String,
    /// Host node identifier (`node-01.example.com`).
    pub host: String,
    /// Actor user id (`k8s:sa/default:app`, `root`, `admin@corp`).
    pub actor_id: String,
    /// Free-form command or configuration payload (exec argv, cgroup
    /// change spec, image digest).
    pub payload: String,
    /// Outcome tag (`success`, `failure`, `partial`).
    pub outcome: String,
    /// Hash of the previous record (0 for genesis).
    pub prev_hash: u64,
}

impl StateChangeRecord {
    /// Canonical byte layout used for hashing and signing.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(224);
        buf.extend_from_slice(&self.seq.to_le_bytes());
        buf.extend_from_slice(self.kind.code().as_bytes());
        buf.push(0);
        buf.extend_from_slice(&self.timestamp_ns.to_le_bytes());
        buf.extend_from_slice(self.container_id.as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.image.as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.host.as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.actor_id.as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.payload.as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.outcome.as_bytes());
        buf.push(0);
        buf.extend_from_slice(&self.prev_hash.to_le_bytes());
        buf
    }

    /// `FNV-1a` hash of the canonical byte layout.
    #[must_use]
    pub fn hash(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in &self.canonical_bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    }
}

// ---------------------------------------------------------------------------
// SignedStateChange
// ---------------------------------------------------------------------------

/// [`StateChangeRecord`] plus the runtime operator's `Ed25519` signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedStateChange {
    /// The wrapped record.
    pub record: StateChangeRecord,
    /// `FNV-1a` hash of the record's canonical bytes.
    pub hash: u64,
    /// `Ed25519` signature over the canonical bytes.
    pub signature: Signature,
    /// Runtime operator's `Ed25519` public key.
    pub operator: PublicKey,
}

impl SignedStateChange {
    /// Verify signature and hash consistency.
    #[must_use]
    pub fn verify(&self) -> bool {
        if self.hash != self.record.hash() {
            return false;
        }
        self.operator
            .verify(&self.record.canonical_bytes(), &self.signature)
    }
}

// ---------------------------------------------------------------------------
// StateChangeTrail
// ---------------------------------------------------------------------------

/// Append-only chain of [`SignedStateChange`] records.
#[derive(Debug, Clone, Default)]
pub struct StateChangeTrail {
    entries: Vec<SignedStateChange>,
}

impl StateChangeTrail {
    /// Construct an empty trail.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the trail is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Read-only view.
    #[must_use]
    pub fn entries(&self) -> &[SignedStateChange] {
        &self.entries
    }

    /// Hash of the last record (0 for empty).
    #[must_use]
    pub fn tail_hash(&self) -> u64 {
        self.entries.last().map_or(0, |e| e.hash)
    }

    /// Append a new lifecycle event signed with the runtime operator's
    /// key pair.
    pub fn append(
        &mut self,
        keypair: &KeyPair,
        kind: ContainerEventKind,
        timestamp_ns: u64,
        container_id: impl Into<String>,
        image: impl Into<String>,
        host: impl Into<String>,
        actor_id: impl Into<String>,
        payload: impl Into<String>,
        outcome: impl Into<String>,
    ) -> &SignedStateChange {
        let seq = self.entries.len() as u64;
        let prev_hash = self.tail_hash();
        let record = StateChangeRecord {
            seq,
            kind,
            timestamp_ns,
            container_id: container_id.into(),
            image: image.into(),
            host: host.into(),
            actor_id: actor_id.into(),
            payload: payload.into(),
            outcome: outcome.into(),
            prev_hash,
        };
        let bytes = record.canonical_bytes();
        let hash = record.hash();
        let signature = keypair.sign(&bytes);
        let operator = keypair.public();
        self.entries.push(SignedStateChange {
            record,
            hash,
            signature,
            operator,
        });
        self.entries.last().expect("entry was just pushed")
    }

    /// Verify signature and chain integrity end-to-end.
    #[must_use]
    pub fn find_first_tamper(&self) -> Option<usize> {
        let mut expected_prev: u64 = 0;
        for (i, e) in self.entries.iter().enumerate() {
            if e.record.seq as usize != i {
                return Some(i);
            }
            if e.record.prev_hash != expected_prev {
                return Some(i);
            }
            if !e.verify() {
                return Some(i);
            }
            expected_prev = e.hash;
        }
        None
    }

    /// Whether the trail is intact.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.find_first_tamper().is_none()
    }

    /// Latest event kind observed for the given container id.
    #[must_use]
    pub fn latest_kind(&self, container_id: &str) -> Option<ContainerEventKind> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.record.container_id == container_id)
            .map(|e| e.record.kind)
    }

    /// Every distinct container id observed in the trail.
    #[must_use]
    pub fn container_ids(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for e in &self.entries {
            if !out.contains(&e.record.container_id) {
                out.push(e.record.container_id.clone());
            }
        }
        out
    }

    /// Count of events of the given kind on the given host.
    #[must_use]
    pub fn count_kind_for_host(&self, host: &str, kind: ContainerEventKind) -> usize {
        self.entries
            .iter()
            .filter(|e| e.record.host == host && e.record.kind == kind)
            .count()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn kp(seed: u8) -> KeyPair {
        KeyPair::from_seed([seed; 32])
    }

    #[test]
    fn kind_code_is_stable() {
        assert_eq!(ContainerEventKind::Created.code(), "CREATE");
        assert_eq!(ContainerEventKind::Started.code(), "START");
        assert_eq!(ContainerEventKind::Exec.code(), "EXEC");
        assert_eq!(ContainerEventKind::Stopped.code(), "STOP");
        assert_eq!(ContainerEventKind::Deleted.code(), "DEL");
        assert_eq!(ContainerEventKind::ImagePulled.code(), "PULL");
        assert_eq!(ContainerEventKind::CgroupUpdated.code(), "CG");
        assert_eq!(ContainerEventKind::SeccompUpdated.code(), "SECCP");
        assert_eq!(ContainerEventKind::NamespaceAttach.code(), "NSATT");
    }

    #[test]
    fn canonical_bytes_are_deterministic() {
        let r = StateChangeRecord {
            seq: 0,
            kind: ContainerEventKind::Started,
            timestamp_ns: 1,
            container_id: String::from("c-1"),
            image: String::from("nginx:1.25"),
            host: String::from("node-01"),
            actor_id: String::from("root"),
            payload: String::from("argv=/usr/sbin/nginx"),
            outcome: String::from("success"),
            prev_hash: 0,
        };
        assert_eq!(r.canonical_bytes(), r.canonical_bytes());
    }

    #[test]
    fn hash_differs_when_actor_changes() {
        let mut r = StateChangeRecord {
            seq: 0,
            kind: ContainerEventKind::Exec,
            timestamp_ns: 1,
            container_id: String::from("c-1"),
            image: String::from("i"),
            host: String::from("h"),
            actor_id: String::from("alice"),
            payload: String::new(),
            outcome: String::new(),
            prev_hash: 0,
        };
        let h1 = r.hash();
        r.actor_id = String::from("root");
        assert_ne!(h1, r.hash());
    }

    #[test]
    fn empty_trail_tail_hash_is_zero() {
        let trail = StateChangeTrail::new();
        assert_eq!(trail.tail_hash(), 0);
        assert!(trail.is_empty());
    }

    #[test]
    fn signed_record_verifies_on_append() {
        let mut trail = StateChangeTrail::new();
        let k = kp(1);
        trail.append(
            &k,
            ContainerEventKind::Created,
            1,
            "c-1",
            "nginx:1.25",
            "node-01",
            "root",
            "",
            "success",
        );
        assert!(trail.entries()[0].verify());
    }

    #[test]
    fn chained_prev_hash_matches_predecessor() {
        let mut trail = StateChangeTrail::new();
        let k = kp(1);
        trail.append(
            &k,
            ContainerEventKind::Created,
            1,
            "c-1",
            "i",
            "h",
            "u",
            "",
            "success",
        );
        trail.append(
            &k,
            ContainerEventKind::Started,
            2,
            "c-1",
            "i",
            "h",
            "u",
            "",
            "success",
        );
        let first = trail.entries()[0].hash;
        assert_eq!(trail.entries()[1].record.prev_hash, first);
    }

    #[test]
    fn intact_lifecycle_is_valid() {
        let mut trail = StateChangeTrail::new();
        let k = kp(1);
        for (ts, ev) in [
            (1, ContainerEventKind::ImagePulled),
            (2, ContainerEventKind::Created),
            (3, ContainerEventKind::Started),
            (4, ContainerEventKind::Exec),
            (5, ContainerEventKind::Stopped),
            (6, ContainerEventKind::Deleted),
        ] {
            trail.append(&k, ev, ts, "c-1", "i", "h", "u", "", "success");
        }
        assert!(trail.is_valid());
    }

    #[test]
    fn tampered_payload_is_detected() {
        let mut trail = StateChangeTrail::new();
        let k = kp(1);
        trail.append(
            &k,
            ContainerEventKind::Exec,
            1,
            "c-1",
            "i",
            "h",
            "u",
            "argv=/bin/ls",
            "success",
        );
        // Attacker rewrites benign exec to hide a shell.
        trail.entries[0].record.payload = String::from("argv=/bin/sh");
        assert!(!trail.entries[0].verify());
        assert_eq!(trail.find_first_tamper(), Some(0));
    }

    #[test]
    fn tampered_image_is_detected() {
        let mut trail = StateChangeTrail::new();
        let k = kp(1);
        trail.append(
            &k,
            ContainerEventKind::ImagePulled,
            1,
            "c-1",
            "sha256:abc",
            "h",
            "u",
            "",
            "success",
        );
        trail.entries[0].record.image = String::from("sha256:attacker");
        assert!(!trail.entries[0].verify());
    }

    #[test]
    fn foreign_operator_signature_is_rejected() {
        let mut trail = StateChangeTrail::new();
        let genuine = kp(1);
        let attacker = kp(2);
        trail.append(
            &genuine,
            ContainerEventKind::Exec,
            1,
            "c-1",
            "i",
            "h",
            "u",
            "",
            "success",
        );
        let bytes = trail.entries[0].record.canonical_bytes();
        trail.entries[0].signature = attacker.sign(&bytes);
        assert!(!trail.entries[0].verify());
    }

    #[test]
    fn latest_kind_returns_most_recent() {
        let mut trail = StateChangeTrail::new();
        let k = kp(1);
        trail.append(
            &k,
            ContainerEventKind::Created,
            1,
            "c-1",
            "i",
            "h",
            "u",
            "",
            "",
        );
        trail.append(
            &k,
            ContainerEventKind::Started,
            2,
            "c-1",
            "i",
            "h",
            "u",
            "",
            "",
        );
        trail.append(
            &k,
            ContainerEventKind::Stopped,
            3,
            "c-1",
            "i",
            "h",
            "u",
            "",
            "",
        );
        assert_eq!(trail.latest_kind("c-1"), Some(ContainerEventKind::Stopped));
    }

    #[test]
    fn latest_kind_returns_none_for_unknown() {
        let trail = StateChangeTrail::new();
        assert_eq!(trail.latest_kind("c-none"), None);
    }

    #[test]
    fn container_ids_lists_distinct() {
        let mut trail = StateChangeTrail::new();
        let k = kp(1);
        trail.append(
            &k,
            ContainerEventKind::Created,
            1,
            "c-A",
            "i",
            "h",
            "u",
            "",
            "",
        );
        trail.append(
            &k,
            ContainerEventKind::Created,
            2,
            "c-B",
            "i",
            "h",
            "u",
            "",
            "",
        );
        trail.append(
            &k,
            ContainerEventKind::Started,
            3,
            "c-A",
            "i",
            "h",
            "u",
            "",
            "",
        );
        let ids = trail.container_ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&String::from("c-A")));
        assert!(ids.contains(&String::from("c-B")));
    }

    #[test]
    fn count_kind_for_host_filters() {
        let mut trail = StateChangeTrail::new();
        let k = kp(1);
        for _ in 0..3 {
            trail.append(
                &k,
                ContainerEventKind::Exec,
                0,
                "c",
                "i",
                "node-01",
                "u",
                "",
                "",
            );
        }
        for _ in 0..2 {
            trail.append(
                &k,
                ContainerEventKind::Exec,
                0,
                "c",
                "i",
                "node-02",
                "u",
                "",
                "",
            );
        }
        assert_eq!(
            trail.count_kind_for_host("node-01", ContainerEventKind::Exec),
            3
        );
        assert_eq!(
            trail.count_kind_for_host("node-02", ContainerEventKind::Exec),
            2
        );
        assert_eq!(
            trail.count_kind_for_host("node-03", ContainerEventKind::Exec),
            0
        );
    }

    #[test]
    fn different_kinds_produce_different_hashes() {
        let mk = |kind: ContainerEventKind| StateChangeRecord {
            seq: 0,
            kind,
            timestamp_ns: 1,
            container_id: String::new(),
            image: String::new(),
            host: String::new(),
            actor_id: String::new(),
            payload: String::new(),
            outcome: String::new(),
            prev_hash: 0,
        };
        assert_ne!(
            mk(ContainerEventKind::Exec).hash(),
            mk(ContainerEventKind::ImagePulled).hash()
        );
    }
}
