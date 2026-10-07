//! Process lifecycle events: fork, exec and exit.
//!
//! `sched_switch` answers "who was on the CPU"; it does not say who *started*
//! or *died*, which is often the actual explanation for a stall (a fork storm,
//! a process thrashing under a supervisor, a daemon respawning in a loop).
//! These three tracepoints are sent through a second, much smaller ring buffer
//! so the hot `sched_switch` path keeps its own single record type: two maps,
//! two fixed record layouts, no tag to branch on in the kernel.
//!
//! Lifecycle events are rarer than context switches by orders of magnitude, so
//! they add little overhead and can be retained for the whole window.
//!
//! Wire layout (must stay byte-identical to `blackbox-bpf`'s `Lifecycle`):
//!
//! ```text
//!   ts_ns      u64   0
//!   value      i64   8    (exit: priority; others unused)
//!   kind       u32   16   (0 fork, 1 exec, 2 exit)
//!   pid        u32   20
//!   peer_pid   u32   24   (fork: child; exec: pid before exec; exit: 0)
//!   _pad       u32   28
//!   comm       [u8;16]  32
//!   name       [u8;16]  48   (fork: child comm; exec: path; exit: empty)
//! ```

use std::collections::VecDeque;
use std::mem::offset_of;

use serde::{Deserialize, Serialize};

use crate::event::{comm_to_str, field, COMM_LEN};

/// Length of the secondary name field (child comm or executable path).
pub const NAME_LEN: usize = 16;

/// Raw `kind` values in the wire record.
pub const KIND_FORK: u32 = 0;
pub const KIND_EXEC: u32 = 1;
pub const KIND_EXIT: u32 = 2;

/// The fixed record the BPF program writes for each lifecycle event.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LifecycleRecord {
    pub ts_ns: u64,
    pub value: i64,
    pub kind: u32,
    pub pid: u32,
    pub peer_pid: u32,
    pub _pad: u32,
    pub comm: [u8; COMM_LEN],
    pub name: [u8; NAME_LEN],
}

impl LifecycleRecord {
    /// Decode one raw ring buffer record, or `None` on a wrong-size record.
    ///
    /// Same contract as [`crate::event::SchedSwitch::from_bytes`]: field offsets
    /// come from `offset_of!` and every copy is bounds-checked, so this is safe
    /// on any alignment.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != std::mem::size_of::<Self>() {
            return None;
        }
        Some(Self {
            ts_ns: u64::from_ne_bytes(field(bytes, offset_of!(Self, ts_ns))?),
            value: i64::from_ne_bytes(field(bytes, offset_of!(Self, value))?),
            kind: u32::from_ne_bytes(field(bytes, offset_of!(Self, kind))?),
            pid: u32::from_ne_bytes(field(bytes, offset_of!(Self, pid))?),
            peer_pid: u32::from_ne_bytes(field(bytes, offset_of!(Self, peer_pid))?),
            _pad: u32::from_ne_bytes(field(bytes, offset_of!(Self, _pad))?),
            comm: field(bytes, offset_of!(Self, comm))?,
            name: field(bytes, offset_of!(Self, name))?,
        })
    }

    pub fn kind(&self) -> Option<LifecycleKind> {
        LifecycleKind::from_raw(self.kind)
    }

    pub fn comm_str(&self) -> &str {
        comm_to_str(&self.comm)
    }

    pub fn name_str(&self) -> &str {
        comm_to_str(&self.name)
    }
}

/// Which lifecycle event this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LifecycleKind {
    Fork,
    Exec,
    Exit,
}

impl LifecycleKind {
    pub fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            KIND_FORK => Some(Self::Fork),
            KIND_EXEC => Some(Self::Exec),
            KIND_EXIT => Some(Self::Exit),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Fork => "fork",
            Self::Exec => "exec",
            Self::Exit => "exit",
        }
    }
}

/// A decoded lifecycle event, ready for the dump or report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleEvent {
    pub ts_ns: u64,
    pub kind: LifecycleKind,
    /// Subject pid: the parent for `fork`, the process itself for `exec`/`exit`.
    pub pid: u32,
    /// `fork`: the child pid. `exec`: the pid before the exec. `exit`: 0.
    pub peer_pid: u32,
    /// `exit`: the process priority. `fork`/`exec`: 0.
    pub value: i64,
    /// Subject comm: the parent's name for `fork`, the process name for `exit`.
    pub comm: String,
    /// `fork`: the child's comm. `exec`: the executed path. `exit`: empty.
    pub name: String,
}

impl LifecycleEvent {
    pub fn from_record(record: &LifecycleRecord) -> Option<Self> {
        Some(Self {
            ts_ns: record.ts_ns,
            kind: record.kind()?,
            pid: record.pid,
            peer_pid: record.peer_pid,
            value: record.value,
            comm: record.comm_str().to_owned(),
            name: record.name_str().to_owned(),
        })
    }

    /// One-line human description for the text report.
    pub fn describe(&self) -> String {
        match self.kind {
            LifecycleKind::Fork => {
                if self.name.is_empty() {
                    format!("fork:  pid {} -> pid {}", self.pid, self.peer_pid)
                } else {
                    format!(
                        "fork:  {} (pid {}) -> {} (pid {})",
                        or_unknown(&self.comm),
                        self.pid,
                        self.name,
                        self.peer_pid
                    )
                }
            }
            LifecycleKind::Exec => {
                let what = if self.name.is_empty() {
                    or_unknown(&self.comm)
                } else {
                    &self.name
                };
                format!("exec:  {} (pid {})", what, self.pid)
            }
            LifecycleKind::Exit => format!(
                "exit:  {} (pid {}, prio {})",
                or_unknown(&self.comm),
                self.pid,
                self.value
            ),
        }
    }
}

fn or_unknown(s: &str) -> &str {
    if s.is_empty() {
        "<unknown>"
    } else {
        s
    }
}

/// A bounded lifecycle window, mirroring [`crate::history::HistoryRing`].
///
/// Same two caps (count and duration) and the same eviction rules, kept as a
/// separate structure because the element type differs and the sched path must
/// not grow a branch for it.
#[derive(Debug)]
pub struct LifecycleRing {
    events: VecDeque<LifecycleEvent>,
    max_events: usize,
    max_duration_ns: u64,
    evicted: u64,
}

impl LifecycleRing {
    pub fn new(max_events: usize, max_seconds: u64) -> Self {
        Self {
            events: VecDeque::with_capacity(max_events.min(8192)),
            max_events: max_events.max(1),
            max_duration_ns: max_seconds.saturating_mul(1_000_000_000),
            evicted: 0,
        }
    }

    pub fn push(&mut self, ev: LifecycleEvent) {
        self.events.push_back(ev);
        while self.events.len() > self.max_events {
            self.events.pop_front();
            self.evicted += 1;
        }
        loop {
            let span = match (self.events.front(), self.events.back()) {
                (Some(first), Some(last)) => last.ts_ns.saturating_sub(first.ts_ns),
                _ => 0,
            };
            if span <= self.max_duration_ns || self.events.len() <= 1 {
                return;
            }
            self.events.pop_front();
            self.evicted += 1;
        }
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    pub fn iter(&self) -> impl Iterator<Item = &LifecycleEvent> {
        self.events.iter()
    }

    /// Chronological snapshot, oldest first (arrival order is only approximate).
    pub fn snapshot(&self) -> Vec<LifecycleEvent> {
        let mut out: Vec<LifecycleEvent> = self.events.iter().cloned().collect();
        out.sort_by_key(|e| e.ts_ns);
        out
    }

    pub fn clear(&mut self) {
        self.events.clear();
    }
}

impl Default for LifecycleRing {
    fn default() -> Self {
        Self::new(
            crate::history::DEFAULT_MAX_EVENTS,
            crate::history::DEFAULT_MAX_SECONDS,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec(ts: u64, pid: u32, path: &str) -> LifecycleEvent {
        LifecycleEvent {
            ts_ns: ts,
            kind: LifecycleKind::Exec,
            pid,
            peer_pid: pid + 1,
            value: 0,
            comm: "bash".into(),
            name: path.into(),
        }
    }

    /// Encode a record the way the BPF program lays it out, against the
    /// documented offsets rather than `offset_of!`, so a struct drift fails
    /// here instead of silently following the struct off the wire.
    fn wire_bytes(r: &LifecycleRecord) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[0..8].copy_from_slice(&r.ts_ns.to_ne_bytes());
        out[8..16].copy_from_slice(&r.value.to_ne_bytes());
        out[16..20].copy_from_slice(&r.kind.to_ne_bytes());
        out[20..24].copy_from_slice(&r.pid.to_ne_bytes());
        out[24..28].copy_from_slice(&r.peer_pid.to_ne_bytes());
        out[28..32].copy_from_slice(&r._pad.to_ne_bytes());
        out[32..48].copy_from_slice(&r.comm);
        out[48..64].copy_from_slice(&r.name);
        out
    }

    #[test]
    fn wire_size_and_offsets_are_stable() {
        assert_eq!(std::mem::size_of::<LifecycleRecord>(), 64);
        assert_eq!(offset_of!(LifecycleRecord, ts_ns), 0);
        assert_eq!(offset_of!(LifecycleRecord, value), 8);
        assert_eq!(offset_of!(LifecycleRecord, kind), 16);
        assert_eq!(offset_of!(LifecycleRecord, pid), 20);
        assert_eq!(offset_of!(LifecycleRecord, peer_pid), 24);
        assert_eq!(offset_of!(LifecycleRecord, comm), 32);
        assert_eq!(offset_of!(LifecycleRecord, name), 48);
    }

    #[test]
    fn from_bytes_round_trips_a_wire_record() {
        let r = LifecycleRecord {
            ts_ns: 4_200,
            value: -3,
            kind: KIND_FORK,
            pid: 100,
            peer_pid: 101,
            _pad: 0,
            comm: {
                let mut c = [0u8; COMM_LEN];
                c[..4].copy_from_slice(b"init");
                c
            },
            name: {
                let mut n = [0u8; NAME_LEN];
                n[..4].copy_from_slice(b"bash");
                n
            },
        };
        let decoded = LifecycleRecord::from_bytes(&wire_bytes(&r)).expect("must decode");
        assert_eq!(decoded, r);
        assert_eq!(decoded.kind(), Some(LifecycleKind::Fork));
        assert_eq!(decoded.comm_str(), "init");
        assert_eq!(decoded.name_str(), "bash");
    }

    #[test]
    fn from_bytes_rejects_wrong_lengths() {
        let r = LifecycleRecord::default();
        let bytes = wire_bytes(&r);
        assert_eq!(LifecycleRecord::from_bytes(&bytes[..63]), None);
        assert_eq!(LifecycleRecord::from_bytes(&[]), None);
    }

    #[test]
    fn unknown_kind_is_rejected() {
        let r = LifecycleRecord {
            kind: 99,
            ..Default::default()
        };
        assert_eq!(r.kind(), None);
        assert_eq!(LifecycleEvent::from_record(&r), None);
    }

    #[test]
    fn kinds_round_trip_through_their_raw_values() {
        for (raw, kind) in [
            (KIND_FORK, LifecycleKind::Fork),
            (KIND_EXEC, LifecycleKind::Exec),
            (KIND_EXIT, LifecycleKind::Exit),
        ] {
            assert_eq!(LifecycleKind::from_raw(raw), Some(kind));
            assert!(!kind.as_str().is_empty());
        }
    }

    #[test]
    fn describe_is_human_readable_for_every_kind() {
        let fork = LifecycleEvent {
            ts_ns: 0,
            kind: LifecycleKind::Fork,
            pid: 1,
            peer_pid: 2,
            value: 0,
            comm: "systemd".into(),
            name: "bash".into(),
        };
        assert!(fork.describe().contains("systemd"));
        assert!(fork.describe().contains("bash"));
        let exec = exec(0, 10, "/usr/bin/ls");
        assert!(exec.describe().contains("/usr/bin/ls"));
        let exit = LifecycleEvent {
            ts_ns: 0,
            kind: LifecycleKind::Exit,
            pid: 7,
            peer_pid: 0,
            value: 120,
            comm: "worker".into(),
            name: String::new(),
        };
        assert!(exit.describe().contains("120"));
    }

    #[test]
    fn describe_degrades_on_an_empty_name() {
        let mut e = exec(0, 5, "");
        e.comm = String::new();
        assert!(e.describe().contains("<unknown>"));
    }

    #[test]
    fn ring_evicts_to_the_count_cap() {
        let mut r = LifecycleRing::new(3, 1000);
        for i in 0..5 {
            r.push(exec(i, i as u32, "x"));
        }
        assert_eq!(r.len(), 3);
        assert_eq!(r.evicted(), 2);
    }

    #[test]
    fn ring_evicts_to_the_time_cap_and_keeps_one() {
        let mut r = LifecycleRing::new(100, 1);
        r.push(exec(0, 1, "x"));
        r.push(exec(5_000_000_000, 2, "x"));
        assert_eq!(r.len(), 1);
        assert_eq!(r.snapshot()[0].pid, 2);
    }

    #[test]
    fn ring_snapshot_is_chronological_and_clear_keeps_counters() {
        let mut r = LifecycleRing::new(10, 100);
        r.push(exec(30, 1, "x"));
        r.push(exec(10, 2, "x"));
        r.push(exec(20, 3, "x"));
        let ts: Vec<u64> = r.snapshot().iter().map(|e| e.ts_ns).collect();
        assert_eq!(ts, vec![10, 20, 30]);
        r.clear();
        assert!(r.is_empty());
    }
}
