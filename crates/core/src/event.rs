//! The raw event record emitted by the BPF program, and the naming details that
//! the kernel gives us.

/// Length of `TASK_COMM_LEN`. The kernel pads with NULs, and the last byte is
/// always reserved, so a comm is at most 15 characters.
pub const COMM_LEN: usize = 16;

/// `prev_state == 0` means the task was still runnable when it was switched out,
/// i.e. it was preempted rather than blocked. This distinction is what lets the
/// report separate scheduler latency from time spent blocked on I/O or sleep.
pub const TASK_RUNNING: i64 = 0;

/// A single `sched_switch` observation.
///
/// This is the layout the BPF program writes into the ring buffer, so it must
/// stay `#[repr(C)]` and POD: fixed size, no pointers, no padding surprises.
/// The compile-time assertion below guards the wire size.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SchedSwitch {
    /// Monotonic clock (ktime), matching `CLOCK_MONOTONIC`.
    pub ts_ns: u64,
    /// `prev_state` from the tracepoint. See [`TASK_RUNNING`].
    pub prev_state: i64,
    pub prev_pid: u32,
    pub next_pid: u32,
    /// Stamped in BPF with `bpf_get_smp_processor_id()`.
    ///
    /// The `sched_switch` tracepoint payload does not carry a CPU field, but we
    /// cannot reconstruct on-CPU intervals without one, so the BPF program adds
    /// it. Cheaper than keeping per-CPU state on the kernel side.
    pub cpu: u32,
    pub prev_comm: [u8; COMM_LEN],
    pub next_comm: [u8; COMM_LEN],
}

const _: () = assert!(std::mem::size_of::<SchedSwitch>() == 64);

impl SchedSwitch {
    /// Build an event from raw parts. Used by tests and by the replay path.
    pub fn new(
        ts_ns: u64,
        cpu: u32,
        prev_pid: u32,
        next_pid: u32,
        prev_state: i64,
        prev_comm: &[u8],
        next_comm: &[u8],
    ) -> Self {
        Self {
            ts_ns,
            prev_state,
            prev_pid,
            next_pid,
            cpu,
            prev_comm: comm_bytes(prev_comm),
            next_comm: comm_bytes(next_comm),
        }
    }

    pub fn prev_comm_str(&self) -> &str {
        comm_to_str(&self.prev_comm)
    }

    pub fn next_comm_str(&self) -> &str {
        comm_to_str(&self.next_comm)
    }

    /// True when the outgoing task was still runnable, i.e. it lost the CPU
    /// rather than blocking.
    pub fn was_preempted(&self) -> bool {
        self.prev_state == TASK_RUNNING
    }
}

fn comm_bytes(src: &[u8]) -> [u8; COMM_LEN] {
    let mut out = [0u8; COMM_LEN];
    let n = src.len().min(COMM_LEN - 1);
    out[..n].copy_from_slice(&src[..n]);
    out
}

/// Decode a NUL-padded kernel comm into a `&str`.
pub fn comm_to_str(bytes: &[u8; COMM_LEN]) -> &str {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(COMM_LEN);
    // The kernel comm is ASCII in practice, but a task can rename itself to
    // non-UTF-8 bytes, so degrade rather than panic.
    std::str::from_utf8(&bytes[..end]).unwrap_or("<non-utf8>")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_size_is_stable() {
        // Changing this changes the on-disk schema and the ring buffer layout,
        // so it is an error to change it without bumping SCHEMA_VERSION.
        assert_eq!(std::mem::size_of::<SchedSwitch>(), 64);
    }

    #[test]
    fn comm_is_truncated_at_nul() {
        let ev = SchedSwitch::new(0, 0, 1, 2, 0, b"systemd-journal", b"kworker/0:1");
        assert_eq!(ev.prev_comm_str(), "systemd-journal");
        assert_eq!(ev.next_comm_str(), "kworker/0:1");
    }

    #[test]
    fn comm_longer_than_buffer_is_truncated_to_15_bytes() {
        let ev = SchedSwitch::new(0, 0, 1, 2, 0, b"a-really-long-process-name", b"b");
        // The kernel reserves the final byte for a NUL terminator.
        assert_eq!(ev.prev_comm_str().len(), COMM_LEN - 1);
    }

    #[test]
    fn empty_comm_decodes_to_empty_string() {
        let ev = SchedSwitch::new(0, 0, 1, 2, 0, b"", b"x");
        assert_eq!(ev.prev_comm_str(), "");
    }

    #[test]
    fn non_utf8_comm_degrades_instead_of_panicking() {
        let mut raw = [0u8; COMM_LEN];
        raw[0] = 0xff;
        raw[1] = 0xfe;
        let ev = SchedSwitch {
            next_comm: raw,
            ..Default::default()
        };
        assert_eq!(ev.next_comm_str(), "<non-utf8>");
    }

    #[test]
    fn preemption_is_state_zero() {
        let preempted = SchedSwitch::new(0, 0, 1, 2, TASK_RUNNING, b"a", b"b");
        let blocked = SchedSwitch::new(0, 0, 1, 2, 1, b"a", b"b");
        assert!(preempted.was_preempted());
        assert!(!blocked.was_preempted());
    }
}
