//! The raw event record emitted by the BPF program, and the naming details that
//! the kernel gives us.

use std::mem::offset_of;

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

    /// Decode one raw ring buffer record.
    ///
    /// The BPF program writes this struct into the ring buffer verbatim, so a
    /// record is exactly `size_of::<SchedSwitch>()` bytes of native-endian
    /// fields — both halves run on the same machine, so native endianness is
    /// correct by construction. A wrong-length record is rejected outright
    /// rather than padded or truncated: a short record would silently misparse
    /// every field after the gap, which is worse than dropping it.
    ///
    /// Fully safe: field offsets come from `offset_of!` (compiler truth, so
    /// this tracks any layout change) and every copy is bounds-checked, so an
    /// unaligned or oddly-placed buffer works just as well.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != std::mem::size_of::<Self>() {
            return None;
        }
        Some(Self {
            ts_ns: u64::from_ne_bytes(field(bytes, offset_of!(Self, ts_ns))?),
            prev_state: i64::from_ne_bytes(field(bytes, offset_of!(Self, prev_state))?),
            prev_pid: u32::from_ne_bytes(field(bytes, offset_of!(Self, prev_pid))?),
            next_pid: u32::from_ne_bytes(field(bytes, offset_of!(Self, next_pid))?),
            cpu: u32::from_ne_bytes(field(bytes, offset_of!(Self, cpu))?),
            prev_comm: field(bytes, offset_of!(Self, prev_comm))?,
            next_comm: field(bytes, offset_of!(Self, next_comm))?,
        })
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

/// Copy `N` bytes out of `bytes` at `offset`, or `None` when out of bounds.
///
/// Bounds-checked via `get`, so a bad offset returns `None` instead of
/// panicking inside the daemon's collector thread.
pub(crate) fn field<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    bytes.get(offset..offset + N)?.try_into().ok()
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

    /// Encode an event the way the BPF program lays it out: fields at their
    /// documented offsets. Written against the documented layout rather than
    /// `offset_of!` on purpose — if the struct drifts, these two disagree and
    /// the test fails instead of the parser quietly following the struct away
    /// from the wire format.
    fn wire_bytes(ev: &SchedSwitch) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[0..8].copy_from_slice(&ev.ts_ns.to_ne_bytes());
        out[8..16].copy_from_slice(&ev.prev_state.to_ne_bytes());
        out[16..20].copy_from_slice(&ev.prev_pid.to_ne_bytes());
        out[20..24].copy_from_slice(&ev.next_pid.to_ne_bytes());
        out[24..28].copy_from_slice(&ev.cpu.to_ne_bytes());
        out[28..44].copy_from_slice(&ev.prev_comm);
        out[44..60].copy_from_slice(&ev.next_comm);
        out
    }

    #[test]
    fn field_offsets_match_the_documented_wire_layout() {
        // Changing any of these changes the ring buffer layout, so it needs a
        // rebuilt blackbox-bpf.o and a SCHEMA_VERSION bump — same rule as
        // `wire_size_is_stable`.
        assert_eq!(offset_of!(SchedSwitch, ts_ns), 0);
        assert_eq!(offset_of!(SchedSwitch, prev_state), 8);
        assert_eq!(offset_of!(SchedSwitch, prev_pid), 16);
        assert_eq!(offset_of!(SchedSwitch, next_pid), 20);
        assert_eq!(offset_of!(SchedSwitch, cpu), 24);
        assert_eq!(offset_of!(SchedSwitch, prev_comm), 28);
        assert_eq!(offset_of!(SchedSwitch, next_comm), 44);
    }

    #[test]
    fn from_bytes_round_trips_a_wire_record() {
        let ev = SchedSwitch::new(
            1_234_567_890_123,
            3,
            42,
            7,
            TASK_RUNNING,
            b"kworker/0:1",
            b"systemd-journal",
        );
        let decoded = SchedSwitch::from_bytes(&wire_bytes(&ev)).expect("record must decode");
        assert_eq!(decoded, ev);
        assert_eq!(decoded.prev_comm_str(), "kworker/0:1");
        assert_eq!(decoded.next_comm_str(), "systemd-journal");
    }

    #[test]
    fn from_bytes_tolerates_arbitrary_comm_bytes() {
        // A task can rename itself to non-UTF-8 bytes; decoding must still
        // produce the record, with comm decoding degrading separately.
        let mut ev = SchedSwitch::new(9, 0, 1, 2, -1, b"a", b"b");
        ev.prev_comm = [0xff; COMM_LEN];
        ev.prev_state = -5;
        let decoded = SchedSwitch::from_bytes(&wire_bytes(&ev)).expect("record must decode");
        assert_eq!(decoded, ev);
        assert_eq!(decoded.prev_comm_str(), "<non-utf8>");
    }

    #[test]
    fn from_bytes_rejects_wrong_lengths() {
        let ev = SchedSwitch::new(1, 0, 1, 2, 0, b"a", b"b");
        let bytes = wire_bytes(&ev);
        // Too short, too long, and empty: none can be a whole record, and
        // guessing would corrupt every field after the first gap.
        assert_eq!(SchedSwitch::from_bytes(&bytes[..63]), None);
        assert_eq!(SchedSwitch::from_bytes(&bytes[..0]), None);
        let mut long = bytes.to_vec();
        long.push(0);
        assert_eq!(SchedSwitch::from_bytes(&long), None);
    }

    #[test]
    fn from_bytes_requires_no_alignment() {
        // Ring buffer items are aligned in practice, but a parser that only
        // works on aligned input invites unsafe or copy bugs elsewhere; this
        // one copies field by field, so any offset works.
        let ev = SchedSwitch::new(77, 2, 5, 6, 1, b"prev", b"next");
        let mut buf = [0u8; 65];
        buf[1..65].copy_from_slice(&wire_bytes(&ev));
        assert_eq!(SchedSwitch::from_bytes(&buf[1..]), Some(ev));
    }
}
