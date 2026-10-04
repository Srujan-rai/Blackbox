//! The BPF half of blackbox: observe `sched_switch`, publish to a ring buffer.
//!
//! Deliberately minimal. Everything hard -- reconstructing intervals, ranking
//! consumers, deciding whether a trace is complete -- happens in
//! `blackbox-core` in userspace, because logic here costs verifier budget and
//! runtime on every context switch on the machine.
//!
//! On the permissions question: this program uses tracepoints only. Tracepoints
//! need no GPL-only helper, which is precisely why the project can stay MIT.
//! Reimplementing any of this with kprobes would pull in `bpf_probe_read_user`
//! and friends, whose GPL-only licensing would force the whole project to
//! GPL. If you are tempted to swap a tracepoint for a kprobe, that is the
//! moment the licence changes, and it needs to be a deliberate decision.

#![no_std]
#![no_main]

use aya_ebpf::macros::{map, tracepoint};
use aya_ebpf::maps::RingBuf;
use aya_ebpf::programs::TracePointContext;
use aya_ebpf::helpers::gen::bpf_ktime_get_ns;

/// Ring buffer shared with userspace.
///
/// Size is fixed at compile time; userspace reads it as `EVENTS_LEN * 8` bytes
/// when sizing its poll buffer. 8 MB comfortably absorbs a burst on a large box
/// while the daemon does other work, and is the main reason kernel-side drops
/// should read zero in practice.
const EVENTS_LEN: usize = 1 << 20;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SchedSwitch {
    pub ts_ns: u64,
    pub prev_state: i64,
    pub prev_pid: u32,
    pub next_pid: u32,
    pub cpu: u32,
    pub prev_comm: [u8; 16],
    pub next_comm: [u8; 16],
}

// Keep the wire struct byte-identical to blackbox_core::event::SchedSwitch.
// A silent divergence here would produce garbage timestamps rather than an
// error, which is the worst failure mode available.
const _: () = assert!(core::mem::size_of::<SchedSwitch>() == 64);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size((EVENTS_LEN * 8) as u32, 0);

#[tracepoint]
pub fn sched_switch(ctx: TracePointContext) -> u32 {
    // The tracepoint payload is laid out as:
    //   prev_comm[16] prev_pid prev_prio prev_state next_comm[16] next_pid next_prio
    // with a 4-byte common_type prefix, which aya has already skipped, so the
    // offsets below are relative to the start of the payload.
    let prev_comm: &[u8; 16] = unsafe { ctx.read_at(0).map_err(|_| return 0).unwrap() };
    let prev_pid: u32 = unsafe { ctx.read_at(16).map_err(|_| return 0).unwrap() };
    let prev_state: i64 = unsafe { ctx.read_at(24).map_err(|_| return 0).unwrap() };
    let next_comm: &[u8; 16] = unsafe { ctx.read_at(32).map_err(|_| return 0).unwrap() };
    let next_pid: u32 = unsafe { ctx.read_at(48).map_err(|_| return 0).unwrap() };

    let ev = SchedSwitch {
        ts_ns: unsafe { bpf_ktime_get_ns() },
        prev_state,
        prev_pid,
        next_pid,
        // Not in the tracepoint payload. On-CPU intervals cannot be rebuilt
        // per-CPU without it, so it is cheaper to stamp it here than to keep
        // coherent per-CPU state in a map.
        cpu: unsafe { aya_ebpf::helpers::bpf_get_smp_processor_id() },
        prev_comm: *prev_comm,
        next_comm: *next_comm,
    };

    // A failed output is dropped, never retried. Blocking or reserving space
    // would risk stalling the scheduler, and on the ring buffer an error means
    // the reader is too far behind anyway. The count of these is what
    // `events_dropped_kernel` in the dump reports.
    let _ = EVENTS.output(&ev, 0);

    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Unreachable in practice: the program has no panicking paths and is built
    // with panic=abort. Looping is what aya expects here.
    loop {}
}

/// Licence declaration read by the kernel at load time.
///
/// This is MIT, not "GPL", and that is load-bearing rather than cosmetic. The
/// kernel refuses to load a non-GPL program that calls a GPL-only helper, and
/// "GPL" here would mean the *userspace* daemon has to be GPL too, because the
/// two are linked together. We stay MIT precisely because nothing above uses a
/// GPL-only helper. If you add one -- `bpf_probe_write_user`, a kprobe, most
/// `bpf_override_return` users -- this must change to "Dual MIT/GPL" and the
/// project licence has to be revisited with it.
#[link_section = "license"]
#[no_mangle]
static LICENSE: &[u8] = b"MIT\0";