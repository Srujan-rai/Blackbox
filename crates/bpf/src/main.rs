//! The BPF half of blackbox: observe `sched_switch`, publish to a ring buffer.
//!
//! Deliberately minimal. Everything hard -- reconstructing intervals, ranking
//! consumers, deciding whether a trace is complete -- happens in
//! `blackbox-core` in userspace, because logic here costs verifier budget and
//! runtime on every context switch on the machine.
//!
//! On licensing: reading the tracepoint context goes through
//! [`TracePointContext::read_at`], which lowers to `bpf_probe_read`. That
//! helper is GPL-only -- the kernel refuses to load a program that calls it
//! unless the program declares a GPL-compatible licence -- so this object is
//! declared `Dual MIT/GPL`. That is not the same as the daemon being GPL: the
//! object is dual licensed (you may still take it under MIT), and every
//! userspace crate here stays MIT. The GPL option exists only to satisfy the
//! kernel's helper rule.
//!
//! Reading the context with direct field loads would keep the object MIT, but
//! Rust/LLVM does not fold the field offset into the load for a `PTR_TO_CTX`
//! access: it emits `r2 = r1; r2 += offset; ld*(r2)`, which the verifier
//! rejects as "dereference of modified ctx ptr". `read_at` is therefore
//! required, not merely convenient.

#![no_std]
#![no_main]

use aya_ebpf::helpers::gen::bpf_ktime_get_ns;
use aya_ebpf::macros::{map, tracepoint};
use aya_ebpf::maps::RingBuf;
use aya_ebpf::programs::TracePointContext;

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
    // The context is the whole trace event record, common header included, so
    // these offsets match
    //   /sys/kernel/tracing/events/sched/sched_switch/format
    // (the same file trace-cmd and libbpf read):
    //   common_type/flags/preempt_count/pid    0..8
    //   prev_comm[16]                            8
    //   prev_pid (u32)                          24
    //   prev_prio (i32, unused)                 28
    //   prev_state (i64)                        32
    //   next_comm[16]                           40
    //   next_pid (u32; next_prio follows)       56
    //
    // `read_at` fails only if the record is shorter than the ABI promises,
    // which should not happen; bail out rather than trace on a layout we do
    // not understand. These are `match`es and not `.unwrap()`s deliberately:
    // unwrap's panic path drags panic subprograms into the object, and aya
    // appends them after the program's final `exit`, which the verifier
    // rejects with "last insn is not an exit or jmp".
    let prev_comm: [u8; 16] = match unsafe { ctx.read_at(8) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let prev_pid: u32 = match unsafe { ctx.read_at(24) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let prev_state: i64 = match unsafe { ctx.read_at(32) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let next_comm: [u8; 16] = match unsafe { ctx.read_at(40) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let next_pid: u32 = match unsafe { ctx.read_at(56) } {
        Ok(v) => v,
        Err(_) => return 0,
    };

    let ev = SchedSwitch {
        ts_ns: unsafe { bpf_ktime_get_ns() },
        prev_state,
        prev_pid,
        next_pid,
        // Not in the tracepoint payload. On-CPU intervals cannot be rebuilt
        // per-CPU without it, so it is cheaper to stamp it here than to keep
        // coherent per-CPU state in a map.
        cpu: unsafe { aya_ebpf::helpers::bpf_get_smp_processor_id() },
        prev_comm,
        next_comm,
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
/// `Dual MIT/GPL`, not plain MIT: `read_at` (above) calls `bpf_probe_read`,
/// which the kernel only permits for GPL-compatible programs. Dual licensing
/// keeps the source available under MIT while giving the kernel the GPL option
/// it demands. It does **not** make the userspace daemon GPL -- the BPF object
/// is an independent program, not linked into `blackboxd`.
///
/// The value type must be the bytes, not a `&[u8]`. `#[link_section]` puts the
/// *static's value* in the section, and a `&[u8]` is a fat pointer (address +
/// length), so a slice would emit pointer bytes that aya reads back as the
/// licence string and rejects ("invalid license"). A fixed-size array emits the
/// literal bytes instead.
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
