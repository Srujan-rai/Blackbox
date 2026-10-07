//! The BPF half of blackbox: observe `sched_switch` and process lifecycle
//! (fork/exec/exit), and publish to two ring buffers.
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
use aya_ebpf::helpers::{bpf_get_current_comm, bpf_probe_read_kernel_str_bytes};
use aya_ebpf::macros::{map, tracepoint};
use aya_ebpf::maps::RingBuf;
use aya_ebpf::programs::TracePointContext;
use aya_ebpf::EbpfContext;

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

/// Lifecycle ring buffer (fork/exec/exit). Far smaller than `EVENTS`: these
/// events are rare compared to context switches, and 512 KiB absorbs any burst
/// (a fork bomb) while the daemon drains.
const LIFECYCLE_BYTES: u32 = 1 << 19;

#[map]
static LIFECYCLE: RingBuf = RingBuf::with_byte_size(LIFECYCLE_BYTES, 0);

/// Wire `kind` values, mirrored in blackbox_core::lifecycle.
pub const KIND_FORK: u32 = 0;
pub const KIND_EXEC: u32 = 1;
pub const KIND_EXIT: u32 = 2;

/// The record written for every lifecycle event. Must stay byte-identical to
/// blackbox_core::lifecycle::LifecycleRecord (64 bytes, offsets below).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Lifecycle {
    pub ts_ns: u64,
    pub value: i64,
    pub kind: u32,
    pub pid: u32,
    pub peer_pid: u32,
    pub _pad: u32,
    pub comm: [u8; 16],
    pub name: [u8; 16],
}

const _: () = assert!(core::mem::size_of::<Lifecycle>() == 64);

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

/// Try to publish a lifecycle record. Failure (kernel-side ring full) drops it;
/// same reasoning as `EVENTS.output`.
fn emit_lifecycle(ev: &Lifecycle) {
    let _ = LIFECYCLE.output(ev, 0);
}

/// Copy a tracepoint `__data_loc` string (the low 16 bits hold the byte offset
/// from the start of the record) into a capped NUL-terminated buffer.
///
/// The string lives in the trace entry itself — kernel memory — so the kernel
/// string reader is the right helper. A bogus offset (e.g. the field was
/// zeroed or the record is from an unexpected layout) yields an empty name
/// rather than a dropped event: the process identity is in `pid` either way.
fn read_data_loc_name(ctx: &TracePointContext, loc: u32) -> [u8; 16] {
    let mut name = [0u8; 16];
    let off = (loc & 0xffff) as usize;
    if off == 0 {
        return name;
    }
    let src = unsafe { (ctx.as_ptr() as *const u8).add(off) };
    let _ = unsafe { bpf_probe_read_kernel_str_bytes(src, &mut name) };
    // bpf_probe_read_kernel_str_bytes NUL-terminates within `name` on success;
    // a failure leaves zeros. Force the final byte so the buffer always ends.
    name[15] = 0;
    name
}

/// `fork` — a new task was created. Offsets match
/// /sys/kernel/tracing/events/sched/sched_process_fork/format:
///   common header                    0..8
///   parent_comm[16]                   8
///   parent_pid (pid_t)               24
///   child_comm[16]                   28
///   child_pid (pid_t)                44
#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    let parent_comm: [u8; 16] = match unsafe { ctx.read_at(8) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let parent_pid: u32 = match unsafe { ctx.read_at(24) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let child_comm: [u8; 16] = match unsafe { ctx.read_at(28) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let child_pid: u32 = match unsafe { ctx.read_at(44) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    emit_lifecycle(&Lifecycle {
        ts_ns: unsafe { bpf_ktime_get_ns() },
        value: 0,
        kind: KIND_FORK,
        pid: parent_pid,
        peer_pid: child_pid,
        _pad: 0,
        comm: parent_comm,
        name: child_comm,
    });
    0
}

/// `exec` — a process replaced its image. Offsets match
/// /sys/kernel/tracing/events/sched/sched_process_exec/format:
///   common header                    0..8
///   filename (__data_loc)            8
///   pid (pid_t)                     12
///   old_pid (pid_t)                 16
#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    let filename_loc: u32 = match unsafe { ctx.read_at(8) } {
        Ok(v) => v,
        Err(_) => 0,
    };
    let pid: u32 = match unsafe { ctx.read_at(12) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let old_pid: u32 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => [0u8; 16],
    };
    emit_lifecycle(&Lifecycle {
        ts_ns: unsafe { bpf_ktime_get_ns() },
        value: 0,
        kind: KIND_EXEC,
        pid,
        peer_pid: old_pid,
        _pad: 0,
        comm,
        name: read_data_loc_name(&ctx, filename_loc),
    });
    0
}

/// `exit` — a task is exiting. Offsets match
/// /sys/kernel/tracing/events/sched/sched_process_exit/format:
///   common header                    0..8
///   comm[16]                         8
///   pid (pid_t)                     24
///   prio (int)                      28
#[tracepoint]
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    let comm: [u8; 16] = match unsafe { ctx.read_at(8) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let pid: u32 = match unsafe { ctx.read_at(24) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let prio: i32 = match unsafe { ctx.read_at(28) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    emit_lifecycle(&Lifecycle {
        ts_ns: unsafe { bpf_ktime_get_ns() },
        value: prio as i64,
        kind: KIND_EXIT,
        pid,
        peer_pid: 0,
        _pad: 0,
        comm,
        name: [0u8; 16],
    });
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
