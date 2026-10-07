# Architecture

Blackbox is three pieces with one job each:

| Piece | Runs as | Responsibility |
|---|---|---|
| `blackbox-bpf` | kernel (BPF) | Observe `sched_switch`, stamp a CPU id, copy a fixed 64-byte record into a ring buffer. Nothing else. |
| `blackboxd` | userspace daemon | Drain the ring buffer into a bounded history window, poll PSI, answer the control socket, write dumps. |
| `blackbox-core` | library | All analysis and formatting: interval reconstruction, PSI hysteresis, dump schema, reports. |

The split is deliberate: everything hard and everything testable lives in
`blackbox-core`, which needs no privileges and runs in unit tests. The BPF
program only does what has to happen on every context switch.

## Why the history window is in userspace

A BPF ring buffer is a **transport**, not storage. It overwrites the oldest
unread records and cannot answer "what happened 20 seconds ago". If the daemon
is not draining it, old events are simply lost.

So the "last N seconds" window is a bounded `VecDeque<SchedSwitch>` in
`blackbox-core`, continuously refilled by the collector thread and capped two
ways:

- `history.max_events` — a hard memory cap, and
- `history.max_seconds` — a width cap.

The retained window is the **smaller** of the two. On a quiet machine the time
cap wins; on a busy one the event cap does. A dump records which cap was hit
(`window.truncated`) and how many events were evicted (`overhead.events_evicted`).

The honest consequence: **history exists only while `blackboxd` is running.**
There is no on-disk history, and a crash loses the window.

```
   sched_switch                    ringbuf (8 MB)              VecDeque (bounded)
   ─────────────  ──output()──►   ─────────────  ──drain──►  ──────────────────► dump
   per context switch              transport only              the actual history
```

## Threads

`blackboxd` runs three threads sharing one `Runtime` behind a `std::sync::Mutex`.

1. **IPC thread** (main) — accepts one connection at a time, reads one
   line-delimited JSON request, sends one response, closes. Requests are rare
   (a human typing `status` or `dump`), so a connection table would be pure
   overhead and a crashed client could otherwise leave daemon state behind.
2. **Collector thread** — waits on the ring buffer with a bounded timeout,
   drains a batch, decodes each record with `SchedSwitch::from_bytes`, and
   pushes it into the history. Records are decoded with `offset_of!`-derived
   offsets and bounds-checked copies, so a short or corrupt record is dropped
   rather than misread.
3. **PSI poller thread** — reads `/proc/pressure/{cpu,memory,io}` every
   `pressure.poll_interval_ms`, feeds a `PressureMonitor`, and asks the runtime
   to write a dump when a trigger fires.

Every critical section is short (a batch push, a status copy, a dump write), so
`status` never waits behind a ring-buffer drain. Both workers re-check a
process-wide stop flag each iteration, so `SIGINT`/`SIGTERM` shutdown is bounded
to a few hundred milliseconds without interrupting a syscall mid-work.

## Failure posture

The daemon prefers to keep serving over dying:

- **A bad config file is fatal.** That is an operator mistake worth stopping
  for, and unknown keys are rejected so a typo never becomes a silent default.
- **A bad environment is not.** Missing object, no privileges, no BTF, no PSI —
  each is logged loudly and surfaced in `blackbox status`
  (`bpf_attached: false` plus a reason). Manual dumps and PSI-triggered dumps
  still work, and a daemon quietly collecting nothing is exactly the failure the
  status field exists to make impossible to miss.

## On-CPU interval reconstruction

The tracepoint gives a stream of switches:

```
… prev_comm/pid/state ──► next_comm/pid …      on CPU c, at time t
```

A task is *on CPU* on `c` from the switch that made it `next` until the switch
that makes it `prev`. Consecutive records are paired per CPU to produce those
intervals; the `prev_state` on the closing record says why the task left:

- `prev_state == 0` — still runnable, so this is **scheduler delay**: the task
  wanted the CPU and did not get it.
- anything else — the task **blocked** (sleep, I/O, …), which is *not* a
  scheduling problem and is reported separately.

This is why the CPU id is stamped in BPF: it is not in the tracepoint payload,
and intervals cannot be rebuilt per CPU without it.

## Wire format

The BPF struct and `blackbox_core::event::SchedSwitch` must stay byte-identical.
The BPF crate asserts `size_of::<SchedSwitch>() == 64` at compile time; the
userspace decoder rejects any record whose length is not exactly 64 rather than
padding or truncating, because a short record would silently misparse every
following field.

The tracepoint record itself includes the kernel's 8-byte `trace_entry` common
header, so payload offsets are `prev_comm` 8, `prev_pid` 24, `prev_state` 32,
`next_comm` 40, `next_pid` 56 — taken from
`/sys/kernel/tracing/events/sched/sched_switch/format`. Reading the wrong offset
is silent (wrong names, wrong pids), which is why the BPF crate documents the
source of those numbers and they are checked in review.
