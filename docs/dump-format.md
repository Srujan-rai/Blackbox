# Dump format

Dumps are native JSON with `schema_version: 2` (v1 traces still load). They
are self-describing, so a trace from last week is still interpretable without
the machine it came from.

| Field | Contents |
|---|---|
| `trigger` | `reason` (`manual`, `psi_cpu`, `psi_memory`, `psi_io`, `oom`) and a human-readable `detail` |
| `window` | monotonic and wall-clock endpoints, span, and `truncated` when a cap was hit |
| `overhead` | `events_recorded`, `events_evicted` (the window's own backpressure), `events_dropped_kernel`, `lifecycle_recorded`, `lifecycle_evicted`, `lifecycle_dropped_kernel` |
| `host` | hostname, kernel release, boot id, uptime at dump time |
| `clock_offset_ns` | `CLOCK_REALTIME - CLOCK_MONOTONIC`; add it to an event timestamp for wall-clock time |
| `events` | the `sched_switch` records, with raw monotonic ns timestamps |
| `lifecycle` | fork/exec/exit events with `kind`, `pid`, `peer_pid`, optional `value` (exit priority), `comm` and `name` (child comm on fork, executed path on exec). New in schema 2 |

## Reading `prev_state`

Each event carries the kernel's raw `prev_state` for the outgoing task:

| Value | Meaning | Reported as |
|---|---|---|
| has bit `0x100` (`TASK_REPORT_MAX`, ftrace `R+`) | involuntarily preempted | scheduler delay |
| `0` | still runnable, yielded | scheduler delay |
| anything else (`1` S, `2` D, `0x80` idle kthread, ...) | blocked | blocked time |

pid `0` is the per-CPU idle task. It runs on every CPU at once, so reports
count it as idle time instead of as a consumer or a delay.

## Completeness

`blackbox report` validates the schema and event ordering before rendering.

Kernel-side ring-buffer drops are counted by the BPF program itself (a per-CPU
`DROPS` map, since aya's ring-buffer API does not expose overflows). A report
with kernel drops says so loudly: totals in it are lower bounds. An object
built before the `DROPS` map existed still loads, and its drops read `0`.
