# Overhead

Blackbox is a tracer, so the fair question is not "is it free" — nothing that
reads every context switch is free — but **what does it cost, and does that cost
scale with the thing being traced?**

This document is the answer for v0.1, measured with a harness you can run
yourself ([`scripts/bench.sh`](../scripts/bench.sh)). The short version:

- **Cost scales with the context-switch rate, not with CPU load.** Blackbox only
  runs on `sched_switch`, so a compute-bound workload is essentially untouched,
  while a workload that does nothing *but* switch is slowed proportionally to the
  per-event cost.
- **The daemon used ≈ 0.6 of one core** while tracing a switch-heavy workload on
  this 8-core host — about 2.5 µs of daemon CPU per event, or ~1.5 µs added
  latency per switch seen by the workload.
- The benchmark found and fixed a real bug (see
  [A bug this benchmark found](#a-bug-this-benchmark-found)).

These are numbers from a **shared, busy developer workstation**, not a quiet
lab box. Treat the percentage deltas as indicative and the method as the
deliverable. Reproduce it on hardware you control for numbers you can quote.

## What we measured

Two scenarios from [`crates/bench`](../crates/bench), a tiny dependency-free
workload binary:

| Scenario | What it does | Why |
|---|---|---|
| `switch` | Two threads ping-pong over *rendezvous* channels, so every round trip forces the scheduler to run the peer (`≈2` context switches per round). | Worst case for a `sched_switch` tracer; isolates per-switch cost. |
| `cpu` | A pure userspace integer hot loop. | Control. Blackbox does not run on compute, so this should look untraced. |

For each scenario we run the workload `REPS` times **before** starting the
daemon (baseline) and `REPS` times **while it collects** (traced), on the same
machine, back to back. `scripts/bench.sh` reports the minimum and median, plus
how much CPU the daemon process itself consumed (from `/proc/<pid>/stat`
`utime+stime`), which is the one number here that is fairly stable run to run.

The daemon and the workload are pinned to disjoint core sets (`taskset`) to
reduce, though not remove, self-contention. Host processes still roam.

## Environment

| | |
|---|---|
| CPU | 11th Gen Intel Core i5-1135G7 @ 2.40 GHz, 8 logical CPUs |
| Kernel | 6.8.0-146-generic |
| Idle machine-wide switches | ~10.5k/s (from `/proc/stat` `ctxt`) |
| Build | `cargo build --release`; BPF via `crates/bpf/build.sh release` |
| Run | privileged Docker on the same kernel (`--privileged --pid=host`) |

`REPS=7`, `ROUNDS=200000`, so each `switch` rep is 400 000 context switches and
each `cpu` rep is 200 million inner operations.

## Results

### `switch` — context-switch heavy (the case that matters)

| | baseline | traced | change |
|---|---|---|---|
| best (min) | 991.70 ms | 1491.49 ms | **+50.4 %** |
| median | 1091.05 ms | 1781.67 ms | **+63.3 %** |

Daemon CPU: **7520 ms over 12.62 s wall = 59.6 % of one core.**

Per switch: 400 000 switches per rep, so the added latency is
`(1491.49 − 991.70) ms / 400 000 ≈ **1.25 µs/switch**` at best, `≈1.7 µs` at the
median. The daemon's own CPU works out to `7520 ms / (7 × 400 000) ≈ **2.7 µs
per event**`, including host events it also had to ingest.

### `cpu` — compute-bound (control)

| | baseline | traced | change |
|---|---|---|---|
| best (min) | 590.27 ms | 693.71 ms | +17.5 % |
| median | 629.95 ms | 706.70 ms | +12.2 % |

Daemon CPU: **3170 ms over 5.09 s wall = 62.3 % of one core.**

Blackbox executes **nothing** on a pure compute loop, so a *clean* run should
show ≈0 %. On this shared host the control still moved by double digits, which we
attribute to **CPU contention** — the daemon is consuming ~0.6 core on a machine
that is already busy — not to tracing the computation. It is a reminder that
this host cannot produce clean microbenchmarks, and it is why the daemon's CPU
figure is the number we trust most here.

### Before the fix (for contrast)

The first `switch` run, before the bug below was fixed, measured **+102 %** and
the daemon burning **161 % of one core** over the same window.

## A bug this benchmark found

The baseline/traced comparison is only interesting if the traced half is doing
something it shouldn't. It was: in the PSI polling loop, the common case
(no trigger fired) did a `continue`, which **skipped the sleep at the bottom of
the loop**:

```rust
let fired = lock_runtime(&runtime).observe_psi(&snapshot);
if fired.is_empty() {
    continue;            // <-- skipped sleep_until_stop(poll_interval)
}
```

So instead of sampling `/proc/pressure` every 250 ms, the poller spun as fast as
it could — re-reading pressure files and taking the shared runtime lock in a
tight loop, contending with the collector. The fix is to let an empty `fired`
fall through to the sleep (an empty `for` is a no-op). That single change cut
daemon CPU from **1.6 cores to 0.6 cores** and the measured overhead from
**+102 % to +50–63 %**.

This is exactly what an overhead benchmark is for, and it is why the harness
ships in the repo rather than a one-off number in a blog post.

## How to read these numbers

- **Tracing a busy machine is proportional to *machine-wide* switch rate**, not
  to your workload. `sched_switch` is global; a container cannot scope it
  (namespaces do not apply to tracepoints). On a 64-core box at millions of
  switches per second, expect several cores of daemon CPU.
- **Relative overhead depends on switch density.** A workload switching 400k
  times per second is slowed a lot; a workload switching 1k times per second
  while burning CPU is slowed ~not at all.
- **Tune the window, not the tracepoint.** The ingest cost is dominated by
  decoding and retaining events. Lower `[history].max_events` to shrink memory
  and the eviction churn; it does not reduce the per-event decode cost.
- **v0.1 has no filtering.** There is no cgroup/PID scoping and no sampling yet
  (see [Limitations](../README.md#limitations)); both are the obvious next
  levers for high-switch hosts.

## Reproduce it

```sh
cargo build --release
sudo scripts/bench.sh                       # 200k rounds, 5 reps per phase
sudo ROUNDS=500000 REPS=7 scripts/bench.sh  # tighter
sudo SCENARIO=cpu scripts/bench.sh          # the control
```

`bench.sh` refuses to run if a `blackboxd` is already up, so the baseline is
genuinely untraced. See the header of the script for every environment override
(`BIN_DIR`, `REPS`, `ROUNDS`, `SCENARIO`, `PIN_BENCH`, `PIN_DAEMON`, …).
