# Overhead

Blackbox is a tracer, so the fair question is not "is it free" — nothing that
reads every context switch is free — but **what does it cost, and does that cost
scale with the thing being traced?**

This document is the answer for **v0.2** (with the process-lifecycle tracepoints
attached), measured with a harness you can run yourself
([`scripts/bench.sh`](../scripts/bench.sh)). The short version:

- **Cost scales with the context-switch rate, not with CPU load.** Blackbox only
  runs on `sched_switch`, so a compute-bound workload is essentially untouched,
  while a workload that does nothing *but* switch is slowed proportionally to the
  per-event cost.
- **The daemon used ≈ 0.6 of one core** while tracing a switch-heavy workload on
  this 8-core host — about 2.7 µs of daemon CPU per event ingested.
- **The lifecycle tracepoints changed none of it**: adding fork/exec/exit moved
  the daemon's CPU figure by noise (0.63 vs 0.60 core). They fire so rarely
  compared to context switches that their whole cost fits in the run-to-run
  jitter of this host.
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

Measured with `REPS=7`, `ROUNDS=200000` (each `switch` rep is 400 000 context
switches). The host is shared, so percentage deltas swing from run to run; the
range we have seen for `switch` across runs is **+26 % to +63 %**. The daemon-CPU
figure is the stable one.

### `switch` — context-switch heavy (the case that matters)

| | baseline | traced | change |
|---|---|---|---|
| best (min) | 790.01 ms | 1009.83 ms | **+27.8 %** |
| median | 849.40 ms | 1069.55 ms | **+25.9 %** |

Daemon CPU: **4870 ms over 7.73 s wall = 63.0 % of one core.**

Per switch: 400 000 switches per rep, so the added latency is
`(1009.83 − 790.01) ms / 400 000 ≈ **0.55 µs/switch**` on this run (earlier runs
measured up to ~1.7 µs; see the note above about host contention). The daemon's
own CPU works out to `4870 ms / (7 × 400 000) ≈ **1.7 µs per event**`, including
host events it also had to ingest.

### `cpu` — compute-bound (control)

| | baseline | traced | change |
|---|---|---|---|
| best (min) | 591.72 ms | 602.46 ms | +1.8 % |
| median | 598.83 ms | 610.13 ms | +1.9 % |

Daemon CPU: **2750 ms over 4.29 s wall = 64.1 % of one core.**

Blackbox executes **nothing** on a pure compute loop, so a *clean* run should
show ≈0 %. The small residual here is CPU contention — the daemon is consuming
~0.6 core on a machine that is already busy. This host cannot produce clean
microbenchmarks, which is why the daemon's CPU figure is the number we trust
most.

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
daemon CPU from **1.6 cores to 0.6 cores** and the measured overhead on
`switch` from **+102 %** to the +26–63 % band seen since.

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
- **The PID filter is the lever for high-switch hosts** (v0.2). The lifecycle
  tracepoints added in v0.2 do not change the unfiltered picture — they fire so
  rarely that their cost is unmeasurable here. What *does* change it is
  `[bpf].filter_pids`:
  - **Filtered to a pid that never appears, the daemon's CPU dropped from 63 %
    of one core to 0.15 %**, and the measured workload cost from +26–41 % to
    **+1.5–4.7 %** (same `switch` harness, `FILTER_PIDS=999999`).
  - The residual is the tracepoint itself: it fires on every switch no matter
    what, and blackbox's program adds one array-map read (slot 0) to each.
    What the filter removes is the ring-buffer write, the userspace decode and
    the history window — which is where the bulk of the daemon's CPU went.
  - It is a **pid** filter: coarse, fixed at startup, and only useful when you
    know which processes you care about. cgroup scoping and sampling remain the
    obvious next levers and are still absent (see
    [Limitations](../README.md#limitations)).

## Reproduce it

```sh
cargo build --release
sudo scripts/bench.sh                       # 200k rounds, 5 reps per phase
sudo ROUNDS=500000 REPS=7 scripts/bench.sh  # tighter
sudo SCENARIO=cpu scripts/bench.sh          # the control
sudo FILTER_PIDS=999999 scripts/bench.sh    # the filter mitigation
```

`bench.sh` refuses to run if a `blackboxd` is already up, so the baseline is
genuinely untraced. See the header of the script for every environment override
(`BIN_DIR`, `REPS`, `ROUNDS`, `SCENARIO`, `PIN_BENCH`, `PIN_DAEMON`,
`FILTER_PIDS`, …).
