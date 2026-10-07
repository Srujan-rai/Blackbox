# Blackbox

[![CI](https://github.com/Srujan-rai/Blackbox/actions/workflows/ci.yml/badge.svg)](https://github.com/Srujan-rai/Blackbox/actions/workflows/ci.yml)

**A low-overhead, post-mortem trace recorder for the Linux scheduler.**

Blackbox watches `sched_switch` with eBPF, keeps a rolling window of scheduling
history in userspace, and writes a self-describing trace the moment pressure
crosses a threshold (or when you ask). The trace opens in
[ui.perfetto.dev](https://ui.perfetto.dev/) or renders as a plain-text report.

> **Status:** v0.1 — the MVP described in [Scope](#scope). The BPF program has
> been loaded and verified end-to-end on a real kernel (see [Testing](#testing)).

---

## Why

When a machine stalls, the interesting thing is usually what happened in the
half-second *before* you noticed — which tasks were runnable and couldn't get a
CPU, who was holding it, what was stuck on I/O. By the time you attach `perf`,
the moment is gone. Blackbox is always running, so the history is already
there when the stall happens.

It is deliberately small: one tracepoint, one ring buffer, one bounded window,
a handful of triggers, and two export formats.

## Features

- **eBPF `sched_switch` capture** through a single tracepoint (no kprobes), via
  [aya](https://aya-rs.dev/) and CO-RE. One object runs across compatible
  kernels.
- **Bounded history window** — the last *N* seconds capped by both an event
  count and a duration, so memory use is predictable (default 250k events /
  30s).
- **PSI triggers** for CPU, memory and I/O pressure, polled from
  `/proc/pressure`, with **hysteresis**: a trigger must stay over threshold for
  a configurable number of consecutive samples and re-arms only once pressure
  actually recedes. No dump storms.
- **Native, lossless dumps** — JSON with a schema version, trigger reason,
  host identity, window bounds (monotonic *and* wall-clock), and self-overhead
  counters.
- **Perfetto export** — `blackbox report --perfetto` emits Chrome JSON that
  loads directly in [ui.perfetto.dev](https://ui.perfetto.dev/).
- **Text report** — top CPU consumers, longest scheduler delays (time a
  runnable task waited for a CPU), most blocked time, optional per-CPU
  breakdown.
- **Daemon + CLI over a Unix socket** — `start` / `status` / `dump`, with a
  `--foreground` mode for service managers.
- **Graceful degradation** — if the BPF program can't load (no object, no
  privileges, no BTF), the daemon keeps serving status, manual dumps and PSI
  triggers, and `blackbox status` says exactly why collection is off.
- **Clean shutdown** on `SIGINT`/`SIGTERM`, removing the socket and PID file.
- **Dump retention** — keep the newest *K* dumps, delete the rest.
- **systemd unit** and an annotated example config.
- **Reproducible demo and overhead benchmark** — [`scripts/demo.sh`](scripts/demo.sh)
  runs the whole flow end to end; [`scripts/bench.sh`](scripts/bench.sh) measures
  the daemon's cost on a scheduler-heavy workload (results in
  [`docs/overhead.md`](docs/overhead.md)).

## Scope

**In (v0.1):** `sched_switch` only; PSI (CPU/memory/IO) + manual triggers;
bounded history; native dump; text and Perfetto reports.

**Deliberately out (for now):** exec/exit/IO/OOM event sources, on-disk history
across daemon restarts, a GUI, remote shipping. See
[Limitations](#limitations) for the honest edges of what exists today.

## How it works

```
        kernel                                   userspace (blackboxd)
┌───────────────────────┐                ┌────────────────────────────────────┐
│ sched/sched_switch    │  8 MB          │  collector thread                  │
│ tracepoint ──► 64-byte│  ringbuf ────► │   decode ──► HistoryRing           │
│ record (no helper)    │                │              (last N s / max count)│
└───────────────────────┘                │                                    │
                                         │  PSI poller thread ──► trigger ──┐  │
        /proc/pressure  ────────────────►│   hysteresis in PressureMonitor  │  │
                                         │                                  ▼  │
                                         │  IPC thread (Unix socket) ──► write │
      blackbox CLI ──(status/dump)──────►│   status · manual dump · retention  │
                                         └────────────────────────────────────┘
```

Two design decisions matter:

1. **The ring buffer is transport only; history lives in userspace.** A BPF
   ring buffer cannot retain history — it overwrites with the newest events and
   drops the oldest unread ones. So the actual "last *N* seconds" window is a
   bounded `VecDeque` in `blackbox-core`, continuously refilled by the daemon.
   The consequence, stated plainly: **history exists only while `blackboxd` is
   running.**

2. **All the hard logic is in pure, testable Rust.** Interval reconstruction,
   ranking consumers, PSI hysteresis and report formatting live in
   `blackbox-core`, which runs without privileges. The BPF program only stamps
   a CPU id and copies a fixed record into the ring buffer.

On-CPU intervals are rebuilt per CPU from consecutive switches, using
`prev_state` to separate *scheduler latency* (a runnable task lost the CPU —
`prev_state == 0`) from *blocked time* (the task slept or waited on I/O).

## Overhead

Blackbox reads every `sched_switch`, so it is not free — its cost scales with
the **machine-wide** context-switch rate, not with CPU load. Measured on an
8-core host tracing a workload that does nothing but switch (400k switches per
run):

- the workload ran **~1.5×** slower (**+50–63 %**), i.e. **~1.5 µs added per
  switch** the workload caused;
- the daemon itself used **~0.6 of one core**;
- a **compute-bound** control was essentially untouched (blackbox runs no code
  on compute).

Writing that benchmark immediately found a real bug — a PSI poller that spun
because a `continue` skipped its sleep — and fixing it cut daemon CPU from 1.6
to 0.6 cores. Full method, raw numbers, caveats and the reproduction commands
are in [`docs/overhead.md`](docs/overhead.md).

## Requirements

- **Linux 5.15 or newer** (BPF ring buffer + BTF + PSI). CO-RE needs
  `/sys/kernel/btf/vmlinux`.
- **Privileges:** loading/attaching BPF needs `CAP_BPF` + `CAP_PERFMON`, or
  root. Reading PSI and running `blackbox report` need nothing special.
- **To build:** stable Rust (workspace) plus nightly + `rust-src` and a static
  [`bpf-linker`](https://github.com/aya-rs/bpf-linker) for the BPF crate.

## Install

### From a release

Download the tarball for your architecture from
[Releases](https://github.com/Srujan-rai/Blackbox/releases), verify it against
the attached `.sha256`, and install:

```sh
tar -xzf blackbox-<version>-x86_64-unknown-linux-gnu.tar.gz
cd blackbox-<version>-x86_64-unknown-linux-gnu
sudo install -m755 blackbox blackboxd /usr/local/bin/
sudo install -d /usr/local/lib/blackbox /etc/blackbox
sudo install -m644 blackbox-bpf.o /usr/local/lib/blackbox/
sudo install -m644 examples/config.toml /etc/blackbox/config.toml
```

### From source

```sh
# 1. BPF object (uses nightly + bpf-linker; installs ./blackbox-bpf.o)
./crates/bpf/build.sh release

# 2. CLI and daemon
cargo build --release
```

`build.sh` writes the object to `crates/bpf/target/.../blackbox-bpf` and copies
it to the repo root as `blackbox-bpf.o`, where the daemon looks by default. The
non-obvious build flags are explained in
[`crates/bpf/BUILD_NOTES.md`](crates/bpf/BUILD_NOTES.md).

## Quick start

```sh
# Start the daemon (detached; --foreground to stay in this terminal)
sudo blackbox start

# Is it collecting? Retained events, history evictions, kernel drops, last trigger
blackbox status

# Take a trace now
blackbox dump -o /tmp/incident.json

# Read it as text…
blackbox report /tmp/incident.json

# …or open it in Perfetto
blackbox report /tmp/incident.json --perfetto > /tmp/incident.perfetto.json
# then drag it onto https://ui.perfetto.dev/
```

A real `blackbox status` from a running daemon:

```
blackboxd status
  running         true
  pid             72205
  uptime          5s
  socket          /run/blackbox/blackboxd.sock
  dump dir        /var/lib/blackbox/dumps

bpf collection    attached

ring buffer
  events retained 250000
  history evicted 2152997
  kernel drops    0

last trigger      none yet
```

And the matching `blackbox report`:

```
blackbox trace
--------------
  trigger         manual
  window          0.512s
  host            b0a323c6f565 (6.8.0-146-generic)

completeness
------------
  events          250000
  on-cpu slices   249999
  kernel drops    0

top cpu consumers
-----------------
   63.72%       2.56s  pid 0        swapper/3
   10.91%     438.9ms  pid 72208    psi-poller
    6.38%     256.5ms  pid 72207    bpf-collector
    3.88%     155.9ms  pid 18589    gnome-terminal-
    3.34%     134.2ms  pid 17068    brave

longest scheduler delays
------------------------
  time a runnable task spent waiting for a cpu

       2.0ms  pid 0        swapper/3
       1.8ms  pid 69434    dav1d-worker
```

(Note `psi-poller` and `bpf-collector` in the ranking — that is the daemon
measuring itself.)

## CLI reference

| Command | Description |
|---|---|
| `blackbox start [--config PATH] [--foreground]` | Start the daemon (detached by default). |
| `blackbox status` | Show daemon health, collection state, ring-buffer counters and last trigger. |
| `blackbox dump [-o FILE]` | Trigger a manual dump (configured directory, or `-o`). |
| `blackbox report FILE [--perfetto] [--top N] [--per-cpu]` | Text report, or Perfetto Chrome JSON with `--perfetto`. |

The CLI talks to the daemon over a Unix socket, trying
`/run/blackbox/blackboxd.sock`, then `/var/run/...`, then `/tmp/blackboxd.sock`,
so a non-root development run works. The daemon runs the control socket, a
collector thread and a PSI-poller thread sharing one locked `Runtime`.

`blackboxd` itself takes `--config PATH` and `--no-bpf` (IPC + PSI only).

## Configuration

`/etc/blackbox/config.toml` (see [`examples/config.toml`](examples/config.toml)).
A missing file at the default path means defaults; a malformed one is a startup
error — and unknown keys are rejected, so a typo never becomes a silent
default.

```toml
[history]
max_events  = 250000      # hard cap on retained events (~16 MB)
max_seconds = 30          # cap on the window's width

[pressure]
poll_interval_ms = 250
cpu    = { enabled = true, threshold_pct = 80.0, consecutive = 4 }
memory = { enabled = true, threshold_pct = 20.0, consecutive = 4 }
io     = { enabled = true, threshold_pct = 20.0, consecutive = 4 }

[dump]
dir              = "/var/lib/blackbox/dumps"
keep_last        = 10     # keep the newest N dumps; omit for unlimited
timestamped_names = true

[bpf]
# object_path = "/usr/local/lib/blackbox/blackbox-bpf.o"
```

`consecutive` is the hysteresis: N samples over threshold before firing. After
firing, a trigger re-arms only once the reading drops back below the threshold.

The BPF object is located by, in order: `[bpf].object_path` (a missing file
here is a startup error), then `BLACKBOX_BPF_OBJECT`, then
`/usr/local/lib/blackbox/blackbox-bpf.o`, `/usr/lib/blackbox/blackbox-bpf.o`,
`./blackbox-bpf.o`. If the search finds nothing, the daemon logs why, reports
`bpf_attached: false` in `status`, and keeps serving.

## Dump format

Dumps are native JSON with `schema_version: 1`. They are self-describing, so a
trace from last week is still interpretable:

- `trigger` — `reason` (`manual`, `psi_cpu`, `psi_memory`, `psi_io`) and a
  human `detail`.
- `window` — monotonic and wall-clock endpoints, span, and `truncated` when a
  cap was hit.
- `overhead` — `events_recorded`, `events_evicted` (our window's own
  backpressure) and `events_dropped_kernel`.
- `host` — hostname, kernel release, boot id, uptime.
- `events` — the `sched_switch` records (monotonic ns timestamps).

`blackbox report` validates the schema and event ordering before rendering.
Kernel-side ring-buffer drops are **not currently observable** through aya's
API, so `events_dropped_kernel` is reported as `0`; it is not faked.

## systemd

[`contrib/blackboxd.service`](contrib/blackboxd.service) runs the daemon with
`RuntimeDirectory=blackbox` (so the socket and PID file have a place to live),
`Restart=on-failure`, and a conservative sandbox (`NoNewPrivileges`,
`ProtectSystem`, `ProtectHome`). Drop privileges by narrowing `User=` and the
capability set once your deployment's needs are known.

```sh
sudo install -m644 contrib/blackboxd.service /etc/systemd/system/
sudo install -m644 examples/config.toml /etc/blackbox/config.toml
sudo systemctl daemon-reload && sudo systemctl enable --now blackboxd
```

## Privileges, privacy and threat model

- **Least privilege.** Loading and attaching BPF is the only privileged act.
  The daemon can be run as root or with `CAP_BPF` + `CAP_PERFMON`; PSI reads
  and all report generation need no capabilities.
- **Privacy.** Blackbox records only what the kernel puts in the `sched_switch`
  tracepoint: the 15-character `comm`, PIDs, the previous task state, a
  timestamp and a CPU id. It does **not** capture command lines, arguments,
  environment variables, file paths or memory contents, so there is nothing
  sensitive to redact by default.
- **No network.** The daemon neither listens on nor dials a network socket; it
  speaks line-delimited JSON over a local Unix socket, one request per
  connection.
- **Self-describing honesty.** Dumps carry their own completeness counters, so
  a trace that lost events says so rather than looking authoritative.

## Limitations

- **History only while running.** A stall that kills `blackboxd` leaves a short
  or empty window. This is inherent to holding history in userspace over a BPF
  ring buffer.
- **A busy host shortens the window.** The retained window is the smaller of
  `max_seconds` and `max_events`; at ~500k events/s, 250k events is only ~0.5s.
  Raise `max_events` (memory permitting) for a longer window on busy machines.
- **Kernel drops read 0.** See above — not observable through aya today.
- **`comm` only.** The kernel name (15 chars), not the full command line.
- **Requires BTF** (`CONFIG_DEBUG_INFO_BTF`) for CO-RE.
- **Single event source.** Only `sched_switch` in v0.1.

## Testing

```sh
cargo test --workspace            # 142 tests, no privileges needed
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

The suite covers PSI parsing and hysteresis, on-CPU interval reconstruction,
the bounded ring, config validation, dump schema validation, retention, the
wire-record decoder, the IPC protocol and the text/Perfetto renderers.

The BPF path is validated on a real kernel in privileged Docker:

```sh
docker run --rm --privileged --pid=host \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/kernel/tracing:/sys/kernel/tracing:ro \
  -v "$PWD/target/release/blackboxd:/usr/local/bin/blackboxd:ro" \
  -v "$PWD/target/release/blackbox:/usr/local/bin/blackbox:ro" \
  -v "$PWD/blackbox-bpf.o:/opt/blackbox-bpf.o:ro" \
  -e BLACKBOX_BPF_OBJECT=/opt/blackbox-bpf.o \
  python:3.12-slim bash -c 'blackboxd & sleep 5; blackbox status; blackbox dump -o /tmp/t.json; blackbox report /tmp/t.json'
```

This is how the tracepoint offsets and the licence requirement below were
caught — neither is visible from unit tests.

Two scripts drive the same real kernel end to end (both need root):

```sh
sudo scripts/demo.sh    # start → load → status → dump → report → Perfetto
sudo scripts/bench.sh   # baseline vs traced overhead on a switch hammer
```

## Repository layout

```
crates/core     blackbox-core — pure analysis: events, history, PSI, dumps, reports
crates/daemon   blackboxd — BPF collector, PSI poller, IPC server
crates/cli      blackbox — start / status / dump / report
crates/bench    blackbox-bench — dependency-free workload for the overhead benchmark
crates/bpf      blackbox-bpf — the tracepoint program (excluded from the workspace)
scripts/        reproducible demo and overhead benchmark
examples/       annotated config
contrib/        systemd unit
docs/           design notes (architecture, operations, overhead)
```

CI (`.github/workflows/ci.yml`) runs fmt, clippy, tests and a BPF build on every
push and PR; `.github/workflows/release.yml` builds and publishes a tagged
release with binaries, the BPF object and a `.sha256`.

## License

The userspace crates (`core`, `daemon`, `cli`) are **MIT** — see
[`LICENSE`](LICENSE).

The BPF object (`crates/bpf`) is **dual MIT/GPL**. Reading the tracepoint
context uses `bpf_probe_read`, a GPL-only kernel helper, and the kernel refuses
to load a program that calls it unless the program declares a GPL-compatible
licence. Declaring `Dual MIT/GPL` keeps the source available under MIT and gives
the kernel the GPL option it requires; it does **not** make the userspace daemon
GPL, because the BPF object is a separate program, not linked into `blackboxd`.

Because `bpf_probe_read` is required, "tracepoints only" is not by itself enough
to avoid GPL-only helpers in Rust; `read_at` is the reason for the dual
licence. Swapping the tracepoint for a kprobe would not change this.
