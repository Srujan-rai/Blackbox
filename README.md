# Blackbox

A minimal, low-overhead scheduler recorder that dumps a trace on pressure stalls.

**blackbox** captures `sched_switch` events with BPF, keeps a short rolling window of history in userspace, polls PSI for pressure thresholds (CPU, memory, I/O), and writes a self-describing trace when a stall is detected. Traces can be converted to Perfetto's Chrome JSON format for visualisation, or summarised as plain text.

## Design

The key design decision is the split between kernel transport and userspace analysis:

- **BPF (kernel)**: A single tracepoint on `sched/sched_switch` writes fixed-size records into a ring buffer. The CPU is stamped in-kernel via `bpf_get_smp_processor_id()` because the tracepoint payload does not include it. Only tracepoints are used (no kprobes) to keep the project MIT-licensed.
- **Userspace daemon (`blackboxd`)**: Drains the ring buffer continuously into a bounded history window (count + duration caps). Since BPF ring buffers cannot retain history across drops, the "last N seconds" window exists only while the daemon is running.
- **PSI triggers**: Pressure Stall Information is polled from `/proc/pressure/*` with hysteresis (trigger requires N consecutive samples above threshold, and rearms only after pressure recedes). No BPF is used for PSI.
- **Core analysis (`blackbox-core`)**: On-CPU intervals are reconstructed from the switch stream per-CPU, distinguishing preemption while runnable (scheduler latency) from time blocked on I/O/sleep. All logic is pure Rust and unit-testable without privileges.
- **Exports**: Dumps are stored as native JSON with full metadata (trigger reason, host identity, overhead counters including kernel-side drops). The CLI can convert a dump to Chrome JSON for [ui.perfetto.dev](https://ui.perfetto.dev/).

## MVP Scope (v0.1)

- `sched_switch` collection only
- PSI-based triggers (CPU/memory/IO) with hysteresis
- Bounded history ring (count and time caps)
- Dump on trigger + manual `blackbox dump`
- Text report and Perfetto Chrome JSON export via `blackbox report`
- MIT license, CO-RE-friendly (requires BTF), tracepoints only

## Building

### Prerequisites

- Rust (stable for workspace; BPF crate uses nightly for `-Z build-std=core`)
- [`bpf-linker`](https://github.com/aya-rs/bpf-linker) on `PATH` (prebuilt static binary is recommended)

### Build

```bash
# Build BPF object first (uses nightly)
./crates/bpf/build.sh release

# Build all binaries and libraries
cargo build --release
```

The BPF object will be built with `.BTF` and `.BTF.ext` sections (required for Aya/CO-RE). The build script fails fast if BTF is missing.

## Usage

### CLI

```bash
# Generate a report from a dump
blackbox report trace.bb.json

# Export as Perfetto Chrome JSON
blackbox report trace.bb.json --perfetto > trace.perfetto.json

# View at https://ui.perfetto.dev/
```

The CLI also exposes `start`, `status`, and `dump` subcommands (daemon/runtime scaffolding is in place; full daemon loop to be extended as needed).

## Dump Schema

Dumps are native JSON with a `schema_version`. Key fields:

- `trigger`: reason and human-readable detail (e.g. PSI threshold description)
- `window`: monotonic and wall-clock endpoints, span, `truncated` flag if window hit caps
- `overhead`: `events_recorded`, `events_evicted` (userspace history drops), `events_dropped_kernel` (BPF ringbuf drops)
- `host`: hostname, kernel release, boot_id, uptime
- `events`: array of serialised `sched_switch` events (monotonic ns timestamps)

The file format is lossless and self-describing; `blackbox report` validates schema and ordering before processing.

## Notes & Caveats

- **History only while running**: A stall that kills `blackboxd` itself will produce a short or empty dump. This is inherent to userspace history over a BPF ring buffer.
- **Kernel requirements**: Linux 5.15+ recommended (ringbuf + BTF + PSI). PSI is required for the default triggers.
- **Privileges**: Loading BPF programs requires `CAP_BPF`/`CAP_PERFMON` or root. The daemon is designed to run with minimal privileges where possible; PSI reads are from `/proc` with no special caps.
- **No cmdline capture**: Only the 15-character kernel `comm` is recorded (no `argv`), avoiding accidental capture of secrets in v0.1.
- **MIT license**: Tracepoints only. Do not substitute kprobes without re-evaluating licensing (GPL-only helpers would change this).
- **CO-RE**: The BPF object carries BTF, so one binary should work across compatible kernels.

## Testing

```bash
# Run all core unit tests (no privileges required)
cargo test -p blackbox-core
```

102 tests covering PSI parsing, hysteresis, on-CPU reconstruction, history ring, Perfetto export, report formatting, dump validation, and config.

## Contributing

Changes to the analysis logic belong in `blackbox-core` (pure, testable). BPF changes go in `crates/bpf`. Keep unsafe to a minimum and add unit tests for any new analysis paths.
