# Configuration

`blackboxd` reads `/etc/blackbox/config.toml` (override with `--config PATH`).
An annotated copy lives in [`examples/config.toml`](../examples/config.toml).

- A **missing** file at the default path means defaults.
- A **malformed** file is a startup error.
- **Unknown keys are rejected**, so a typo never becomes a silent default.

## Full reference

```toml
[history]
max_events  = 250000      # hard cap on retained events (~16 MB at 64 B each)
max_seconds = 30          # cap on the window's width

[pressure]
poll_interval_ms = 250
cpu    = { enabled = true, threshold_pct = 80.0, consecutive = 4 }
memory = { enabled = true, threshold_pct = 20.0, consecutive = 4 }
io     = { enabled = true, threshold_pct = 20.0, consecutive = 4 }
oom    = { enabled = true }

[dump]
dir               = "/var/lib/blackbox/dumps"
keep_last         = 10    # keep the newest N dumps; omit for unlimited
timestamped_names = true

[bpf]
# object_path = "/usr/local/lib/blackbox/blackbox-bpf.o"
# filter_pids = [1234, 5678]   # trace only these pids (max 32); empty = all

[ipc]
# restrict_mutations = true    # (default) dump/stop need the daemon owner or root;
#                              # status is always open. false = any local user.
```

## Triggers

`consecutive` is the hysteresis: a trigger needs N samples over its threshold
before it fires, and after firing it re-arms only once the reading drops back
below the threshold. A sustained stall produces one dump, not one per sample.

`oom` has no threshold or window: any advance of the kernel's `oom_kill`
counter in `/proc/vmstat` fires it. The first reading after startup only sets
the baseline, so a kill that happened before the daemon started never fires.

## History window

The retained trace is `min(max_events / event_rate, max_seconds)` wide. At
500k switches/s the default cap holds only ~0.5 s, which is exactly when you
need the trace most. Raise `max_events` (memory grows at 64 B per event) or
cut ingest with `filter_pids`; `max_seconds` only widens already-quiet
windows.

## Finding the BPF object

The object is located by, in order:

1. `[bpf].object_path` (a missing file here is a startup error)
2. the `BLACKBOX_BPF_OBJECT` environment variable
3. `/usr/local/lib/blackbox/blackbox-bpf.o`
4. `/usr/lib/blackbox/blackbox-bpf.o`
5. `./blackbox-bpf.o`

If nothing is found, the daemon logs why, reports `bpf_attached: false` in
`blackbox status`, and keeps serving status and trigger dumps.

## PID filter

`[bpf].filter_pids` (up to 32 pids; empty = every process) is written into the
kernel-side `FILTER` map before any tracepoint attaches.

- A `sched_switch` record is kept when **either** side of the switch is listed.
- A lifecycle event is kept when its subject is listed.
- The filter is fixed for the daemon's lifetime; restart to change it.
- pid `0` (the idle task) is rejected: it sits on one side of most switches
  and would quietly turn the filter back into machine-wide tracing.

The tracepoints still fire either way. What the filter removes is the ingest,
decode and history cost, which is most of the daemon's CPU (see
[overhead.md](overhead.md)).

## Dumps on disk

- Written atomically (temporary file, then rename or link): an interrupted
  write never leaves a truncated trace.
- Files in the dump directory are mode `0600`. If the directory cannot be
  created (typically a non-root run against `/var/lib`), dumps fall back to
  `/tmp`.
- `blackbox dump -o PATH` writes exactly there (mode `0644`). The CLI resolves
  a relative `PATH` against your working directory, and only root or the
  daemon's owner may choose a path.
- Retention (`keep_last`) only ever deletes `blackbox.json` and
  `blackbox-*.json`, never other files in the directory.
