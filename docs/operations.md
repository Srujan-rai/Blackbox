# Operations

Practical notes for running `blackboxd` on a real machine.

## Privileges

Loading and attaching the BPF program is the only privileged operation.

- Simplest: run as **root** (`sudo blackbox start`, or the systemd unit).
- Least privilege: run with **`CAP_BPF` + `CAP_PERFMON`** (Linux 5.8+). The
  daemon needs read access to tracefs as well.
- Reading PSI (`/proc/pressure`) and generating reports need **no** privileges.

`blackbox status` says `bpf collection: attached` when collection is live, or
`NOT attached` with a reason. A permissions problem and a missing object file
produce different reasons, so the message tells you which one you have.

## Placement of the BPF object

The daemon looks for the object in this order:

1. `[bpf].object_path` in the config — a path set here that does not exist is a
   **startup error**;
2. the `BLACKBOX_BPF_OBJECT` environment variable;
3. `/usr/local/lib/blackbox/blackbox-bpf.o`
4. `/usr/lib/blackbox/blackbox-bpf.o`
5. `./blackbox-bpf.o` (handy when running from the repo)

A *search* that finds nothing is not fatal: the daemon logs it, reports
`bpf_attached: false`, and keeps serving manual and trigger (PSI/OOM) dumps.

## Tuning the window

The retained window is `min(max_seconds, max_events)`. At roughly 500k
events/second on an 8-CPU host, the default 250 000 events is only about half a
second. If you need a longer window on a busy machine, raise `max_events`
(each event is a 64-byte record plus queue overhead — 1M events is on the order
of tens of MB). `overhead.events_evicted` in a dump tells you how much was
thrown away to honour the cap.

## Trigger tuning

Each PSI trigger has a `threshold_pct` and a `consecutive` count. A trigger
fires only after the reading stays over threshold for `consecutive` samples in a
row, and re-arms only once the reading falls back below threshold. If you see no
PSI dumps, either nothing crossed the threshold or `keep_last` retention has
already rotated the old ones out — `blackbox status` shows the last trigger.

The OOM trigger is different: it is a discrete event, so it has no
`threshold_pct`/`consecutive`. The daemon watches the `oom_kill` counter in
`/proc/vmstat` and dumps the poll after it advances, reporting how many kills
happened in the burst. Disable it with `oom = { enabled = false }` under
`[pressure]`. The first reading after startup only establishes a baseline, so a
kill that happened before the daemon started is deliberately not reported.

Dumps land in `dump.dir`. With `timestamped_names = true` the filename carries a
millisecond timestamp, so several dumps in the same second do not overwrite each
other. `keep_last = N` prunes to the newest N dumps.

## Reading a dump

```sh
blackbox report incident.json                 # human-readable summary
blackbox report incident.json --per-cpu       # per-CPU breakdown
blackbox report incident.json --top 20        # longer consumer list
blackbox report incident.json --perfetto > incident.perfetto.json
```

The report's `process lifecycle` section lists fork/exec/exit events observed in
the window (most recent first), with the executed path for `exec` events. Dumps
of schema 2 include the `lifecycle` array; dumps written by an older build
(schema 1) load fine and simply have no lifecycle events. With
`[bpf].filter_pids` set, the daemon only records lifecycle events whose subject
is in the list (a fork matches on parent *or* child), and `blackbox status`
prints `scope N pid(s)` so a filtered daemon cannot be mistaken for a
machine-wide one.

Open the Perfetto file by dragging it onto <https://ui.perfetto.dev/>.
Lifecycle events appear there as instant markers on each process's track.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `bpf_attached: false`, reason mentions privileges | Not root and missing `CAP_BPF`/`CAP_PERFMON`. |
| `bpf_attached: false`, reason mentions the object | Object not found, or built for a different kernel/BTF. Rebuild with `./crates/bpf/build.sh release`. |
| `bpf_attached: true`, `events retained 0` | Nothing is switching on the visible tasks, or the very first batch has not landed yet. If `status` shows `scope N pid(s)`, only events involving those pids are retained — a quiet or absent process explains an empty window instantly. |
| No lifecycle events in a dump | Expected when the window contains no forks/execs/exits; the section only renders when there is at least one. |
| A lifecycle tracepoint is not attached | Extremely rare; the daemon logs which one and keeps collecting `sched_switch`. Check the daemon log. |
| Window much shorter than `max_seconds` | `max_events` is the binding cap; raise it. |
| `kernel drops` shows `0` | Expected: aya does not expose ring-buffer drop counts, so the field is always zero today. Do not read it as proof of completeness — use `events_evicted` and `window.truncated` instead. |
| `blackbox status` says the daemon is unreachable | Check the socket path it lists; a non-root daemon falls back to `/tmp/blackboxd.sock`. |

## Shutdown

`SIGINT`/`SIGTERM` stop both worker threads within a few hundred milliseconds
and remove the socket and PID file. The systemd unit uses `Restart=on-failure`,
so a clean stop stays stopped.
