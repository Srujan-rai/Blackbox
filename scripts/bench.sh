#!/usr/bin/env bash
#
# Measure blackbox's overhead on a scheduler-heavy workload.
#
# The workload is `blackbox-bench switch`: two threads ping-ponging over
# rendezvous channels, which is the worst case for a `sched_switch` tracer.
# We run it N times with no daemon (baseline) and N times with blackboxd
# collecting (traced), then report the change in elapsed time and how much CPU
# the daemon itself burned.
#
# Needs root (or CAP_BPF+CAP_PERFMON) because it starts blackboxd for the
# traced half. It refuses to run if a daemon is already up, so the baseline is
# genuinely untraced.
#
# Usage:
#   sudo scripts/bench.sh                 # 200k rounds, 5 reps
#   sudo ROUNDS=500000 REPS=7 scripts/bench.sh
#
# Env overrides:
#   BIN_DIR   directory holding the built binaries (default: target/release)
#   BENCH / BLACKBOX / BLACKBOXD   explicit binary paths
#   SCENARIO  workload: `switch` (default) or `cpu` (the control)
#   ROUNDS    workload rounds per rep      (default: 200000)
#   REPS      repetitions per phase        (default: 5)
#   PIN_BENCH / PIN_DAEMON   CPU sets for the workload / daemon (needs taskset)
#   KEEP      where to copy the traced dump (default: ./blackbox-bench-traced.json)
set -euo pipefail

BIN_DIR=${BIN_DIR:-target/release}
BENCH=${BENCH:-$BIN_DIR/blackbox-bench}
BLACKBOX=${BLACKBOX:-$BIN_DIR/blackbox}
BLACKBOXD=${BLACKBOXD:-$BIN_DIR/blackboxd}
ROUNDS=${ROUNDS:-200000}
REPS=${REPS:-5}
SCENARIO=${SCENARIO:-switch}

die() { echo "bench: $*" >&2; exit 1; }

[ -x "$BENCH" ] || die "bench binary not found at $BENCH (run: cargo build --release)"
[ -x "$BLACKBOXD" ] || die "daemon binary not found at $BLACKBOXD"
[ -x "$BLACKBOX" ] || die "cli binary not found at $BLACKBOX"
[ "$(id -u)" -eq 0 ] || die "must run as root (blackbox needs CAP_BPF/CAP_PERFMON)"

# A daemon already running would contaminate the baseline.
if "$BLACKBOX" status >/dev/null 2>&1; then
  die "a blackboxd is already running; stop it first so the baseline is untraced"
fi

WORK=$(mktemp -d)
DAEMON_PID=""
cleanup() {
  if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill -TERM "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

CLK_TCK=$(getconf CLK_TCK)

# Optional CPU isolation: pin the benchmark and the daemon to disjoint core
# sets so they do not contend with each other (host tasks still roam, so this
# reduces noise rather than removing it). Only when taskset exists (util-linux).
PIN_BENCH=${PIN_BENCH:-0-1}
PIN_DAEMON=${PIN_DAEMON:-2-3}
HAVE_TASKSET=""
if command -v taskset >/dev/null 2>&1 && [ "$(nproc)" -ge 4 ]; then
  HAVE_TASKSET=1
fi
bench_cmd() {
  if [ -n "$HAVE_TASKSET" ]; then
    taskset -c "$PIN_BENCH" "$BENCH" "$@"
  else
    "$BENCH" "$@"
  fi
}

# utime+stime in clock ticks, robust to spaces in comm (which shifts awk fields).
read_ticks() {
  sed -E 's/^[0-9]+ \(.*\) //' "/proc/$1/stat" | awk '{print $12 + $13}'
}

# Median of the numbers on stdin.
median() {
  sort -n | awk '{a[NR]=$1} END{
    if (NR==0) { print "NA"; exit }
    m=int((NR+1)/2)
    if (NR%2) { print a[m] } else { printf "%.0f\n", (a[NR/2]+a[NR/2+1])/2 }
  }'
}

elapsed_ns() { sed -n 's/.*elapsed_ns=\([0-9]*\).*/\1/p'; }

echo "blackbox overhead benchmark"
echo "  workload      $SCENARIO, rounds=$ROUNDS"
echo "  reps          $REPS per phase"
echo "  cpus          $(nproc)"
echo

# ---------------------------------------------------------------------------
# Baseline: no daemon.
# ---------------------------------------------------------------------------
BASE_FILE=$(mktemp)
echo "baseline (no daemon)…"
for i in $(seq 1 "$REPS"); do
  ns=$(bench_cmd "$SCENARIO" "$ROUNDS" | elapsed_ns)
  echo "  rep $i: $ns ns"
  echo "$ns" >> "$BASE_FILE"
done
BASE_MED=$(median < "$BASE_FILE")
BASE_MIN=$(sort -n "$BASE_FILE" | head -1)

# ---------------------------------------------------------------------------
# Traced: start the daemon, wait until the BPF program is attached.
# ---------------------------------------------------------------------------
mkdir -p "$WORK/dumps"
cat > "$WORK/config.toml" <<EOF
[dump]
dir = "$WORK/dumps"
keep_last = 3
EOF

if [ -n "$HAVE_TASKSET" ]; then
  taskset -c "$PIN_DAEMON" "$BLACKBOXD" --config "$WORK/config.toml" >"$WORK/daemon.log" 2>&1 &
else
  "$BLACKBOXD" --config "$WORK/config.toml" >"$WORK/daemon.log" 2>&1 &
fi
DAEMON_PID=$!

attached=0
for _ in $(seq 1 50); do
  if "$BLACKBOX" status 2>/dev/null | grep -qE '^bpf collection +attached$'; then
    attached=1
    break
  fi
  sleep 0.2
done
[ "$attached" -eq 1 ] || {
  echo "--- daemon log ---" >&2
  cat "$WORK/daemon.log" >&2
  die "daemon did not attach its BPF program"
}
echo "daemon attached (pid $DAEMON_PID)"

TRACED_FILE=$(mktemp)
echo "traced (blackboxd collecting)…"
bench_cmd "$SCENARIO" "$((ROUNDS / 4))" >/dev/null   # warm up, not measured

TICKS_BEFORE=$(read_ticks "$DAEMON_PID")
WALL_START=$(date +%s.%N)
for i in $(seq 1 "$REPS"); do
  ns=$(bench_cmd "$SCENARIO" "$ROUNDS" | elapsed_ns)
  echo "  rep $i: $ns ns"
  echo "$ns" >> "$TRACED_FILE"
done
WALL_END=$(date +%s.%N)
TICKS_AFTER=$(read_ticks "$DAEMON_PID")
TRACED_MED=$(median < "$TRACED_FILE")
TRACED_MIN=$(sort -n "$TRACED_FILE" | head -1)

# Optional best-effort perf counter; not all environments allow it.
PERF_LINE=""
if command -v perf >/dev/null 2>&1; then
  if perf stat -e context-switches -x, bench_cmd "$((ROUNDS / 2))" >/dev/null 2>"$WORK/perf.err"; then
    n=$(grep -E '^[0-9,]+' "$WORK/perf.err" | head -1 | cut -d, -f1 | tr -d ' ')
    PERF_LINE="  perf context-switches (~$((ROUNDS / 2)) rounds): ${n:-?}"
  fi
fi

# A dump while still tracing, so the self-overhead report is available too.
DUMP="$WORK/dumps/traced.json"
"$BLACKBOX" dump -o "$DUMP" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# Report.
# ---------------------------------------------------------------------------
python3 - "$BASE_MED" "$TRACED_MED" "$BASE_MIN" "$TRACED_MIN" "$TICKS_BEFORE" "$TICKS_AFTER" "$WALL_START" "$WALL_END" "$CLK_TCK" <<'PY'
import sys
base, traced, bmin, tmin, tb, ta, ws, we, tick = (float(x) for x in sys.argv[1:10])
overhead = (traced - base) / base * 100.0 if base else 0.0
ohead_min = (tmin - bmin) / bmin * 100.0 if bmin else 0.0
wall = we - ws
cpu = (ta - tb) / tick
pct = (cpu / wall * 100.0) if wall > 0 else 0.0
print()
print("results")
print(f"  baseline         min {bmin/1e6:8.2f} ms   median {base/1e6:8.2f} ms")
print(f"  traced           min {tmin/1e6:8.2f} ms   median {traced/1e6:8.2f} ms")
print(f"  overhead         min {ohead_min:+8.2f} %   median {overhead:+8.2f} %")
print(f"  daemon CPU        {cpu*1000:8.1f} ms over {wall:.2f} s wall = {pct:.2f}% of one core")
PY
[ -n "$PERF_LINE" ] && echo "$PERF_LINE"
echo

if [ -s "$DUMP" ]; then
  echo "daemon self-overhead as seen by its own report (trace window):"
  "$BLACKBOX" report "$DUMP" --top 6 2>/dev/null | sed -n '/top cpu consumers/,/^$/p' | sed 's/^/  /'
fi

# Preserve the trace before cleanup removes the working directory.
KEEP=${KEEP:-$(pwd -P)/blackbox-bench-traced.json}
cp "$DUMP" "$KEEP" 2>/dev/null && echo "traced dump kept at $KEEP"
