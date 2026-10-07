#!/usr/bin/env bash
#
# A reproducible end-to-end demo of blackbox.
#
# It starts the daemon, generates a short burst of scheduler activity, takes a
# dump, and renders both the text report and the Perfetto export. Run it and
# watch; nothing is left behind.
#
# Needs root (or CAP_BPF+CAP_PERFMON) because blackboxd loads a BPF program.
#
# Usage:
#   sudo scripts/demo.sh
#   sudo BIN_DIR=target/release scripts/demo.sh
set -euo pipefail

BIN_DIR=${BIN_DIR:-target/release}
BLACKBOX=${BLACKBOX:-$BIN_DIR/blackbox}
BLACKBOXD=${BLACKBOXD:-$BIN_DIR/blackboxd}

say() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
die() { echo "demo: $*" >&2; exit 1; }

[ -x "$BLACKBOXD" ] || die "daemon binary not found at $BLACKBOXD (run: cargo build --release)"
[ -x "$BLACKBOX" ] || die "cli binary not found at $BLACKBOX"
[ "$(id -u)" -eq 0 ] || die "must run as root (blackbox needs CAP_BPF/CAP_PERFMON)"

if "$BLACKBOX" status >/dev/null 2>&1; then
  die "a blackboxd is already running; stop it first so the demo controls its own daemon"
fi

WORK=$(mktemp -d)
OUT=${OUT:-$WORK}
DAEMON_PID=""
cleanup() {
  if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill -TERM "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

say "build check"
"$BLACKBOX" --version
"$BLACKBOXD" --help >/dev/null

say "starting blackboxd"
mkdir -p "$WORK/dumps"
cat > "$WORK/config.toml" <<EOF
[dump]
dir = "$WORK/dumps"
keep_last = 5
EOF
"$BLACKBOXD" --config "$WORK/config.toml" >"$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 50); do
  "$BLACKBOX" status 2>/dev/null | grep -qE '^bpf collection +attached$' && break
  sleep 0.2
done
"$BLACKBOX" status | grep -qE '^bpf collection +attached$' || {
  echo "--- daemon log ---" >&2; cat "$WORK/daemon.log" >&2
  die "BPF program did not attach"
}
echo "daemon is collecting (pid $DAEMON_PID)"

say "generating scheduler activity"
# More runnable work than CPUs: forces queueing, so real scheduler delays show
# up in the "longest scheduler delays" section below. Short-lived processes add
# plenty of switches.
seq 1 24 | xargs -P 24 -n 1 sh -c 'i=0; while [ $i -lt 4000 ]; do i=$((i+1)); done' &
LOAD_PID=$!
seq 1 2000 | xargs -P 16 -n 1 /bin/true
wait "$LOAD_PID" || true
echo "load done"

say "status while running"
"$BLACKBOX" status

say "taking a dump"
DUMP="$OUT/incident.json"
"$BLACKBOX" dump -o "$DUMP"
ls -l "$DUMP"

say "text report"
"$BLACKBOX" report "$DUMP" --top 10

say "perfetto export"
PERFETTO="$OUT/incident.perfetto.json"
"$BLACKBOX" report "$DUMP" --perfetto > "$PERFETTO"
echo "wrote $PERFETTO ($(wc -c < "$PERFETTO") bytes)"
head -c 160 "$PERFETTO"; echo "…"
echo "open it at https://ui.perfetto.dev/ (drag the file in)"

say "stopping daemon"
kill -TERM "$DAEMON_PID"
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""
echo "daemon stopped"

say "artifacts"
echo "  dump:    $DUMP"
echo "  perfetto:$PERFETTO"
echo "  (working dir $WORK kept; delete it when done)"
