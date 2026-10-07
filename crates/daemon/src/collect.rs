//! The two worker threads: BPF ring buffer drain and PSI polling.
//!
//! Both loops are built the same way on purpose: they wait on something with
//! a bounded timeout (or sleep in short slices) and re-check the process-wide
//! stop flag each time round, so SIGINT/SIGTERM shutdown is bounded to a few
//! hundred milliseconds without ever interrupting a syscall mid-work.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use blackbox_core::event::SchedSwitch;
use blackbox_core::psi;
use nix::errno::Errno;
use nix::poll::{poll, PollFd, PollFlags};
use std::os::fd::AsFd;

use crate::bpf::{describe_failure, load_and_attach};
use crate::runtime::Runtime;

/// What the IPC thread and both workers share.
///
/// A plain std mutex: every critical section here is short (a batch push, a
/// status read, a dump write) and std's is dependency-free, which matters
/// more than fairness for three threads.
pub type SharedRuntime = Arc<Mutex<Runtime>>;

/// Process-wide stop flag, flipped by the signal handler and by main during
/// shutdown.
///
/// A static rather than an `Arc` because the signal handler that sets it
/// cannot capture anything — one global is simpler than two mechanisms that
/// could disagree about whether shutdown has begun.
static STOP: AtomicBool = AtomicBool::new(false);

/// Ask every loop to finish. Idempotent; safe to call from anywhere.
pub fn request_stop() {
    STOP.store(true, Ordering::SeqCst);
}

pub fn stop_requested() -> bool {
    STOP.load(Ordering::SeqCst)
}

/// Take the runtime lock, tolerating poisoning.
///
/// Poison means some thread panicked mid-update. The fields served from here
/// (counters, history, status) are written one at a time, so the values stay
/// individually meaningful; serving a slightly-stale readout beats cascading
/// a panic and losing the daemon outright.
pub fn lock_runtime(runtime: &SharedRuntime) -> MutexGuard<'_, Runtime> {
    runtime.lock().unwrap_or_else(|e| e.into_inner())
}

/// How long each wait blocks before the stop flag is re-checked. This is
/// also the idle wakeup rate, so it stays small but need not be tiny.
const IDLE_POLL_MS: u16 = 250;

/// Events decoded before the runtime lock is taken to push them. Bounds how
/// long the collector can spend outside the lock (and how much it can hold)
/// even during a burst.
const MAX_BATCH: usize = 4096;

/// Load the BPF program, then drain the ring buffer into the history window
/// until the stop flag is set.
///
/// On any load/attach failure this returns after recording the reason on the
/// runtime — degraded mode, not a crash: status, manual dumps and PSI
/// triggers keep working, and `blackbox status` carries the explanation.
pub fn run_collector(runtime: SharedRuntime, object: PathBuf) {
    let (_ebpf, mut ringbuf) = match load_and_attach(&object) {
        Ok(loaded) => loaded,
        Err(err) => {
            let reason = describe_failure(&err, &object);
            eprintln!("blackboxd: {reason}");
            lock_runtime(&runtime).set_bpf_status(false, Some(reason));
            return;
        }
    };
    lock_runtime(&runtime).set_bpf_status(true, None);
    eprintln!(
        "blackboxd: collecting sched_switch events via {}",
        object.display()
    );

    // `_ebpf` is bound (not the bare `_` pattern, which would drop it
    // immediately): it owns the program's link, so it must live until this
    // function returns. Dropping it at the end of the scope is what detaches
    // the tracepoint — shutdown = detach.
    let mut collected: u64 = 0;
    let mut malformed: u64 = 0;

    while !stop_requested() {
        // Wait for data with a timeout so quiet systems still notice the stop
        // flag. aya's `RingBuf::next` is non-blocking with no blocking
        // variant, so poll(2) on the ring buffer's fd is the wait.
        // The `PollFd` is scoped: it borrows the ring buffer, and the drain
        // below needs a mutable borrow, so the two must not coexist.
        let ready = {
            let mut fds = [PollFd::new(ringbuf.as_fd(), PollFlags::POLLIN)];
            poll(&mut fds, IDLE_POLL_MS)
        };
        match ready {
            // A signal interrupted poll; the loop head re-checks the flag.
            Err(Errno::EINTR) => continue,
            Err(err) => {
                eprintln!("blackboxd: ring buffer poll failed: {err}; stopping collection");
                break;
            }
            // Ready or timed out — try draining either way; an empty ring
            // costs one position comparison.
            Ok(_) => {}
        }

        // Decode into a local batch first, then lock once to push it. The
        // lock is never held while reading the ring buffer, and never once
        // per event.
        let mut batch = Vec::with_capacity(1024);
        while batch.len() < MAX_BATCH {
            let Some(item) = ringbuf.next() else { break };
            match SchedSwitch::from_bytes(&item) {
                Some(event) => batch.push(event),
                None => {
                    malformed += 1;
                    if malformed == 1 {
                        // One loud warning, not one per record: the size
                        // cannot change mid-run, so the cause is a single
                        // stale object, not a stream of new problems.
                        eprintln!(
                            "blackboxd: ring buffer record of unexpected size discarded — \
                             {} may be a stale build (further discards only counted)",
                            object.display()
                        );
                    }
                }
            }
        }
        if batch.is_empty() {
            continue;
        }
        collected += batch.len() as u64;
        let mut rt = lock_runtime(&runtime);
        for event in batch {
            rt.history_mut().push(event);
        }
    }

    // `ebpf` and `ringbuf` drop here: detach, then close.
    eprintln!("blackboxd: collector stopped ({collected} events recorded, {malformed} malformed)");
}

/// Poll /proc/pressure on the configured interval and write a dump for every
/// trigger that fires, until the stop flag is set.
///
/// Hysteresis lives entirely in `PressureMonitor` (consecutive samples,
/// re-arm only after the pressure recedes); this loop adds no debouncing of
/// its own so the configured semantics are the only ones in effect.
pub fn run_psi(runtime: SharedRuntime) {
    // Read once: the config is immutable for the daemon's lifetime (no
    // reload), and holding the lock just for this would be pointless.
    let poll_interval_ms = {
        let rt = lock_runtime(&runtime);
        rt.config().pressure.poll_interval_ms
    };
    let poll_interval = Duration::from_millis(poll_interval_ms);
    eprintln!(
        "blackboxd: polling /proc/pressure every {}ms",
        poll_interval.as_millis()
    );

    // Remember the first failure so a persistent one logs once instead of
    // once per poll (250ms spam would bury everything else).
    let mut psi_broken: Option<String> = None;

    while !stop_requested() {
        match psi::read_snapshot(Path::new("/proc")) {
            Ok(snapshot) => {
                if let Some(previous) = psi_broken.take() {
                    eprintln!("blackboxd: PSI reads recovered (was failing: {previous})");
                }
                // Short lock for evaluation...
                let fired = lock_runtime(&runtime).observe_psi(&snapshot);
                if fired.is_empty() {
                    continue;
                }
                // ...then one lock per dump, so a status request only waits
                // for the dump being written right now, not all of them.
                for trigger in fired {
                    let mut rt = lock_runtime(&runtime);
                    match rt.write_psi_dump(&trigger) {
                        Ok(path) => eprintln!(
                            "blackboxd: PSI trigger {} fired, wrote {}",
                            trigger.reason(),
                            path.display()
                        ),
                        Err(err) => eprintln!(
                            "blackboxd: PSI trigger {} fired but the dump failed: {err:#}",
                            trigger.reason()
                        ),
                    }
                }
            }
            Err(err) => {
                if psi_broken.is_none() {
                    eprintln!(
                        "blackboxd: cannot read /proc/pressure, no pressure triggers until \
                         it recovers: {err}"
                    );
                }
                psi_broken = Some(err.to_string());
            }
        }
        sleep_until_stop(poll_interval);
    }
    eprintln!("blackboxd: PSI poller stopped");
}

/// Sleep for `total`, waking early only to check the stop flag.
///
/// Sliced rather than one sleep because a configured poll interval can be as
/// long as 10s, and shutdown should not inherit that latency.
fn sleep_until_stop(total: Duration) {
    let deadline = Instant::now() + total;
    while !stop_requested() {
        let now = Instant::now();
        if now >= deadline {
            return;
        }
        thread::sleep((deadline - now).min(Duration::from_millis(50)));
    }
}
