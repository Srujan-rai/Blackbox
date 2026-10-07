//! A tiny, dependency-free workload for measuring blackbox's overhead.
//!
//! Two scenarios, deliberately different:
//!
//! * `switch` hammers the scheduler. Two threads ping-pong over rendezvous
//!   channels, so every round trip blocks the sender until the peer receives;
//!   the kernel schedules both threads over and over. This is the worst case
//!   for a `sched_switch` tracer, and the case the overhead number is about.
//! * `cpu` is a pure userspace hot loop, as a control. Blackbox only runs on
//!   context switches, so its cost here should be indistinguishable from zero.
//!
//! Output is one line of `key=value` pairs, so `scripts/bench.sh` can parse it
//! without pulling in a JSON dependency. Exit code 2 means bad usage.

use std::env;
use std::process;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

fn main() {
    let mut args = env::args().skip(1);
    let scenario = args.next().unwrap_or_else(|| "switch".to_string());
    let rounds: u64 = match args.next() {
        Some(raw) => match raw.parse() {
            Ok(v) => v,
            Err(_) => {
                eprintln!("blackbox-bench: rounds must be an integer, got {raw:?}");
                process::exit(2);
            }
        },
        None => 200_000,
    };

    match scenario.as_str() {
        "switch" => switch_bench(rounds),
        "cpu" => cpu_bench(rounds),
        other => {
            eprintln!("blackbox-bench: unknown scenario {other:?} (want `switch` or `cpu`)");
            process::exit(2);
        }
    }
}

/// Two threads ping-pong over rendezvous channels.
///
/// `sync_channel(0)` is a rendezvous: a send blocks until the peer receives,
/// so each of the two sends per round forces the scheduler to run the other
/// side. That is roughly two context switches per round on a multi-core box.
fn switch_bench(rounds: u64) {
    let (main_tx, worker_rx) = mpsc::sync_channel::<u64>(0);
    let (worker_tx, main_rx) = mpsc::sync_channel::<u64>(0);

    let worker = thread::spawn(move || {
        // Receive until the main side hangs up.
        while let Ok(received) = worker_rx.recv() {
            if worker_tx.send(received).is_err() {
                break;
            }
        }
    });

    let start = Instant::now();
    for round in 0..rounds {
        if main_tx.send(round).is_err() || main_rx.recv().is_err() {
            break;
        }
    }
    let elapsed = start.elapsed();

    drop(main_tx); // hang up; the worker sees the channel close and exits
    let _ = worker.join();

    let switches = rounds.saturating_mul(2);
    let secs = elapsed.as_secs_f64();
    let nanos = elapsed.as_nanos() as f64;
    println!(
        "scenario=switch rounds={rounds} switches={switches} elapsed_ns={} ns_per_switch={:.1} switches_per_sec={:.0}",
        elapsed.as_nanos(),
        if switches > 0 {
            nanos / switches as f64
        } else {
            0.0
        },
        if secs > 0.0 {
            switches as f64 / secs
        } else {
            0.0
        },
    );
}

/// A pure userspace integer workload, as a control.
///
/// `checksum` is printed so the optimiser cannot delete the loop.
fn cpu_bench(rounds: u64) {
    let start = Instant::now();
    let mut acc: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut ops: u64 = 0;
    for _ in 0..rounds {
        // xorshift + multiply: cheap, branch-light, no allocation.
        for _ in 0..1000 {
            acc ^= acc << 13;
            acc ^= acc >> 7;
            acc ^= acc << 17;
            acc = acc.wrapping_mul(0x2545_f491_4f6c_dd1d);
            ops += 1;
        }
    }
    let elapsed = start.elapsed();
    let secs = elapsed.as_secs_f64();
    println!(
        "scenario=cpu rounds={rounds} ops={ops} elapsed_ns={} ops_per_sec={:.0} checksum={acc}",
        elapsed.as_nanos(),
        if secs > 0.0 { ops as f64 / secs } else { 0.0 },
    );
}
