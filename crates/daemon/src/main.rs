//! blackboxd: collects sched_switch events via BPF ring buffer, polls PSI for
//! pressure-triggered dumps, and writes self-describing dump files.
//!
//! Three threads share one `Runtime` behind a std mutex: the IPC loop (this
//! thread), the BPF collector, and the PSI poller. Locks are held only for
//! short, self-contained critical sections — a batch push, a status copy, a
//! dump write — so serving status never waits on a ring buffer drain.
//!
//! The IPC half is a line-delimited JSON protocol over a Unix socket: one
//! request per connection, one response, then close. Requests are rare (a human
//! asking for status or a dump), so per-connection setup beats keeping a
//! connection table, and a crashed client cannot leave the daemon holding state.
//!
//! Failure posture: the daemon prefers to keep serving over dying. A config
//! file it cannot accept is fatal (that is an operator mistake worth stopping
//! for); anything about the environment — no BPF object, no privileges, no
//! PSI — is reported loudly, surfaced as `bpf_attached: false` plus a reason
//! in `blackbox status`, and the daemon continues in degraded mode.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::Context;
use blackbox_core::config::{Config, BPF_OBJECT_ENV};
use blackbox_core::history::HistoryRing;
use blackbox_core::ipc::{DumpResult, Request, Response, StatusInfo};
use blackbox_core::psi::PressureMonitor;
use blackboxd::collect::{
    lock_runtime, request_stop, run_collector, run_triggers, stop_requested, SharedRuntime,
};
use blackboxd::runtime::Runtime;
use clap::Parser;
use nix::errno::Errno;
use nix::poll::{poll, PollFd, PollFlags};
use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};

#[derive(Parser)]
#[command(name = "blackboxd", version, about = "Blackbox daemon")]
struct Cli {
    /// Path to the config file. A missing file at the default location means
    /// defaults; a malformed one is a startup failure.
    #[arg(long, default_value = "/etc/blackbox/config.toml")]
    config: PathBuf,

    /// Skip BPF collection entirely (IPC and PSI only).
    ///
    /// The daemon also degrades to this on its own when the program cannot be
    /// loaded; this flag just makes it intentional. Either way `blackbox
    /// status` reports `bpf_attached: false` with the reason.
    #[arg(long)]
    no_bpf: bool,
}

const PID_PATH: &str = "/run/blackbox/blackboxd.pid";

/// How long the control-socket poll waits before re-checking the stop flag.
/// Also the shutdown latency bound for the IPC thread.
const ACCEPT_POLL_MS: u16 = 250;

/// How long a client gets to send its one-line request. One-line requests
/// answer in microseconds; a stalled client must not pin the IPC thread.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

fn handle_client(
    stream: UnixStream,
    runtime: &SharedRuntime,
    socket_path: &str,
    config_path: &str,
) -> anyhow::Result<()> {
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return Ok(());
    }
    let req: Request = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(_) => return Ok(()),
    };

    let resp = match req {
        Request::Status => {
            // Lock only long enough to copy the readout out; the socket write
            // below can block on a slow client and must not hold the runtime.
            let rt = lock_runtime(runtime);
            Response::Status(StatusInfo {
                running: true,
                pid: Some(std::process::id()),
                uptime_secs: rt.uptime_secs(),
                events_recorded: rt.history().len() as u64,
                events_evicted: rt.history().evicted(),
                // Not measured: aya's ring buffer API does not expose
                // kernel-side drop counts to userspace (the failure is
                // returned to the BPF program, which discards it), and an
                // honest zero beats an invented number.
                events_dropped_kernel: rt.kernel_drops(),
                last_trigger_reason: rt.last_trigger_reason().clone(),
                last_trigger_time: rt.last_trigger_time(),
                socket: socket_path.to_string(),
                dump_dir: rt.config().dump.dir.to_string_lossy().to_string(),
                config_path: config_path.to_string(),
                bpf_attached: rt.bpf_attached(),
                bpf_error: rt.bpf_error().clone(),
            })
        }
        Request::Dump { output } => {
            // The whole dump (snapshot, serialise, write, retention) runs
            // under one lock: dumps are rare, and splitting Runtime to
            // shorten the hold would cost more correctness than it buys.
            // Status requests queue behind it; they do not fail.
            match lock_runtime(runtime).dump_to(output.as_deref().map(Path::new)) {
                Ok(path) => Response::Dump(DumpResult {
                    success: true,
                    path: Some(path.to_string_lossy().to_string()),
                    message: "manual dump completed".to_string(),
                }),
                // Report the failure over the socket: dropping the connection
                // instead would leave the CLI staring at an EOF with no cause.
                Err(err) => Response::Dump(DumpResult {
                    success: false,
                    path: None,
                    message: format!("dump failed: {err:#}"),
                }),
            }
        }
    };

    let mut stream = stream;
    let data = serde_json::to_string(&resp)?;
    stream.write_all(data.as_bytes())?;
    stream.write_all(b"\n")?;
    Ok(())
}

/// Bind the control socket, trying each known location in turn.
///
/// `/run` needs root, and a developer run does not have it, so failure to bind
/// the preferred path falls through to the next rather than aborting. The path
/// that actually worked is what every later status line reports.
fn bind_socket() -> anyhow::Result<(UnixListener, String)> {
    for path in blackbox_core::DEFAULT_SOCKET_PATHS.iter() {
        if let Some(parent) = Path::new(path).parent() {
            let _ = fs::create_dir_all(parent);
        }
        // A socket file left by a crashed daemon would make bind fail forever.
        let _ = fs::remove_file(path);
        if let Ok(listener) = UnixListener::bind(path) {
            return Ok((listener, (*path).to_string()));
        }
    }
    Err(anyhow::anyhow!(
        "failed to bind any of {:?}",
        blackbox_core::DEFAULT_SOCKET_PATHS
    ))
}

/// Resolve which BPF object to load, from config then environment.
///
/// Failure comes back as the operator-facing message — the same text goes to
/// the log and into `bpf_error` on the status reply.
fn resolve_bpf_object(runtime: &SharedRuntime) -> Result<PathBuf, String> {
    let env_object = std::env::var_os(BPF_OBJECT_ENV).map(PathBuf::from);
    let rt = lock_runtime(runtime);
    rt.config()
        .bpf
        .resolve_object(env_object.as_deref())
        .map_err(|err| err.to_string())
}

/// Install SIGINT/SIGTERM handlers that flip the shared stop flag.
///
/// `SA_RESTART` so a signal never tears a syscall out from under a worker:
/// every loop re-checks the stop flag on its own timer anyway (the kernel
/// never restarts `poll` regardless — signals surface there as EINTR, which
/// the loops handle — and the PSI thread sleeps in slices), and the
/// control-socket read has its own timeout. No shutdown path depends on
/// EINTR arriving at the right moment.
fn install_signal_handlers() -> anyhow::Result<()> {
    let action = SigAction::new(
        SigHandler::Handler(on_signal),
        SaFlags::SA_RESTART,
        SigSet::empty(),
    );
    // SAFETY: `on_signal` performs a single atomic store, which is
    // async-signal-safe by construction, and the returned previous action is
    // an owned value we discard without dereferencing anything.
    #[allow(unsafe_code)]
    unsafe {
        sigaction(Signal::SIGINT, &action)?;
        sigaction(Signal::SIGTERM, &action)?;
    }
    Ok(())
}

/// Signal handler body: only the stop-flag store may run here — no locks, no
/// allocation, no I/O.
extern "C" fn on_signal(_sig: std::os::raw::c_int) {
    request_stop();
}

/// Spawn a named worker thread. Names show up in `ps`/`/proc`, which is the
/// cheapest way to tell the two loops apart when something hangs.
fn spawn_worker(
    name: &str,
    body: impl FnOnce() + Send + 'static,
) -> anyhow::Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name(name.to_string())
        .spawn(body)
        .with_context(|| format!("spawning {name} thread"))
}

/// Serve the control socket until the stop flag is set or accept fails.
///
/// `poll` with a timeout instead of a blocking accept: SIGINT/SIGTERM only
/// flip a flag, and a thread parked in `accept(2)` would never observe it.
/// The timeout doubles as the IPC thread's shutdown latency bound.
fn serve(listener: &UnixListener, runtime: &SharedRuntime, socket_path: &str, config_path: &str) {
    loop {
        if stop_requested() {
            return;
        }
        // Scoped: the `PollFd` borrows the listener, and `accept` below needs
        // its own borrow, so the two must not coexist.
        let ready = {
            let mut fds = [PollFd::new(listener.as_fd(), PollFlags::POLLIN)];
            poll(&mut fds, ACCEPT_POLL_MS)
        };
        match ready {
            // The signal handler ran somewhere; loop and re-check the flag.
            Err(Errno::EINTR) => continue,
            Err(err) => {
                eprintln!("blackboxd: control socket poll failed: {err}");
                return;
            }
            Ok(0) => continue, // timeout
            Ok(_) => {}
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_read_timeout(Some(REQUEST_TIMEOUT));
                if let Err(err) = handle_client(stream, runtime, socket_path, config_path) {
                    // Dump failures are already reported over the socket;
                    // what is left here is a client that disconnected
                    // mid-response, which is their business, not ours.
                    eprintln!("blackboxd: request failed: {err:#}");
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => {
                eprintln!("blackboxd: accept on the control socket failed: {err}");
                return;
            }
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // A missing config at the default path is normal (usable with no config);
    // a config that exists but cannot be read or parsed is a real failure and
    // must not be silently replaced by defaults.
    let config = if cli.config.exists() {
        Config::load(&cli.config)?
    } else {
        Config::default()
    };
    config.validate()?;

    install_signal_handlers()?;

    let history = HistoryRing::new(config.history.max_events, config.history.max_seconds);
    let monitor = PressureMonitor::new(config.pressure.triggers.expand());
    let runtime: SharedRuntime = Arc::new(Mutex::new(Runtime::new(history, monitor, config)));

    let (listener, socket_path) = bind_socket()?;

    // Workers start before the PID file: if a spawn fails, what remains is at
    // most a stale socket (the next start removes it before binding) and no
    // PID file advertising a daemon that is not running.
    let mut workers = Vec::new();
    if cli.no_bpf {
        // Deliberate degraded mode: no resolution attempt, status says why.
        lock_runtime(&runtime)
            .set_bpf_status(false, Some("collection disabled by --no-bpf".to_string()));
    } else {
        match resolve_bpf_object(&runtime) {
            Ok(object) => {
                let runtime_for_worker = runtime.clone();
                workers.push(spawn_worker("bpf-collector", move || {
                    run_collector(runtime_for_worker, object)
                })?);
            }
            // Environment problem, not a config problem: log it, record it for
            // `blackbox status`, and keep serving IPC and PSI. Dying here
            // would leave the operator with nothing to ask.
            Err(reason) => {
                eprintln!("blackboxd: {reason}");
                lock_runtime(&runtime).set_bpf_status(false, Some(reason));
            }
        }
    }
    let runtime_for_psi = runtime.clone();
    workers.push(spawn_worker("trigger-poller", move || {
        run_triggers(runtime_for_psi)
    })?);

    // PID file, best-effort: writing it needs a writable /run, which a
    // non-root run does not have. Ignoring the failure keeps the daemon
    // usable in both cases.
    if let Some(parent) = Path::new(PID_PATH).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(PID_PATH, format!("{}", std::process::id()));

    eprintln!("blackboxd listening on {socket_path}");

    serve(
        &listener,
        &runtime,
        &socket_path,
        &cli.config.to_string_lossy(),
    );

    // Shutdown: signal the workers, then join. Both loops re-check the stop
    // flag within ~250ms (collector and IPC poll timeouts; the trigger thread
    // sleeps in slices), so these joins are bounded in practice. The collector
    // dropping its `Ebpf` handle is what detaches the tracepoint.
    request_stop();
    for worker in workers {
        let _ = worker.join();
    }
    let _ = fs::remove_file(&socket_path);
    let _ = fs::remove_file(PID_PATH);
    eprintln!("blackboxd: stopped (control socket and PID file removed)");
    Ok(())
}
