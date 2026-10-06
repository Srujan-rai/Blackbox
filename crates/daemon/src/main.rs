//! blackboxd: collects sched_switch events via BPF ring buffer, polls PSI for
//! pressure-triggered dumps, and writes self-describing dump files.
//!
//! The IPC half is a line-delimited JSON protocol over a Unix socket: one
//! request per connection, one response, then close. Requests are rare (a human
//! asking for status or a dump), so per-connection setup beats keeping a
//! connection table, and a crashed client cannot leave the daemon holding state.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use blackbox_core::config::Config;
use blackbox_core::history::HistoryRing;
use blackbox_core::ipc::{DumpResult, Request, Response, StatusInfo};
use blackbox_core::psi::PressureMonitor;
use blackboxd::runtime::Runtime;
use clap::Parser;

#[derive(Parser)]
#[command(name = "blackboxd", version, about = "Blackbox daemon")]
struct Cli {
    /// Path to the config file. A missing file at the default location means
    /// defaults; a malformed one is a startup failure.
    #[arg(long, default_value = "/etc/blackbox/config.toml")]
    config: PathBuf,
}

const PID_PATH: &str = "/run/blackbox/blackboxd.pid";

fn handle_client(
    stream: UnixStream,
    runtime: &mut Runtime,
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
        Request::Status => Response::Status(StatusInfo {
            running: true,
            pid: Some(std::process::id()),
            uptime_secs: runtime.uptime_secs(),
            events_recorded: runtime.history().len() as u64,
            events_evicted: runtime.history().evicted(),
            events_dropped_kernel: runtime.kernel_drops(),
            last_trigger_reason: runtime.last_trigger_reason().clone(),
            last_trigger_time: runtime.last_trigger_time(),
            socket: socket_path.to_string(),
            dump_dir: runtime.config().dump.dir.to_string_lossy().to_string(),
            config_path: config_path.to_string(),
        }),
        Request::Dump { output } => {
            let path = runtime.dump_to(output.as_deref().map(Path::new))?;
            Response::Dump(DumpResult {
                success: true,
                path: Some(path.to_string_lossy().to_string()),
                message: "manual dump completed".to_string(),
            })
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

    let history = HistoryRing::new(config.history.max_events, config.history.max_seconds);
    let monitor = PressureMonitor::new(config.pressure.triggers.expand());
    let mut runtime = Runtime::new(history, monitor, config);

    let (listener, socket_path) = bind_socket()?;

    // PID file, best-effort: writing it needs a writable /run, which a
    // non-root run does not have. Ignoring the failure keeps the daemon
    // usable in both cases.
    if let Some(parent) = Path::new(PID_PATH).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(PID_PATH, format!("{}", std::process::id()));

    eprintln!("blackboxd listening on {socket_path}");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let _ = handle_client(
                    stream,
                    &mut runtime,
                    &socket_path,
                    &cli.config.to_string_lossy(),
                );
            }
            Err(_) => break,
        }
    }
    let _ = fs::remove_file(PID_PATH);

    Ok(())
}
