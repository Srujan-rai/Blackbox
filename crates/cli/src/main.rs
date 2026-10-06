use anyhow::Result;
use blackbox_core::dump::Dump;
use blackbox_core::ipc::{Request, Response, StatusInfo, DEFAULT_SOCKET_PATHS};
use blackbox_core::perfetto::to_chrome_json;
use blackbox_core::report::{render_report_with, ReportOptions};
use clap::{Parser, Subcommand};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "blackbox", version, about = "Manage blackbox trace collection")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start the blackbox daemon
    Start {
        /// Path to config file
        #[arg(long, default_value = "/etc/blackbox/config.toml")]
        config: PathBuf,
        /// Run in this terminal instead of detaching
        #[arg(long)]
        foreground: bool,
    },
    /// Show daemon status
    Status,
    /// Trigger a manual dump
    Dump {
        /// Output file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Generate a report from a dump file
    Report {
        /// Dump file to analyze
        file: PathBuf,
        /// Emit Perfetto Chrome JSON instead of text
        #[arg(long)]
        perfetto: bool,
        /// Limit number of rows in tables
        #[arg(long, default_value_t = 10)]
        top: usize,
        /// Include per-CPU breakdown
        #[arg(long)]
        per_cpu: bool,
    },
}

/// Send one request to a running daemon, trying each known socket in turn.
fn send_request(req: &Request) -> Result<Response> {
    let mut errors = Vec::new();
    for path in DEFAULT_SOCKET_PATHS.iter() {
        match UnixStream::connect(path) {
            Ok(mut stream) => {
                let data = serde_json::to_string(req)?;
                stream.write_all(data.as_bytes())?;
                stream.write_all(b"\n")?;
                stream.shutdown(std::net::Shutdown::Write).ok();
                let mut buf = String::new();
                stream.read_to_string(&mut buf)?;
                return Ok(serde_json::from_str(&buf)?);
            }
            Err(e) => errors.push(format!("  {path}: {e}")),
        }
    }
    Err(anyhow::anyhow!(
        "blackboxd is not reachable on any socket:\n{}\n\
         start it with `blackbox start` (or check it with your service manager)",
        errors.join("\n")
    ))
}

/// Spawn blackboxd next to this binary, falling back to PATH.
fn daemon_command() -> Command {
    let sibling = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("blackboxd")));
    match sibling {
        Some(path) if path.exists() => Command::new(path),
        _ => Command::new("blackboxd"),
    }
}

/// Start the daemon and confirm it is accepting requests.
fn start(config: &Path, foreground: bool) -> Result<()> {
    let mut cmd = daemon_command();
    cmd.arg("--config").arg(config);

    if foreground {
        // Foreground: hand the terminal to the daemon so its logs and Ctrl-C
        // behave the way a service manager would give them.
        let status = cmd
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()?;
        return if status.success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("blackboxd exited with {status}"))
        };
    }

    use std::os::unix::process::CommandExt;
    // A detached daemon still needs somewhere to write its logs, since nobody
    // is holding its stderr. Prefer the system log directory and fall back to
    // /tmp the same way the socket binding does.
    let log_path = open_log()?;
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    let log_err = log.try_clone()?;
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .process_group(0)
        .spawn()?;

    // Detached children report their own fate through the socket: a daemon
    // that died on a bad config would otherwise look like a success here.
    let mut last_err = String::from("daemon did not answer");
    for _ in 0..50 {
        thread::sleep(Duration::from_millis(100));
        match send_request(&Request::Status) {
            Ok(Response::Status(info)) => {
                println!(
                    "blackboxd started (pid {}), listening on {}",
                    info.pid.map(|p| p.to_string()).unwrap_or_else(|| "?".into()),
                    info.socket
                );
                println!("  logs: {}", log_path.display());
                return Ok(());
            }
            Ok(Response::Error(e)) => last_err = e,
            Ok(_) => last_err = "unexpected response".into(),
            Err(e) => last_err = e.to_string(),
        }
        // The child may have exited already; do not wait the full 5s on it.
        if let Some(status) = child.try_wait()? {
            return Err(anyhow::anyhow!(
                "blackboxd exited immediately ({status}): {last_err}"
            ));
        }
    }
    Err(anyhow::anyhow!("blackboxd did not come up: {last_err}"))
}

/// Pick a writable log file for a detached daemon.
fn open_log() -> Result<PathBuf> {
    for dir in ["/var/log/blackbox", "/tmp"] {
        if fs::create_dir_all(dir).is_ok() {
            return Ok(PathBuf::from(dir).join("blackboxd.log"));
        }
    }
    Err(anyhow::anyhow!("no writable directory for daemon logs"))
}

fn print_status(info: StatusInfo) {
    println!("blackboxd status");
    println!("  running         {}", info.running);
    println!(
        "  pid             {}",
        info.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into())
    );
    println!(
        "  uptime          {}",
        info.uptime_secs
            .map(|s| format!("{s}s"))
            .unwrap_or_else(|| "-".into())
    );
    println!("  socket          {}", info.socket);
    println!("  config          {}", info.config_path);
    println!("  dump dir        {}", info.dump_dir);
    println!();
    println!("ring buffer");
    println!("  events retained {}", info.events_recorded);
    println!("  history evicted {}", info.events_evicted);
    if info.events_dropped_kernel > 0 {
        println!(
            "  kernel drops    {} (trace has holes; totals are lower bounds)",
            info.events_dropped_kernel
        );
    } else {
        println!("  kernel drops    0");
    }
    println!();
    match (&info.last_trigger_reason, info.last_trigger_time) {
        (Some(reason), Some(ts)) => println!("last trigger      {reason} at unix {ts}ns"),
        (Some(reason), None) => println!("last trigger      {reason}"),
        _ => println!("last trigger      none yet"),
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Start {
            config,
            foreground,
        } => start(&config, foreground)?,
        Cmd::Status => match send_request(&Request::Status)? {
            Response::Status(info) => print_status(info),
            Response::Error(e) => anyhow::bail!(e),
            _ => anyhow::bail!("unexpected response from daemon"),
        },
        Cmd::Dump { output } => {
            let output_str = output.as_ref().map(|p| p.to_string_lossy().to_string());
            match send_request(&Request::Dump { output: output_str })? {
                Response::Dump(result) => {
                    if !result.success {
                        anyhow::bail!(result.message);
                    }
                    match result.path {
                        Some(path) => println!("dump written to {path}"),
                        None => println!("{}", result.message),
                    }
                }
                Response::Error(e) => anyhow::bail!(e),
                _ => anyhow::bail!("unexpected response from daemon"),
            }
        }
        Cmd::Report {
            file,
            perfetto,
            top,
            per_cpu,
        } => {
            let text = fs::read_to_string(&file)?;
            let dump: Dump = serde_json::from_str(&text)?;
            dump.validate().map_err(|e| anyhow::anyhow!(e))?;
            if perfetto {
                println!("{}", to_chrome_json(&dump)?);
            } else {
                println!(
                    "{}",
                    render_report_with(&dump, ReportOptions { top, per_cpu })
                );
            }
        }
    }
    Ok(())
}
