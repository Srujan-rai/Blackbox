use anyhow::Result;
use blackbox_core::dump::Dump;
use blackbox_core::perfetto::to_chrome_json;
use blackbox_core::report::{render_report_with, ReportOptions};
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;

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

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Start { .. } => {
            eprintln!("daemon start not implemented yet");
        }
        Cmd::Status => {
            eprintln!("status not implemented yet");
        }
        Cmd::Dump { .. } => {
            eprintln!("manual dump not implemented yet");
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
