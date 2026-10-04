//! Pure, privilege-free core of blackbox.
//!
//! Everything in this crate is ordinary userspace Rust with no BPF dependency,
//! which is deliberate: the analysis logic is where the real complexity lives,
//! and keeping it here means it can be unit tested on any machine, including
//! ones that cannot load BPF at all.
//!
//! The only thing that does *not* live here is the BPF object itself
//! (`crates/bpf`), which is compiled for `bpfel-unknown-none` and linked into
//! the daemon.

pub mod config;
pub mod dump;
pub mod event;
pub mod history;
pub mod hostinfo;
pub mod oncpu;
pub mod perfetto;
pub mod psi;
pub mod report;

pub use config::Config;
pub use dump::{Dump, DumpEvent, OverheadInfo, TriggerInfo, WindowInfo, SCHEMA_VERSION};
pub use event::{SchedSwitch, TASK_RUNNING};
pub use history::HistoryRing;
pub use oncpu::{gaps, reconstruct, OnCpuSlice, TaskGap};
pub use perfetto::to_chrome_json;
pub use psi::{
    PressureMonitor, PressureTrigger, PsiSample, PsiSnapshot, PsiStat, Resource, TriggerFired,
};
pub use report::render_report;
