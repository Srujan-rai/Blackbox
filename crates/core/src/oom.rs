//! OOM-kill detection from `/proc/vmstat`.
//!
//! The kernel already counts out-of-memory kills for us, so — exactly like PSI
//! — there is no reason to put this in BPF. `oom_kill` in `/proc/vmstat` is a
//! monotonic counter that increments every time the OOM killer takes a victim;
//! watching it for a change is a reliable "something just got killed" signal
//! that costs one file read per poll.
//!
//! Unlike PSI there is no threshold and no hysteresis: a kill is a discrete
//! event, not a level. One increment over the previous sample is one incident,
//! and the count is reported so a burst is visible rather than collapsed into a
//! single boolean.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Machine-readable dump reason for an OOM trigger.
pub const REASON: &str = "oom";

#[derive(Debug, thiserror::Error)]
pub enum OomError {
    #[error("io error reading {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("no oom_kill counter in {path} (kernel too old, or CONFIG_MEMCG-less accounting)")]
    Missing { path: String },
}

/// Pull the `oom_kill` counter out of `/proc/vmstat` text.
///
/// Returns `None` when the key is absent, which is a real possibility on old
/// kernels; the caller degrades rather than guessing zero (zero would look like
/// "no OOMs ever", which is indistinguishable from "not supported").
pub fn parse_oom_kill(text: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        match (words.next(), words.next()) {
            (Some("oom_kill"), Some(value)) => value.parse().ok(),
            _ => None,
        }
    })
}

/// Read and parse the `oom_kill` counter from a proc root.
pub fn read_oom_kill(proc_root: &Path) -> Result<u64, OomError> {
    let path = proc_root.join("vmstat");
    let text = std::fs::read_to_string(&path).map_err(|source| OomError::Io {
        path: path.display().to_string(),
        source,
    })?;
    parse_oom_kill(&text).ok_or_else(|| OomError::Missing {
        path: path.display().to_string(),
    })
}

/// A fired OOM trigger.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OomFired {
    /// Cumulative `oom_kill` count at the sample that fired.
    pub total: u64,
    /// Kills observed since the previous sample. Always `>= 1`.
    pub delta: u64,
}

impl OomFired {
    /// Machine-readable dump reason, matching [`REASON`].
    pub fn reason(&self) -> String {
        REASON.to_string()
    }

    /// One-line human-readable explanation, embedded verbatim in the dump.
    pub fn describe(&self) -> String {
        if self.delta == 1 {
            format!("kernel OOM killer invoked (oom_kill total {})", self.total)
        } else {
            format!(
                "kernel OOM killer invoked {} times (oom_kill total {})",
                self.delta, self.total
            )
        }
    }
}

/// Stateful OOM counter across polling rounds.
#[derive(Debug)]
pub struct OomMonitor {
    enabled: bool,
    last: Option<u64>,
}

impl OomMonitor {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            last: None,
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Fold one sample in.
    ///
    /// The very first sample only establishes the baseline: a daemon starting
    /// after an OOM must not immediately dump for a kill that happened before
    /// it was watching. A counter that goes backwards (read racing a rare
    /// reset, or a 32-bit wraparound on an ancient kernel) is treated as a new
    /// baseline rather than an enormous delta.
    pub fn observe(&mut self, total: u64) -> Option<OomFired> {
        let previous = self.last.replace(total);
        if !self.enabled {
            return None;
        }
        match previous {
            Some(prev) if total > prev => Some(OomFired {
                total,
                delta: total - prev,
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VMSTAT: &str = "nr_free_pages 12345\n\
         oom_kill 7\n\
         pgpgin 999\n";

    #[test]
    fn parses_the_counter_among_other_keys() {
        assert_eq!(parse_oom_kill(VMSTAT), Some(7));
    }

    #[test]
    fn a_zero_counter_parses_as_zero_not_missing() {
        assert_eq!(parse_oom_kill("oom_kill 0\n"), Some(0));
    }

    #[test]
    fn a_missing_key_is_none_rather_than_zero() {
        // "absent" and "zero" must stay distinguishable.
        assert_eq!(parse_oom_kill("nr_free_pages 1\n"), None);
    }

    #[test]
    fn a_non_numeric_value_is_treated_as_absent() {
        assert_eq!(parse_oom_kill("oom_kill notanumber\n"), None);
    }

    #[test]
    fn reads_from_a_fake_proc_tree() {
        let dir = std::env::temp_dir().join(format!("bb-oom-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("vmstat"), VMSTAT).unwrap();
        assert_eq!(read_oom_kill(&dir).unwrap(), 7);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_vmstat_is_an_io_error() {
        let dir = std::env::temp_dir().join(format!("bb-oom-none-{}", std::process::id()));
        assert!(matches!(read_oom_kill(&dir), Err(OomError::Io { .. })));
    }

    #[test]
    fn first_sample_only_sets_the_baseline() {
        let mut m = OomMonitor::new(true);
        assert!(m.observe(5).is_none(), "must not fire on the first read");
        assert!(m.observe(5).is_none(), "no change, no trigger");
    }

    #[test]
    fn an_increment_fires_and_reports_the_delta() {
        let mut m = OomMonitor::new(true);
        m.observe(5);
        let fired = m.observe(6).expect("one kill must fire");
        assert_eq!(fired.delta, 1);
        assert_eq!(fired.total, 6);
    }

    #[test]
    fn a_burst_reports_every_kill_in_one_trigger() {
        let mut m = OomMonitor::new(true);
        m.observe(5);
        let fired = m.observe(9).expect("four kills");
        assert_eq!(fired.delta, 4);
        assert!(fired.describe().contains('4'));
    }

    #[test]
    fn a_counter_going_backwards_rebaselines_instead_of_firing() {
        let mut m = OomMonitor::new(true);
        m.observe(100);
        assert!(m.observe(3).is_none(), "no absurd delta on a reset");
        // And the new baseline is in effect.
        assert_eq!(m.observe(4).expect("fires").delta, 1);
    }

    #[test]
    fn disabled_never_fires_but_still_tracks() {
        let mut m = OomMonitor::new(false);
        assert!(!m.enabled());
        m.observe(1);
        assert!(m.observe(2).is_none());
    }

    #[test]
    fn fired_trigger_has_the_machine_reason_and_a_human_detail() {
        let f = OomFired { total: 3, delta: 1 };
        assert_eq!(f.reason(), "oom");
        assert!(f.describe().starts_with("kernel OOM killer invoked"));
        let many = OomFired { total: 9, delta: 3 };
        assert!(many.describe().contains("3 times"));
    }
}
