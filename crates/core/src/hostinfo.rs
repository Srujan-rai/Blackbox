//! Host facts, read from /proc.
//!
//! Every read is a best-effort string fetch with a fallback, because a dump
//! written during an incident is exactly when some of these may be unreadable,
//! and a missing hostname should not cost you the trace.

use crate::dump::HostSnapshot;

/// The real procfs mount.
pub fn proc_root() -> std::path::PathBuf {
    std::path::PathBuf::from("/proc")
}

fn read_trimmed(path: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Collect a snapshot of host identity.
pub fn collect(proc: &std::path::Path) -> HostSnapshot {
    HostSnapshot {
        hostname: read_trimmed(&proc.join("sys/kernel/hostname")).unwrap_or_default(),
        kernel: read_trimmed(&proc.join("sys/kernel/osrelease")).unwrap_or_default(),
        boot_id: read_trimmed(&proc.join("sys/kernel/random/boot_id")).unwrap_or_default(),
        uptime_ns: uptime_ns(proc).unwrap_or(0),
    }
}

/// System uptime in nanoseconds.
///
/// Prefer `/proc/uptime` over CLOCK_BOOTTIME because it is a plain file: reading
/// a clock needs no capability, which matters when the daemon runs with the
/// narrowest set it can get away with.
pub fn uptime_ns(proc: &std::path::Path) -> Option<u64> {
    let text = read_trimmed(&proc.join("uptime"))?;
    let seconds: f64 = text.split_whitespace().next()?.parse().ok()?;
    if !seconds.is_finite() || seconds < 0.0 {
        return None;
    }
    Some((seconds * 1e9).min(u64::MAX as f64) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Unique scratch dir per test.
    ///
    /// The tests run in parallel inside one process, so keying these on the pid
    /// alone has them deleting each other's fixtures mid-test.
    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bb-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn fake_proc(tag: &str) -> std::path::PathBuf {
        let dir = scratch(tag);
        std::fs::create_dir_all(dir.join("sys/kernel/random")).unwrap();
        std::fs::write(dir.join("sys/kernel/hostname"), "web-07\n").unwrap();
        std::fs::write(dir.join("sys/kernel/osrelease"), "6.8.0-42-generic\n").unwrap();
        std::fs::write(
            dir.join("sys/kernel/random/boot_id"),
            "0123456789abcdef0123456789abcdef\n",
        )
        .unwrap();
        std::fs::write(dir.join("uptime"), "12345.67 98765.43\n").unwrap();
        dir
    }

    #[test]
    fn reads_all_fields_and_trims_newlines() {
        let dir = fake_proc("host-full");
        let h = collect(&dir);
        assert_eq!(h.hostname, "web-07");
        assert_eq!(h.kernel, "6.8.0-42-generic");
        assert_eq!(h.boot_id, "0123456789abcdef0123456789abcdef");
        assert_eq!(h.uptime_ns, 12_345_670_000_000);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn uptime_parses_the_first_field_only() {
        let dir = fake_proc("host-uptime");
        assert_eq!(uptime_ns(&dir), Some(12_345_670_000_000));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_files_degrade_to_empty_rather_than_failing() {
        // A trace must still be written when /proc is unreadable.
        let h = collect(&scratch("host-empty"));
        assert_eq!(h.hostname, "");
        assert_eq!(h.kernel, "");
        assert_eq!(h.boot_id, "");
        assert_eq!(h.uptime_ns, 0);
    }

    #[test]
    fn garbage_uptime_is_rejected() {
        let dir = scratch("host-garbage");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("uptime"), "not-a-number\n").unwrap();
        assert_eq!(uptime_ns(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn negative_uptime_is_rejected() {
        let dir = scratch("host-negative");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("uptime"), "-5.0 0.0\n").unwrap();
        assert_eq!(uptime_ns(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn real_host_has_a_readable_identity() {
        let h = collect(&proc_root());
        assert!(!h.hostname.is_empty());
        assert!(!h.kernel.is_empty());
        assert_eq!(h.boot_id.len(), 36, "boot_id is a uuid with dashes");
    }
}
