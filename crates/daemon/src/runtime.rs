use blackbox_core::config::Config;
use blackbox_core::dump::{Dump, DumpEvent, HostSnapshot, OverheadInfo, TriggerInfo};
use blackbox_core::history::HistoryRing;
use blackbox_core::oom::{OomFired, OomMonitor};
use blackbox_core::psi::{PressureMonitor, PsiSnapshot, TriggerFired};
use blackbox_core::{collect as collect_host, uptime_ns};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct Runtime {
    history: HistoryRing,
    monitor: PressureMonitor,
    oom: OomMonitor,
    config: Config,
    last_trigger_reason: Option<String>,
    last_trigger_time: Option<u64>, // unix ns
    kernel_drops: u64,
    start_time: SystemTime,
    host_snapshot: HostSnapshot,
    bpf_attached: bool,
    bpf_error: Option<String>,
}

impl Runtime {
    pub fn new(history: HistoryRing, monitor: PressureMonitor, config: Config) -> Self {
        let proc_root = PathBuf::from("/proc");
        let host_snapshot = collect_host(&proc_root);
        let oom = OomMonitor::new(config.pressure.triggers.oom.enabled);
        Self {
            history,
            monitor,
            oom,
            config,
            last_trigger_reason: None,
            last_trigger_time: None,
            kernel_drops: 0,
            start_time: SystemTime::now(),
            host_snapshot,
            bpf_attached: false,
            bpf_error: None,
        }
    }

    pub fn observe_psi(&mut self, snapshot: &PsiSnapshot) -> Vec<TriggerFired> {
        self.monitor.observe(snapshot)
    }

    /// Fold one `oom_kill` counter reading in; `Some` means a new kill happened.
    pub fn observe_oom(&mut self, total: u64) -> Option<OomFired> {
        self.oom.observe(total)
    }

    pub fn oom_enabled(&self) -> bool {
        self.oom.enabled()
    }

    pub fn history_mut(&mut self) -> &mut HistoryRing {
        &mut self.history
    }

    pub fn history(&self) -> &HistoryRing {
        &self.history
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn set_kernel_drops(&mut self, drops: u64) {
        self.kernel_drops = drops;
    }

    pub fn kernel_drops(&self) -> u64 {
        self.kernel_drops
    }

    /// Record whether BPF collection is live and, when it is not, why not.
    ///
    /// Kept on the runtime rather than beside the collector thread so that
    /// `blackbox status` reads counters and collection state from one
    /// consistent snapshot under a single lock.
    pub fn set_bpf_status(&mut self, attached: bool, error: Option<String>) {
        self.bpf_attached = attached;
        self.bpf_error = error;
    }

    pub fn bpf_attached(&self) -> bool {
        self.bpf_attached
    }

    pub fn bpf_error(&self) -> &Option<String> {
        &self.bpf_error
    }

    pub fn last_trigger_reason(&self) -> &Option<String> {
        &self.last_trigger_reason
    }

    pub fn last_trigger_time(&self) -> Option<u64> {
        self.last_trigger_time
    }

    pub fn start_time(&self) -> SystemTime {
        self.start_time
    }

    pub fn host_snapshot(&self) -> &HostSnapshot {
        &self.host_snapshot
    }

    pub fn uptime_secs(&self) -> Option<u64> {
        self.start_time.elapsed().ok().map(|d| d.as_secs())
    }

    pub fn build_dump(&self, trigger_reason: &str, trigger_detail: Option<&str>) -> Dump {
        let snapshot_events = self.history.snapshot();
        let (start_mono, end_mono) = match (snapshot_events.first(), snapshot_events.last()) {
            (Some(f), Some(l)) => (f.ts_ns, l.ts_ns),
            _ => (0, 0),
        };

        let dump_events: Vec<DumpEvent> = snapshot_events.iter().map(|e| e.into()).collect();

        let overhead = OverheadInfo {
            events_recorded: dump_events.len() as u64,
            events_evicted: self.history.evicted(),
            events_dropped_kernel: self.kernel_drops,
        };

        let now = SystemTime::now();
        let generated_unix_ns = now
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        // Anchor monotonic timestamps to wall time: CLOCK_MONOTONIC runs from
        // boot, and /proc/uptime reports the same origin (minus suspend time,
        // close enough for rendering a date).
        let uptime_ns_val = uptime_ns(Path::new("/proc")).unwrap_or(0);
        let clock_offset_ns: i64 = (generated_unix_ns as i64) - (uptime_ns_val as i64);

        Dump::new(
            TriggerInfo {
                reason: trigger_reason.to_string(),
                detail: trigger_detail.unwrap_or("").to_string(),
            },
            start_mono,
            end_mono,
            dump_events,
            overhead,
            self.host_snapshot.clone(),
            generated_unix_ns,
            clock_offset_ns,
            // Eviction means a configured cap let events fall out of the
            // window, which is exactly what `truncated` promises to report.
            self.history.evicted() > 0,
        )
    }

    /// Write a dump, either to an explicit path or into the configured dir.
    ///
    /// `requested` is what `blackbox dump --output` asked for; `None` means
    /// "use the config". Retention and trigger bookkeeping run either way, so
    /// an explicitly-targeted dump counts like any other.
    pub fn dump_to(&mut self, requested: Option<&Path>) -> anyhow::Result<PathBuf> {
        let dump = self.build_dump("manual", Some("requested via CLI"));
        match requested {
            Some(target) => {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                let json = serde_json::to_string_pretty(&dump)?;
                fs::write(target, json)?;
                self.note_trigger(&dump);
                self.enforce_retention()?;
                Ok(target.to_path_buf())
            }
            None => self.write_dump(&dump),
        }
    }

    /// Build and write a dump for a fired PSI trigger.
    ///
    /// The reason is machine-readable ([`TriggerFired::reason`], e.g.
    /// `psi_memory`); the detail is the human sentence from
    /// [`TriggerFired::describe`], so a report can say exactly why this dump
    /// exists without re-deriving the threshold state.
    pub fn write_psi_dump(&mut self, trigger: &TriggerFired) -> anyhow::Result<PathBuf> {
        let dump = self.build_dump(&trigger.reason(), Some(&trigger.describe()));
        self.write_dump(&dump)
    }

    /// Build and write a dump for a fired OOM trigger.
    ///
    /// Same contract as [`Self::write_psi_dump`]: machine-readable reason
    /// (`oom`), human-readable detail naming how many kills and the running
    /// total.
    pub fn write_oom_dump(&mut self, fired: &OomFired) -> anyhow::Result<PathBuf> {
        let dump = self.build_dump(&fired.reason(), Some(&fired.describe()));
        self.write_dump(&dump)
    }

    pub fn write_dump(&mut self, dump: &Dump) -> anyhow::Result<PathBuf> {
        let filename = if self.config.dump.timestamped_names {
            // Milliseconds, not seconds: a machine-wide stall can trip the CPU,
            // memory and I/O triggers within the same second, and second-granular
            // names would let the second dump silently overwrite the first.
            let ts = dump.generated_unix_ns / 1_000_000;
            format!("blackbox-{}.json", ts)
        } else {
            "blackbox.json".to_string()
        };

        // Prefer the configured directory; fall back to /tmp when it cannot be
        // created (typically a non-root run against /var/lib). A dump that
        // cannot be written at all is the failure worth avoiding at all costs,
        // so the fallback is silent rather than fatal.
        let dir = if fs::create_dir_all(&self.config.dump.dir).is_ok() {
            self.config.dump.dir.clone()
        } else {
            PathBuf::from("/tmp")
        };
        let path = dir.join(&filename);
        let mut file = File::create(&path)?;
        let json = serde_json::to_string_pretty(dump)?;
        file.write_all(json.as_bytes())?;
        file.flush()?;

        self.note_trigger(dump);
        // Apply retention policy
        self.enforce_retention()?;

        Ok(path)
    }

    /// Record that a dump was just written, for the status readout.
    fn note_trigger(&mut self, dump: &Dump) {
        self.last_trigger_reason = Some(dump.trigger.reason.clone());
        self.last_trigger_time = Some(dump.generated_unix_ns);
    }

    pub fn enforce_retention(&self) -> anyhow::Result<()> {
        if let Some(keep) = self.config.dump.keep_last {
            let mut entries: Vec<(PathBuf, SystemTime)> = Vec::new();
            if let Ok(dir) = fs::read_dir(&self.config.dump.dir) {
                for entry in dir.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("json") {
                        if let Ok(meta) = entry.metadata() {
                            if let Ok(modified) = meta.modified() {
                                entries.push((path, modified));
                            }
                        }
                    }
                }
            }
            // Newest first, so everything past `keep` is the oldest to delete.
            entries.sort_by_key(|e| std::cmp::Reverse(e.1));
            if entries.len() > keep as usize {
                for entry in entries.iter().skip(keep as usize) {
                    let _ = fs::remove_file(&entry.0);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackbox_core::config::{Config, DumpConfig};

    /// Unique scratch dir per test, matching the style used in hostinfo tests.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bbd-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn runtime_in(dir: &Path, keep_last: Option<u32>) -> Runtime {
        let config = Config {
            dump: DumpConfig {
                dir: dir.to_path_buf(),
                keep_last,
                timestamped_names: false,
            },
            ..Config::default()
        };
        let history = HistoryRing::new(100, 30);
        Runtime::new(history, PressureMonitor::new(vec![]), config)
    }

    #[test]
    fn dump_lands_in_the_configured_directory() {
        let dir = scratch("dump-dir");
        let mut rt = runtime_in(&dir, None);
        let dump = rt.build_dump("manual", Some("requested"));
        let path = rt.write_dump(&dump).unwrap();
        assert_eq!(path.parent().unwrap(), dir.as_path());
        assert!(path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_written_dump_is_remembered_for_status() {
        let dir = scratch("dump-last");
        let mut rt = runtime_in(&dir, None);
        assert!(rt.last_trigger_reason().is_none());
        let dump = rt.build_dump("psi_memory", Some("avg10 crossed"));
        rt.write_dump(&dump).unwrap();
        assert_eq!(rt.last_trigger_reason().as_deref(), Some("psi_memory"));
        assert!(rt.last_trigger_time().is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn retention_keeps_only_the_newest_dumps() {
        let dir = scratch("retention");
        // Three pre-existing dumps, distinctly aged so ordering is unambiguous.
        for i in 0..3u64 {
            let path = dir.join(format!("old{i}.json"));
            fs::write(&path, "{}").unwrap();
            let time = UNIX_EPOCH + std::time::Duration::from_secs(i);
            let f = File::options().write(true).open(&path).unwrap();
            f.set_modified(time).unwrap();
        }
        let mut rt = runtime_in(&dir, Some(2));
        let dump = rt.build_dump("manual", None);
        rt.write_dump(&dump).unwrap();

        let remaining: Vec<PathBuf> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        // keep_last = 2: the new dump and the newest old one survive, the two
        // oldest go.
        assert_eq!(remaining.len(), 2, "got {remaining:?}");
        assert!(remaining.iter().any(|p| p.ends_with("old2.json")));
        assert!(!remaining.iter().any(|p| p.ends_with("old1.json")));
        assert!(!remaining.iter().any(|p| p.ends_with("old0.json")));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_keep_last_means_nothing_is_deleted() {
        let dir = scratch("retention-off");
        for i in 0..5 {
            fs::write(dir.join(format!("old{i}.json")), "{}").unwrap();
        }
        let mut rt = runtime_in(&dir, None);
        let dump = rt.build_dump("manual", None);
        rt.write_dump(&dump).unwrap();
        assert_eq!(fs::read_dir(&dir).unwrap().flatten().count(), 6);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dump_to_honours_an_explicit_output_path() {
        let dir = scratch("dump-to");
        let target = dir.join("nested/chosen.json");
        let mut rt = runtime_in(&dir.join("unused"), None);
        let path = rt.dump_to(Some(&target)).unwrap();
        assert_eq!(path, target);
        assert!(target.exists());
        // Explicit dumps still count as triggers for the status readout.
        assert_eq!(rt.last_trigger_reason().as_deref(), Some("manual"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unwritable_dump_dir_falls_back_to_tmp() {
        // A file where the directory should be makes create_dir_all fail.
        let dir = scratch("dump-fallback");
        let blocker = dir.join("blocked");
        fs::write(&blocker, "not a directory").unwrap();
        let mut rt = runtime_in(&blocker, None);
        let dump = rt.build_dump("manual", None);
        let path = rt.write_dump(&dump).unwrap();
        assert!(path.starts_with("/tmp"), "fell back to {path:?}");
        assert!(path.exists());
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn truncated_flag_reflects_eviction() {
        let dir = scratch("truncated");
        let config = Config {
            dump: DumpConfig {
                dir: dir.clone(),
                keep_last: None,
                timestamped_names: false,
            },
            ..Config::default()
        };
        let mut history = HistoryRing::new(2, 30);
        use blackbox_core::event::SchedSwitch;
        for i in 0..5u64 {
            history.push(SchedSwitch::new(i * 1_000_000_000, 0, 1, 2, 0, b"a", b"b"));
        }
        let rt = Runtime::new(history, PressureMonitor::new(vec![]), config);
        let dump = rt.build_dump("manual", None);
        assert!(dump.window.truncated, "eviction must mark the window");
        assert_eq!(dump.overhead.events_evicted, 3);
        assert_eq!(dump.overhead.events_recorded, 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_history_yields_an_empty_valid_dump() {
        let dir = scratch("empty");
        let rt = runtime_in(&dir, None);
        let dump = rt.build_dump("manual", None);
        assert!(dump.events.is_empty());
        assert_eq!(dump.validate(), Ok(()));
        assert!(!dump.window.truncated, "nothing was evicted");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn uptime_counts_up_from_construction() {
        let dir = scratch("uptime");
        let rt = runtime_in(&dir, None);
        assert!(rt.uptime_secs().is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn psi_triggers_write_dumps_tagged_with_their_machine_reason() {
        use blackbox_core::psi::{AvgWindow, Resource};

        let dir = scratch("psi-dump");
        let mut rt = runtime_in(&dir, None);
        for (resource, expected) in [
            (Resource::Cpu, "psi_cpu"),
            (Resource::Memory, "psi_memory"),
            (Resource::Io, "psi_io"),
        ] {
            let trigger = TriggerFired {
                resource,
                window: AvgWindow::Avg10,
                value_pct: 41.25,
                threshold_pct: 20.0,
                consecutive: 4,
            };
            let path = rt.write_psi_dump(&trigger).unwrap();
            let dump: Dump = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
            assert_eq!(dump.trigger.reason, expected);
            assert_eq!(dump.trigger.detail, trigger.describe());
            assert!(
                dump.trigger.detail.starts_with("psi "),
                "detail must stay human-readable: {}",
                dump.trigger.detail
            );
            // Writing the dump is what status remembers as "last trigger".
            assert_eq!(rt.last_trigger_reason().as_deref(), Some(expected));
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn oom_triggers_write_dumps_tagged_with_their_machine_reason() {
        let dir = scratch("oom-dump");
        let mut rt = runtime_in(&dir, None);
        // The first reading only establishes a baseline; no dump for history.
        assert!(rt.observe_oom(0).is_none());
        let fired = rt.observe_oom(1).expect("one kill must fire");
        let path = rt.write_oom_dump(&fired).unwrap();
        let dump: Dump = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(dump.trigger.reason, "oom");
        assert_eq!(dump.trigger.detail, fired.describe());
        assert!(
            dump.trigger.detail.contains("OOM"),
            "detail must stay human-readable: {}",
            dump.trigger.detail
        );
        assert_eq!(rt.last_trigger_reason().as_deref(), Some("oom"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn oom_burst_is_reported_as_a_count_not_a_boolean() {
        let dir = scratch("oom-burst");
        let mut rt = runtime_in(&dir, None);
        rt.observe_oom(5);
        let fired = rt.observe_oom(8).expect("three kills");
        assert_eq!(fired.delta, 3);
        assert!(fired.describe().contains("3 times"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn bpf_status_defaults_to_not_attached_and_round_trips() {
        let dir = scratch("bpf-status");
        let mut rt = runtime_in(&dir, None);
        // Before any collector thread reports in: not attached, no reason yet.
        assert!(!rt.bpf_attached());
        assert_eq!(rt.bpf_error(), &None);
        rt.set_bpf_status(true, None);
        assert!(rt.bpf_attached());
        assert_eq!(rt.bpf_error(), &None);
        rt.set_bpf_status(false, Some("no blackbox-bpf.o found".into()));
        assert!(!rt.bpf_attached());
        assert_eq!(rt.bpf_error().as_deref(), Some("no blackbox-bpf.o found"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn timestamped_dumps_a_millisecond_apart_do_not_overwrite_each_other() {
        // A machine-wide stall can fire several triggers in the same second;
        // second-granular names would lose all but the first dump.
        let dir = scratch("dump-ms");
        let config = Config {
            dump: DumpConfig {
                dir: dir.clone(),
                keep_last: None,
                timestamped_names: true,
            },
            ..Config::default()
        };
        let mut rt = Runtime::new(
            HistoryRing::new(100, 30),
            PressureMonitor::new(vec![]),
            config,
        );
        let first = rt.build_dump("psi_cpu", Some("first"));
        let mut second = rt.build_dump("psi_memory", Some("second"));
        second.generated_unix_ns = first.generated_unix_ns + 1_000_000;
        let path_a = rt.write_dump(&first).unwrap();
        let path_b = rt.write_dump(&second).unwrap();
        assert_ne!(path_a, path_b, "1ms apart must be distinct names");
        assert!(path_a.exists() && path_b.exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
