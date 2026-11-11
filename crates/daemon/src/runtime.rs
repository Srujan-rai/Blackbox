use blackbox_core::config::{Config, DumpConfig};
use blackbox_core::dump::{Dump, DumpEvent, HostSnapshot, OverheadInfo, TriggerInfo};
use blackbox_core::event::SchedSwitch;
use blackbox_core::history::HistoryRing;
use blackbox_core::lifecycle::{LifecycleEvent, LifecycleRing};
use blackbox_core::oom::{OomFired, OomMonitor};
use blackbox_core::psi::{PressureMonitor, PsiSnapshot, TriggerFired};
use blackbox_core::{collect as collect_host, uptime_ns};
use nix::time::{clock_gettime, ClockId};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Mode for dumps written into the configured dump directory.
///
/// Owner-only: a dump is a scheduling trace of every process on the machine,
/// and the control socket already refuses to hand one to an unprivileged
/// user, so the file it lands in must not undo that.
const DUMP_DIR_MODE: u32 = 0o600;

/// Mode for a dump written to an explicit `blackbox dump -o PATH`. The caller
/// (root or the daemon owner, see `handle_client`) chose where it goes and
/// usually wants to read it straight back with `blackbox report`.
const EXPLICIT_DUMP_MODE: u32 = 0o644;

#[derive(Debug)]
pub struct Runtime {
    history: HistoryRing,
    lifecycle: LifecycleRing,
    monitor: PressureMonitor,
    oom: OomMonitor,
    config: Config,
    last_trigger_reason: Option<String>,
    last_trigger_time: Option<u64>, // unix ns
    kernel_drops: u64,
    lifecycle_kernel_drops: u64,
    start_time: SystemTime,
    host_snapshot: HostSnapshot,
    bpf_attached: bool,
    bpf_error: Option<String>,
}

/// Everything a dump needs, copied out of the runtime under its lock.
///
/// Building the JSON is the slow part of a dump (sorting, a `String` per comm,
/// serialising tens of megabytes), and while the runtime lock is held the
/// collector cannot drain the kernel ring buffer. A dump is taken exactly
/// when the machine is under pressure, so stalling the drain then is how the
/// kernel ends up dropping the events the dump exists to keep. Capturing is a
/// plain copy; [`Capture::into_dump`] does the rest with no lock held.
#[derive(Debug, Clone)]
pub struct Capture {
    trigger: TriggerInfo,
    events: Vec<SchedSwitch>,
    lifecycle: Vec<LifecycleEvent>,
    events_evicted: u64,
    kernel_drops: u64,
    lifecycle_evicted: u64,
    lifecycle_kernel_drops: u64,
    host: HostSnapshot,
    generated_unix_ns: u64,
    clock_offset_ns: i64,
}

impl Capture {
    /// Sort, convert and assemble the dump. Lock-free by construction.
    pub fn into_dump(self) -> Dump {
        let mut events = self.events;
        // Arrival order across CPUs is only approximately chronological.
        events.sort_by_key(|e| e.ts_ns);
        let mut lifecycle = self.lifecycle;
        lifecycle.sort_by_key(|e| e.ts_ns);

        // The window spans both streams: a fork/exec/exit is part of the story
        // even when the sched window is empty.
        let earliest = events
            .first()
            .map(|e| e.ts_ns)
            .into_iter()
            .chain(lifecycle.first().map(|e| e.ts_ns))
            .min();
        let latest = events
            .last()
            .map(|e| e.ts_ns)
            .into_iter()
            .chain(lifecycle.last().map(|e| e.ts_ns))
            .max();
        let (start_mono, end_mono) = match (earliest, latest) {
            (Some(f), Some(l)) => (f, l),
            _ => (0, 0),
        };

        let dump_events: Vec<DumpEvent> = events.iter().map(|e| e.into()).collect();
        let overhead = OverheadInfo {
            events_recorded: dump_events.len() as u64,
            events_evicted: self.events_evicted,
            events_dropped_kernel: self.kernel_drops,
            lifecycle_recorded: lifecycle.len() as u64,
            lifecycle_evicted: self.lifecycle_evicted,
            lifecycle_dropped_kernel: self.lifecycle_kernel_drops,
        };

        Dump::new(
            self.trigger,
            start_mono,
            end_mono,
            dump_events,
            lifecycle,
            overhead,
            self.host,
            self.generated_unix_ns,
            self.clock_offset_ns,
            // Eviction means a configured cap let events fall out of the
            // window, which is exactly what `truncated` promises to report.
            self.events_evicted > 0,
        )
    }
}

/// `CLOCK_MONOTONIC` in nanoseconds: the clock `bpf_ktime_get_ns()` stamps
/// events with.
///
/// Not `/proc/uptime`: that is `CLOCK_BOOTTIME`, which keeps counting through
/// suspend while `CLOCK_MONOTONIC` does not, so after a laptop has slept the
/// two disagree by the total suspend time and every wall-clock date in a dump
/// would be off by that much. It also only has 10ms resolution. Reading a
/// clock needs no privilege.
fn monotonic_ns() -> Option<u64> {
    let ts = clock_gettime(ClockId::CLOCK_MONOTONIC).ok()?;
    let secs = u64::try_from(ts.tv_sec()).ok()?;
    let nanos = u64::try_from(ts.tv_nsec()).ok()?;
    Some(secs.saturating_mul(1_000_000_000).saturating_add(nanos))
}

fn unix_now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

impl Runtime {
    pub fn new(history: HistoryRing, monitor: PressureMonitor, config: Config) -> Self {
        let proc_root = PathBuf::from("/proc");
        let host_snapshot = collect_host(&proc_root);
        let oom = OomMonitor::new(config.pressure.triggers.oom.enabled);
        // Lifecycle events are far rarer than sched_switch, so the same caps
        // are generous in practice while keeping the window identical.
        let lifecycle = LifecycleRing::new(config.history.max_events, config.history.max_seconds);
        Self {
            history,
            lifecycle,
            monitor,
            oom,
            config,
            last_trigger_reason: None,
            last_trigger_time: None,
            kernel_drops: 0,
            lifecycle_kernel_drops: 0,
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

    pub fn lifecycle_mut(&mut self) -> &mut LifecycleRing {
        &mut self.lifecycle
    }

    pub fn lifecycle(&self) -> &LifecycleRing {
        &self.lifecycle
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Record the kernel-side ring buffer drop totals, as counted by the BPF
    /// program itself (`sched_switch`, lifecycle).
    pub fn set_kernel_drops(&mut self, sched: u64, lifecycle: u64) {
        self.kernel_drops = sched;
        self.lifecycle_kernel_drops = lifecycle;
    }

    pub fn kernel_drops(&self) -> u64 {
        self.kernel_drops
    }

    pub fn lifecycle_kernel_drops(&self) -> u64 {
        self.lifecycle_kernel_drops
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

    /// Copy out what a dump needs. Cheap: meant to run under the lock.
    pub fn capture(&self, trigger_reason: &str, trigger_detail: Option<&str>) -> Capture {
        // Read both clocks back to back so the offset between them is as
        // tight as the two syscalls allow.
        let generated_unix_ns = unix_now_ns();
        let mono = monotonic_ns().or_else(|| uptime_ns(Path::new("/proc")));
        let clock_offset_ns = (generated_unix_ns as i64) - (mono.unwrap_or(0) as i64);

        // Identity is fixed at startup; uptime is not, and a dump should say
        // how long the host had been up when it was taken.
        let mut host = self.host_snapshot.clone();
        if let Some(up) = uptime_ns(Path::new("/proc")) {
            host.uptime_ns = up;
        }

        Capture {
            trigger: TriggerInfo {
                reason: trigger_reason.to_string(),
                detail: trigger_detail.unwrap_or("").to_string(),
            },
            events: self.history.iter().copied().collect(),
            lifecycle: self.lifecycle.iter().cloned().collect(),
            events_evicted: self.history.evicted(),
            kernel_drops: self.kernel_drops,
            lifecycle_evicted: self.lifecycle.evicted(),
            lifecycle_kernel_drops: self.lifecycle_kernel_drops,
            host,
            generated_unix_ns,
            clock_offset_ns,
        }
    }

    pub fn build_dump(&self, trigger_reason: &str, trigger_detail: Option<&str>) -> Dump {
        self.capture(trigger_reason, trigger_detail).into_dump()
    }

    /// Write a dump, either to an explicit path or into the configured dir.
    ///
    /// `requested` is what `blackbox dump --output` asked for; `None` means
    /// "use the config". Retention and trigger bookkeeping run either way, so
    /// an explicitly-targeted dump counts like any other.
    pub fn dump_to(&mut self, requested: Option<&Path>) -> anyhow::Result<PathBuf> {
        let dump = self.build_dump("manual", Some("requested via CLI"));
        let path = persist(&self.config.dump, &dump, requested)?;
        self.note_trigger(&dump);
        Ok(path)
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
        let path = persist(&self.config.dump, dump, None)?;
        self.note_trigger(dump);
        Ok(path)
    }

    /// Record that a dump was just written, for the status readout.
    pub fn note_trigger(&mut self, dump: &Dump) {
        self.last_trigger_reason = Some(dump.trigger.reason.clone());
        self.last_trigger_time = Some(dump.generated_unix_ns);
    }

    pub fn enforce_retention(&self) -> anyhow::Result<()> {
        enforce_retention(&self.config.dump)
    }
}

/// Serialise and write a dump, then apply retention. Needs no runtime lock.
///
/// With `requested`, the dump goes exactly there (replacing an existing file,
/// like a shell redirect). Without it, it goes into the configured directory
/// under a fresh name that never replaces an earlier dump, falling back to
/// `/tmp` when the directory cannot be created (typically a non-root run
/// against `/var/lib`): a dump that cannot be written at all is the failure
/// worth avoiding at all costs.
///
/// Every write is atomic (temporary file, then rename or link), so a crash
/// mid-dump never leaves a truncated file that `blackbox report` chokes on,
/// and the temporary file is created with `O_EXCL`, so a symlink planted in
/// a shared directory such as `/tmp` is never followed by a root daemon.
pub fn persist(cfg: &DumpConfig, dump: &Dump, requested: Option<&Path>) -> anyhow::Result<PathBuf> {
    let json = serde_json::to_vec_pretty(dump)?;
    let path = match requested {
        Some(target) => {
            if let Some(parent) = target.parent().filter(|p| !p.as_os_str().is_empty()) {
                fs::create_dir_all(parent)?;
            }
            write_atomic(target, &json, EXPLICIT_DUMP_MODE, true)?
        }
        None => {
            let dir = if fs::create_dir_all(&cfg.dir).is_ok() {
                cfg.dir.clone()
            } else {
                PathBuf::from("/tmp")
            };
            let name = if cfg.timestamped_names {
                // Milliseconds, not seconds: a machine-wide stall can trip the
                // CPU, memory and I/O triggers within the same second. Same-ms
                // collisions get a numeric suffix rather than overwriting.
                format!("blackbox-{}.json", dump.generated_unix_ns / 1_000_000)
            } else {
                "blackbox.json".to_string()
            };
            // Untimestamped mode is one rolling file by definition.
            let replace = !cfg.timestamped_names;
            write_atomic(&dir.join(name), &json, DUMP_DIR_MODE, replace)?
        }
    };
    enforce_retention(cfg)?;
    Ok(path)
}

/// Write `bytes` to `target` atomically and return where it landed.
///
/// `replace` renames over an existing target (a symlink there is replaced,
/// not followed). Otherwise the file is hard-linked into place, which fails
/// rather than clobbers, and a taken name gets a `-1`, `-2`, ... suffix.
fn write_atomic(target: &Path, bytes: &[u8], mode: u32, replace: bool) -> anyhow::Result<PathBuf> {
    let dir = match target.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let name = target
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("dump path {} has no file name", target.display()))?
        .to_string_lossy()
        .into_owned();

    let (tmp, mut file) = create_temp(dir, &name, mode)?;
    let result = (|| -> anyhow::Result<PathBuf> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        if replace {
            fs::rename(&tmp, target)?;
            return Ok(target.to_path_buf());
        }
        let (stem, ext) = match name.rsplit_once('.') {
            Some((s, e)) => (s.to_string(), format!(".{e}")),
            None => (name.clone(), String::new()),
        };
        for n in 0..1000u32 {
            let candidate = if n == 0 {
                target.to_path_buf()
            } else {
                dir.join(format!("{stem}-{n}{ext}"))
            };
            match fs::hard_link(&tmp, &candidate) {
                Ok(()) => {
                    let _ = fs::remove_file(&tmp);
                    return Ok(candidate);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        anyhow::bail!("no free dump name next to {}", target.display())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Create a fresh, exclusively-owned temporary file next to the target.
fn create_temp(dir: &Path, name: &str, mode: u32) -> anyhow::Result<(PathBuf, fs::File)> {
    for attempt in 0..100u32 {
        let tmp = dir.join(format!(
            ".{name}.{}.{}.{attempt}.tmp",
            std::process::id(),
            unix_now_ns()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
        {
            Ok(file) => return Ok((tmp, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(anyhow::Error::from(e).context(format!(
                    "creating a temporary dump file in {}",
                    dir.display()
                )))
            }
        }
    }
    anyhow::bail!(
        "could not create a temporary dump file in {}",
        dir.display()
    )
}

/// True for file names blackbox itself writes into the dump directory.
///
/// Retention must only ever delete its own dumps: a dump dir pointed at a
/// shared location (`/tmp`, a home directory) holds other `.json` files.
fn is_blackbox_dump(name: &str) -> bool {
    name == "blackbox.json" || (name.starts_with("blackbox-") && name.ends_with(".json"))
}

/// Keep the newest `keep_last` blackbox dumps in the configured directory.
pub fn enforce_retention(cfg: &DumpConfig) -> anyhow::Result<()> {
    let Some(keep) = cfg.keep_last else {
        return Ok(());
    };
    let mut entries: Vec<(PathBuf, SystemTime)> = Vec::new();
    if let Ok(dir) = fs::read_dir(&cfg.dir) {
        for entry in dir.flatten() {
            let name = entry.file_name();
            if !is_blackbox_dump(&name.to_string_lossy()) {
                continue;
            }
            // Regular files only: never follow or delete through a symlink.
            let Ok(meta) = entry.metadata() else { continue };
            if !meta.file_type().is_file() {
                continue;
            }
            if let Ok(modified) = meta.modified() {
                entries.push((entry.path(), modified));
            }
        }
    }
    // Newest first (name breaks mtime ties: names embed the timestamp), so
    // everything past `keep` is the oldest to delete.
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.0.cmp(&a.0)));
    for entry in entries.iter().skip(keep as usize) {
        let _ = fs::remove_file(&entry.0);
    }
    Ok(())
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
    fn lifecycle_events_flow_into_the_dump_and_overhead() {
        use blackbox_core::lifecycle::{LifecycleEvent, LifecycleKind};
        let dir = scratch("lifecycle");
        let mut rt = runtime_in(&dir, None);
        assert!(rt.lifecycle().is_empty());
        rt.lifecycle_mut().push(LifecycleEvent {
            ts_ns: 1_000,
            kind: LifecycleKind::Exec,
            pid: 77,
            peer_pid: 76,
            value: 0,
            comm: "bash".into(),
            name: "/usr/bin/git".into(),
        });
        let dump = rt.build_dump("manual", Some("requested"));
        assert_eq!(dump.lifecycle.len(), 1);
        assert_eq!(dump.lifecycle[0].pid, 77);
        assert_eq!(dump.lifecycle[0].name, "/usr/bin/git");
        assert_eq!(dump.overhead.lifecycle_recorded, 1);
        // The lifecycle event widens the window even with no sched events.
        assert_eq!(dump.window.span_ns, 0); // single event: span is 0, still bounded
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn lifecycle_ring_caps_are_honoured_inside_the_runtime() {
        use blackbox_core::lifecycle::{LifecycleEvent, LifecycleKind};
        let dir = scratch("lifecycle-cap");
        let config = Config {
            dump: DumpConfig {
                dir: dir.to_path_buf(),
                keep_last: None,
                timestamped_names: false,
            },
            history: blackbox_core::config::HistoryConfig {
                max_events: 100,
                max_seconds: 30,
            },
            ..Config::default()
        };
        let mut rt = Runtime::new(
            HistoryRing::new(100, 30),
            PressureMonitor::new(vec![]),
            config,
        );
        for i in 0..200u32 {
            rt.lifecycle_mut().push(LifecycleEvent {
                ts_ns: i as u64,
                kind: LifecycleKind::Exit,
                pid: i,
                peer_pid: 0,
                value: 120,
                comm: "x".into(),
                name: String::new(),
            });
        }
        assert!(rt.lifecycle().len() <= 100);
        assert!(rt.lifecycle().evicted() >= 100);
        let _ = fs::remove_dir_all(&dir);
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
            let path = dir.join(format!("blackbox-{i}.json"));
            fs::write(&path, "{}").unwrap();
            let time = UNIX_EPOCH + std::time::Duration::from_secs(i);
            let f = fs::File::options().write(true).open(&path).unwrap();
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
        assert!(remaining.iter().any(|p| p.ends_with("blackbox-2.json")));
        assert!(!remaining.iter().any(|p| p.ends_with("blackbox-1.json")));
        assert!(!remaining.iter().any(|p| p.ends_with("blackbox-0.json")));
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

    #[test]
    fn retention_never_deletes_files_blackbox_did_not_write() {
        // A dump dir pointed at a shared place holds other people's JSON.
        let dir = scratch("retention-foreign");
        fs::write(dir.join("package.json"), "{}").unwrap();
        fs::write(dir.join("notes.json"), "{}").unwrap();
        let mut rt = runtime_in(&dir, Some(1));
        for _ in 0..3 {
            let dump = rt.build_dump("manual", None);
            rt.write_dump(&dump).unwrap();
        }
        assert!(dir.join("package.json").exists());
        assert!(dir.join("notes.json").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn same_millisecond_dumps_get_distinct_names() {
        let dir = scratch("dump-same-ms");
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
        let first = rt.build_dump("psi_cpu", None);
        let mut second = rt.build_dump("psi_io", None);
        second.generated_unix_ns = first.generated_unix_ns;
        let a = rt.write_dump(&first).unwrap();
        let b = rt.write_dump(&second).unwrap();
        assert_ne!(a, b, "a collision must not overwrite");
        assert!(a.exists() && b.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dumps_in_the_dump_dir_are_owner_only_and_leave_no_temp_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("dump-mode");
        let mut rt = runtime_in(&dir, None);
        let dump = rt.build_dump("manual", None);
        let path = rt.write_dump(&dump).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["blackbox.json".to_string()]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_explicit_output_replaces_a_symlink_instead_of_following_it() {
        let dir = scratch("dump-symlink");
        let victim = dir.join("victim");
        fs::write(&victim, "precious").unwrap();
        let target = dir.join("out.json");
        std::os::unix::fs::symlink(&victim, &target).unwrap();
        let mut rt = runtime_in(&dir.join("dumps"), None);
        rt.dump_to(Some(&target)).unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
        assert!(!fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dump_wall_clock_tracks_the_monotonic_clock() {
        // The offset must be REALTIME - MONOTONIC, so "now" on the monotonic
        // clock maps to roughly the dump's own generation time.
        let dir = scratch("dump-clock");
        let rt = runtime_in(&dir, None);
        let dump = rt.build_dump("manual", None);
        let mono_now = super::monotonic_ns().unwrap();
        let mapped = dump.unix_ns(mono_now);
        let diff = mapped.abs_diff(dump.generated_unix_ns);
        assert!(diff < 1_000_000_000, "off by {diff}ns");
        let _ = fs::remove_dir_all(&dir);
    }
}
