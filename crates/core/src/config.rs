//! Configuration, loaded from TOML.
//!
//! `deny_unknown_fields` is deliberate. A silently ignored typo in a threshold
//! is much worse than a startup failure: someone debugging a missed capture
//! would have no reason to suspect the config was not read at all.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::history::{DEFAULT_MAX_EVENTS, DEFAULT_MAX_SECONDS};
use crate::psi::{AvgWindow, PressureTrigger, Resource};

/// Default configuration file location.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/blackbox/config.toml";

/// Environment variable naming the BPF object, consulted after an explicit
/// `[bpf].object_path` and before the built-in search list.
pub const BPF_OBJECT_ENV: &str = "BLACKBOX_BPF_OBJECT";

/// Where the BPF object is looked for when nothing names one explicitly.
///
/// The order is deliberate: a daemon started by systemd has no useful working
/// directory, so the packaged install location comes first; a developer
/// running from the repo root gets `./blackbox-bpf.o` last.
pub const DEFAULT_BPF_OBJECT_PATHS: &[&str] = &[
    "/usr/local/lib/blackbox/blackbox-bpf.o",
    "/usr/lib/blackbox/blackbox-bpf.o",
    "./blackbox-bpf.o",
];

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub history: HistoryConfig,
    pub pressure: PressureConfig,
    pub dump: DumpConfig,
    pub bpf: BpfConfig,
}

/// Where to find the compiled BPF object (`blackbox-bpf.o`) and how to scope
/// what it traces.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BpfConfig {
    /// Explicit path to the object. `None` means search: `BLACKBOX_BPF_OBJECT`
    /// and then [`DEFAULT_BPF_OBJECT_PATHS`]. A path that is set but missing
    /// fails startup (caught by [`Config::validate`]) rather than falling
    /// back — silently ignoring a typo would defeat the point of naming one.
    pub object_path: Option<PathBuf>,
    /// Trace only these pids: a `sched_switch` record is kept when the pid on
    /// either side of the switch is in the list; a lifecycle event is kept when
    /// its subject (`pid`, or `parent_pid`/`child_pid` for a fork) is.
    /// Empty (the default) traces everything machine-wide. The point is ingest
    /// reduction on high-switch hosts — the tracepoint still fires, but the
    /// ring buffer, decode and history only see the listed pids. Limited to
    /// [`MAX_FILTER_PIDS`] entries; more are rejected at startup.
    pub filter_pids: Vec<u32>,
}

/// How many pids `[bpf].filter_pids` may list. Mirrors `FILTER_MAX` in the BPF
/// crate (each filter slot costs one array-map entry); keep the two in sync.
pub const MAX_FILTER_PIDS: usize = 32;

impl BpfConfig {
    /// Resolve which BPF object to load.
    ///
    /// Order, first hit wins:
    /// 1. `[bpf].object_path` — explicit, so a missing file is an error rather
    ///    than a fallthrough.
    /// 2. `env_path` — normally `Some` only when `BLACKBOX_BPF_OBJECT` is set;
    ///    treated as explicit for the same reason.
    /// 3. `search` — the built-in locations. Finding nothing here is an
    ///    environment problem rather than a bad config file, so the caller
    ///    reports it (status, log) and runs degraded instead of exiting.
    pub fn resolve_object(&self, env_path: Option<&Path>) -> Result<PathBuf, ConfigError> {
        self.resolve_object_among(env_path, DEFAULT_BPF_OBJECT_PATHS)
    }

    /// [`Self::resolve_object`] against an explicit candidate list; split out
    /// so tests can exercise the search logic without depending on which
    /// files happen to exist on the build machine.
    fn resolve_object_among(
        &self,
        env_path: Option<&Path>,
        search: &[&str],
    ) -> Result<PathBuf, ConfigError> {
        if let Some(path) = &self.object_path {
            return if path.is_file() {
                Ok(path.clone())
            } else {
                Err(ConfigError::BpfObject(format!(
                    "bpf.object_path {} does not exist or is not a file",
                    path.display()
                )))
            };
        }
        if let Some(path) = env_path {
            return if path.is_file() {
                Ok(path.to_path_buf())
            } else {
                Err(ConfigError::BpfObject(format!(
                    "{BPF_OBJECT_ENV} points at {}, which does not exist or is not a file",
                    path.display()
                )))
            };
        }
        for candidate in search {
            let path = Path::new(candidate);
            if path.is_file() {
                return Ok(path.to_path_buf());
            }
        }
        Err(ConfigError::BpfObject(format!(
            "no blackbox-bpf.o found (tried {}); set [bpf].object_path or {BPF_OBJECT_ENV}",
            search.join(", ")
        )))
    }
}

/// How much scheduler history to keep in memory.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HistoryConfig {
    /// Hard cap on retained events. 16 MB at 64 bytes each.
    pub max_events: usize,
    /// Hard cap on the retained window's width.
    pub max_seconds: u64,
}

impl Default for HistoryConfig {
    fn default() -> Self {
        Self {
            max_events: DEFAULT_MAX_EVENTS,
            max_seconds: DEFAULT_MAX_SECONDS,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PressureConfig {
    /// How often to read /proc/pressure. Must be short relative to the
    /// shortest window watched (avg10), or the consecutive-sample
    /// requirement stops meaning anything.
    pub poll_interval_ms: u64,
    #[serde(flatten)]
    pub triggers: PressureTriggers,
}

impl Default for PressureConfig {
    fn default() -> Self {
        Self {
            // Comfortably finer than the shortest window watched (avg10), so
            // the consecutive-sample counter tracks real samples rather than
            // undersampling the stall.
            poll_interval_ms: 250,
            triggers: PressureTriggers::default(),
        }
    }
}

/// Triggers are flattened into `[pressure]` so the TOML reads naturally:
///
/// ```toml
/// [pressure]
/// poll_interval_ms = 250
/// cpu    = { threshold_pct = 80.0, consecutive = 4 }
/// memory = { threshold_pct = 20.0 }
/// io     = { enabled = false }
/// oom    = { enabled = true }
/// ```
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PressureTriggers {
    pub cpu: TriggerTuning,
    pub memory: TriggerTuning,
    pub io: TriggerTuning,
    /// OOM is not a pressure level, so it has no threshold or window: it fires
    /// on the `oom_kill` counter in `/proc/vmstat` moving at all.
    pub oom: OomTuning,
}

impl PressureTriggers {
    /// Expand into the trigger list the monitor evaluates.
    pub fn expand(&self) -> Vec<PressureTrigger> {
        [Resource::Cpu, Resource::Memory, Resource::Io]
            .into_iter()
            .map(|resource| {
                let tuning = match resource {
                    Resource::Cpu => &self.cpu,
                    Resource::Memory => &self.memory,
                    Resource::Io => &self.io,
                };
                PressureTrigger {
                    resource,
                    enabled: tuning.enabled,
                    window: tuning.window,
                    threshold_pct: tuning.threshold_pct,
                    consecutive: tuning.consecutive,
                }
            })
            .collect()
    }
}

/// OOM kill trigger. Count-based, so the only knob is whether to watch it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OomTuning {
    pub enabled: bool,
}

impl Default for OomTuning {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Per-resource tuning; anything omitted keeps the resource's default.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TriggerTuning {
    pub enabled: bool,
    pub window: AvgWindow,
    pub threshold_pct: f64,
    pub consecutive: u32,
}

impl Default for TriggerTuning {
    fn default() -> Self {
        // A resource-blind fallback, used only when a tuning block is absent and
        // no resource-specific default applies. The memory-like values match
        // PressureTrigger::default.
        let base = PressureTrigger::default();
        Self {
            enabled: base.enabled,
            window: base.window,
            threshold_pct: base.threshold_pct,
            consecutive: base.consecutive,
        }
    }
}

impl TriggerTuning {
    fn with_defaults(resource: Resource) -> Self {
        let base = PressureTrigger::default();
        Self {
            enabled: base.enabled,
            window: base.window,
            threshold_pct: base.threshold_pct,
            consecutive: base.consecutive,
        }
        .scaled_for(resource)
    }

    /// Resource-appropriate defaults, chosen so each fires on a stall a human
    /// would call one.
    fn scaled_for(self, resource: Resource) -> Self {
        match resource {
            // Memory and I/O stall far below this and recover quickly, so they
            // trip early. Sustained CPU saturation is normal on a busy box, so
            // wait for it to be extreme before calling it an incident.
            Resource::Cpu => TriggerTuning {
                threshold_pct: 80.0,
                ..self
            },
            Resource::Memory => TriggerTuning {
                threshold_pct: 20.0,
                ..self
            },
            Resource::Io => TriggerTuning {
                threshold_pct: 20.0,
                ..self
            },
        }
    }
}

impl Default for PressureTriggers {
    fn default() -> Self {
        Self {
            cpu: TriggerTuning::with_defaults(Resource::Cpu),
            memory: TriggerTuning::with_defaults(Resource::Memory),
            io: TriggerTuning::with_defaults(Resource::Io),
            oom: OomTuning::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DumpConfig {
    /// Where dumps are written.
    pub dir: PathBuf,
    /// How many dumps to keep. `None` means unlimited.
    pub keep_last: Option<u32>,
    /// Append a timestamp to the filename.
    pub timestamped_names: bool,
}

impl Default for DumpConfig {
    fn default() -> Self {
        Self {
            dir: PathBuf::from("/var/lib/blackbox/dumps"),
            keep_last: None,
            timestamped_names: true,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read config {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid TOML in {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("invalid configuration: {0}")]
    Invalid(String),
    /// Locating the BPF object failed. Unlike the variants above this is
    /// usually the environment (nothing installed, no privileges path to it)
    /// rather than a malformed config file, so the daemon reports it and
    /// degrades instead of refusing to start.
    #[error("{0}")]
    BpfObject(String),
}

impl Config {
    /// Parse from a TOML string.
    pub fn from_toml(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    /// Load from disk.
    ///
    /// A missing file at the default location is not an error: the daemon is
    /// usable with no configuration at all. A malformed file always is.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_toml(&text).map_err(|source| ConfigError::Parse {
            path: path.display().to_string(),
            source,
        })
    }

    /// Reject values that would misbehave at runtime.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.history.max_events == 0 {
            return Err(ConfigError::Invalid(
                "history.max_events must be at least 1".into(),
            ));
        }
        if self.history.max_seconds == 0 {
            return Err(ConfigError::Invalid(
                "history.max_seconds must be at least 1".into(),
            ));
        }
        if self.pressure.poll_interval_ms == 0 {
            return Err(ConfigError::Invalid(
                "pressure.poll_interval_ms must be at least 1".into(),
            ));
        }
        // A poll interval far longer than the shortest window watched makes the
        // consecutive-sample counter meaningless: a sustained stall could be
        // missed entirely between samples.
        if self.pressure.poll_interval_ms > 10_000 {
            return Err(ConfigError::Invalid(
                "pressure.poll_interval_ms above 10000 exceeds every avg window blackbox watches"
                    .into(),
            ));
        }
        for t in self.pressure.triggers.expand() {
            if !(0.0..=100.0).contains(&t.threshold_pct) {
                return Err(ConfigError::Invalid(format!(
                    "trigger for {} has threshold_pct {} outside 0..=100",
                    t.resource.as_str(),
                    t.threshold_pct
                )));
            }
        }
        // An explicitly named BPF object that is missing is a config mistake
        // (typo, stale path), and a daemon quietly collecting nothing would be
        // the worst way to discover it — the same reasoning as
        // `deny_unknown_fields` above. When no path is named, "nothing
        // installed yet" is an environment condition instead, and resolution
        // reports it to status while the daemon keeps serving.
        if let Some(path) = &self.bpf.object_path {
            if !path.is_file() {
                return Err(ConfigError::Invalid(format!(
                    "bpf.object_path {} does not exist or is not a file",
                    path.display()
                )));
            }
        }
        if self.bpf.filter_pids.len() > MAX_FILTER_PIDS {
            return Err(ConfigError::Invalid(format!(
                "bpf.filter_pids lists {} pids; the filter is limited to {MAX_FILTER_PIDS}",
                self.bpf.filter_pids.len()
            )));
        }
        Ok(())
    }

    /// Serialise back to TOML.
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("Config is always serialisable")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        assert!(Config::default().validate().is_ok());
    }

    #[test]
    fn empty_file_yields_defaults() {
        assert_eq!(Config::from_toml("").unwrap(), Config::default());
    }

    #[test]
    fn round_trips_through_toml() {
        let c = Config::default();
        assert_eq!(Config::from_toml(&c.to_toml()).unwrap(), c);
    }

    #[test]
    fn partial_config_keeps_other_defaults() {
        let c = Config::from_toml(
            r#"
            [history]
            max_seconds = 60
            "#,
        )
        .unwrap();
        assert_eq!(c.history.max_seconds, 60);
        assert_eq!(
            c.history.max_events,
            HistoryConfig::default().max_events,
            "untouched keys keep their default"
        );
    }

    #[test]
    fn partial_trigger_overrides_only_what_it_names() {
        let c = Config::from_toml(
            r#"
            [pressure]
            memory = { threshold_pct = 5.0 }
            "#,
        )
        .unwrap();
        let mem = c
            .pressure
            .triggers
            .expand()
            .into_iter()
            .find(|t| t.resource == Resource::Memory)
            .unwrap();
        assert_eq!(mem.threshold_pct, 5.0);
        assert_eq!(mem.window, AvgWindow::Avg10, "default kept");
        assert_eq!(mem.consecutive, 4, "default kept");
    }

    #[test]
    fn triggers_can_be_disabled_individually() {
        let c = Config::from_toml(
            r#"
            [pressure]
            io = { enabled = false }
            "#,
        )
        .unwrap();
        let triggers = c.pressure.triggers.expand();
        let io = triggers
            .iter()
            .find(|t| t.resource == Resource::Io)
            .unwrap();
        let cpu = triggers
            .iter()
            .find(|t| t.resource == Resource::Cpu)
            .unwrap();
        assert!(!io.enabled);
        assert!(cpu.enabled);
    }

    #[test]
    fn every_resource_is_covered_exactly_once() {
        let triggers = Config::default().pressure.triggers.expand();
        assert_eq!(triggers.len(), 3);
        for r in Resource::ALL {
            assert_eq!(triggers.iter().filter(|t| t.resource == r).count(), 1);
        }
    }

    #[test]
    fn oom_defaults_to_enabled() {
        assert!(Config::default().pressure.triggers.oom.enabled);
    }

    #[test]
    fn oom_can_be_disabled_independently_of_pressure() {
        let c = Config::from_toml("[pressure]\noom = { enabled = false }\n").unwrap();
        assert!(!c.pressure.triggers.oom.enabled);
        // The pressure triggers are untouched by the OOM knob.
        assert_eq!(c.pressure.triggers.expand().len(), 3);
        assert!(c.pressure.triggers.cpu.enabled);
    }

    #[test]
    fn oom_is_not_a_pressure_resource() {
        // OOM is count-based, so it must not appear in the pressure trigger
        // list (which carries thresholds and windows it has no use for).
        let triggers = Config::default().pressure.triggers.expand();
        assert!(triggers
            .iter()
            .all(|t| t.resource != Resource::Cpu || t.enabled));
        assert_eq!(triggers.len(), 3);
    }

    #[test]
    fn unknown_oom_key_is_rejected() {
        let err = Config::from_toml("[pressure]\noom = { threshhold = 1.0 }\n").unwrap_err();
        assert!(err.to_string().contains("threshhold"));
    }

    #[test]
    fn default_thresholds_are_distinct_per_resource() {
        // A shared default would mean one threshold makes sense for both a
        // memory stall and CPU saturation, which it does not.
        let t = Config::default().pressure.triggers.expand();
        let cpu = t.iter().find(|x| x.resource == Resource::Cpu).unwrap();
        let mem = t.iter().find(|x| x.resource == Resource::Memory).unwrap();
        assert!(cpu.threshold_pct > mem.threshold_pct);
    }

    #[test]
    fn unknown_key_is_rejected_rather_than_ignored() {
        let err = Config::from_toml("[history]\nmax_secondz = 60\n").unwrap_err();
        assert!(err.to_string().contains("max_secondz"));
    }

    #[test]
    fn unknown_trigger_is_rejected() {
        assert!(Config::from_toml("[pressure]\nswap = { threshold_pct = 1.0 }\n").is_err());
    }

    #[test]
    fn zero_history_caps_are_rejected() {
        let c = Config::from_toml("[history]\nmax_events = 0\n").unwrap();
        assert!(c.validate().is_err());
    }

    #[test]
    fn out_of_range_threshold_is_rejected() {
        let c = Config::from_toml("[pressure]\nmemory = { threshold_pct = 150.0 }\n").unwrap();
        assert!(c.validate().is_err());
        let neg = Config::from_toml("[pressure]\nmemory = { threshold_pct = -1.0 }\n").unwrap();
        assert!(neg.validate().is_err());
    }

    #[test]
    fn absurd_poll_interval_is_rejected() {
        let c = Config::from_toml("[pressure]\npoll_interval_ms = 60000\n").unwrap();
        assert!(c.validate().is_err());
    }

    #[test]
    fn zero_poll_interval_is_rejected() {
        let c = Config::from_toml("[pressure]\npoll_interval_ms = 0\n").unwrap();
        assert!(c.validate().is_err());
    }

    #[test]
    fn missing_file_reports_the_path() {
        let err = Config::load(Path::new("/nonexistent/blackbox.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::Io { .. }));
        assert!(err.to_string().contains("blackbox.toml"));
    }

    /// A scratch file that certainly exists, for BPF object-path tests.
    fn scratch_object(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "bb-bpf-object-{tag}-{}-{:?}.o",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, "").unwrap();
        path
    }

    #[test]
    fn bpf_section_parses() {
        let c = Config::from_toml("[bpf]\nobject_path = \"/opt/bb/blackbox-bpf.o\"\n").unwrap();
        assert_eq!(
            c.bpf.object_path,
            Some(PathBuf::from("/opt/bb/blackbox-bpf.o"))
        );
    }

    #[test]
    fn config_without_a_bpf_section_keeps_the_default() {
        // Existing configs predate the section, so absence must mean "search"
        // and never a parse error.
        let c = Config::from_toml("[history]\nmax_seconds = 60\n").unwrap();
        assert_eq!(c.bpf, BpfConfig::default());
        assert_eq!(c.bpf.object_path, None);
    }

    #[test]
    fn unknown_bpf_key_is_rejected() {
        let err = Config::from_toml("[bpf]\nobject_pathz = \"/x\"\n").unwrap_err();
        assert!(err.to_string().contains("object_pathz"));
    }

    #[test]
    fn filter_pids_parse_and_round_trip() {
        let c = Config::from_toml("[bpf]\nfilter_pids = [100, 200, 300]\n").unwrap();
        assert_eq!(c.bpf.filter_pids, vec![100, 200, 300]);
        let back = Config::from_toml(&c.to_toml()).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn filter_pids_absent_means_trace_everything() {
        let c = Config::from_toml("[history]\nmax_seconds = 60\n").unwrap();
        assert!(c.bpf.filter_pids.is_empty(), "default must be no filter");
        assert_eq!(c.bpf, BpfConfig::default());
    }

    #[test]
    fn filter_pids_at_the_limit_is_accepted_and_above_it_is_rejected() {
        let ok = Config {
            bpf: BpfConfig {
                filter_pids: (1..=MAX_FILTER_PIDS as u32).collect(),
                ..BpfConfig::default()
            },
            ..Config::default()
        };
        assert!(ok.validate().is_ok());
        let too_many = Config {
            bpf: BpfConfig {
                filter_pids: (1..=MAX_FILTER_PIDS as u32 + 1).collect(),
                ..BpfConfig::default()
            },
            ..Config::default()
        };
        let err = too_many.validate().unwrap_err();
        assert!(
            err.to_string().contains(&format!("{MAX_FILTER_PIDS}")),
            "got: {err}"
        );
    }

    #[test]
    fn explicit_object_path_that_exists_is_used_verbatim() {
        let path = scratch_object("explicit");
        let c = Config {
            bpf: BpfConfig {
                object_path: Some(path.clone()),
                ..BpfConfig::default()
            },
            ..Config::default()
        };
        assert!(c.validate().is_ok());
        // The search list is irrelevant once a path is named.
        assert_eq!(c.bpf.resolve_object(None).unwrap(), path);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn explicit_object_path_that_is_missing_is_fatal_to_the_config() {
        let c = Config {
            bpf: BpfConfig {
                object_path: Some(PathBuf::from("/nonexistent/blackbox-bpf.o")),
                ..BpfConfig::default()
            },
            ..Config::default()
        };
        let err = c.validate().unwrap_err();
        assert!(err.to_string().contains("blackbox-bpf.o"));
        // Resolution reports the same condition under the non-fatal variant,
        // for callers that have not run validate.
        let err = c.bpf.resolve_object(None).unwrap_err();
        assert!(matches!(err, ConfigError::BpfObject(_)));
        assert!(err.to_string().contains("blackbox-bpf.o"));
    }

    #[test]
    fn env_object_is_preferred_over_the_search_list() {
        let env = scratch_object("env");
        let hit = scratch_object("hit");
        let c = Config::default();
        let found = c
            .bpf
            .resolve_object_among(Some(&env), &[hit.to_str().unwrap()])
            .unwrap();
        assert_eq!(found, env, "explicit env must win over search");
        let found = c
            .bpf
            .resolve_object_among(None, &[hit.to_str().unwrap()])
            .unwrap();
        assert_eq!(found, hit, "search applies only without an explicit path");
        let _ = std::fs::remove_file(&env);
        let _ = std::fs::remove_file(&hit);
    }

    #[test]
    fn env_object_that_is_missing_names_the_variable() {
        let err = Config::default()
            .bpf
            .resolve_object_among(Some(Path::new("/nonexistent/bb.o")), &[])
            .unwrap_err();
        assert!(err.to_string().contains(BPF_OBJECT_ENV));
    }

    #[test]
    fn search_list_is_tried_in_order() {
        let first = scratch_object("first");
        let second = scratch_object("second");
        let missing = "/nonexistent/blackbox-bpf.o";
        let c = Config::default();
        let found = c
            .bpf
            .resolve_object_among(
                None,
                &[missing, first.to_str().unwrap(), second.to_str().unwrap()],
            )
            .unwrap();
        assert_eq!(found, first, "first existing candidate must win");
        let found = c
            .bpf
            .resolve_object_among(None, &[second.to_str().unwrap(), first.to_str().unwrap()])
            .unwrap();
        assert_eq!(found, second, "order is honoured, not preference");
        let _ = std::fs::remove_file(&first);
        let _ = std::fs::remove_file(&second);
    }

    #[test]
    fn search_miss_lists_every_candidate_and_the_escape_hatches() {
        let err = Config::default()
            .bpf
            .resolve_object_among(None, &["/nope/a.o", "/nope/b.o"])
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("/nope/a.o") && msg.contains("/nope/b.o"));
        assert!(msg.contains(BPF_OBJECT_ENV));
        assert!(msg.contains("[bpf].object_path"));
    }
}
