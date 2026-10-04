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

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub history: HistoryConfig,
    pub pressure: PressureConfig,
    pub dump: DumpConfig,
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
/// ```
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PressureTriggers {
    pub cpu: TriggerTuning,
    pub memory: TriggerTuning,
    pub io: TriggerTuning,
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
}
