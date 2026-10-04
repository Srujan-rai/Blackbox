//! PSI (Pressure Stall Information) parsing and trigger evaluation.
//!
//! PSI needs no BPF at all. The kernel already maintains the accounting and
//! publishes it as text under /proc/pressure, so polling it from userspace is
//! both simpler and more reliable than sampling in the kernel, and it keeps the
//! privileged surface of the daemon down to event collection only.
//!
//! The part that matters is hysteresis. A single sample above threshold is
//! usually a blip, and a tool that dumps on every blip is worse than useless
//! because it fills the disk and trains people to ignore it. A trigger
//! therefore has to stay over threshold for a configurable number of
//! consecutive samples, and once it fires it stays quiet until the pressure
//! has genuinely receded.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Which pressure resource a reading describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Resource {
    Cpu,
    Memory,
    Io,
}

impl Resource {
    pub const ALL: [Resource; 3] = [Resource::Cpu, Resource::Memory, Resource::Io];

    /// File name under /proc/pressure.
    pub fn file_name(self) -> &'static str {
        match self {
            Resource::Cpu => "cpu",
            Resource::Memory => "memory",
            Resource::Io => "io",
        }
    }

    pub fn as_str(self) -> &'static str {
        self.file_name()
    }
}

/// One `avgNN=`/`total=` line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PsiStat {
    pub avg10: f64,
    pub avg60: f64,
    pub avg300: f64,
    pub total: u64,
}

/// A resource's `some` and optional `full` lines.
///
/// `full` is absent for `io` on kernels before 5.13, so it is optional.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PsiSample {
    pub some: PsiStat,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full: Option<PsiStat>,
}

/// All three resources as read in one polling round.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PsiSnapshot {
    pub cpu: PsiSample,
    pub memory: PsiSample,
    pub io: PsiSample,
}

impl PsiSnapshot {
    pub fn get(&self, resource: Resource) -> PsiSample {
        match resource {
            Resource::Cpu => self.cpu,
            Resource::Memory => self.memory,
            Resource::Io => self.io,
        }
    }
}

/// Which exponential moving average a trigger watches.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AvgWindow {
    /// Reacts in seconds. Noisy, but right for catching a sudden stall.
    #[default]
    Avg10,
    /// Reacts in a minute. Right for a system degrading over time.
    Avg60,
    /// Smoothed over five minutes. For chronic problems.
    Avg300,
}

impl AvgWindow {
    pub fn value(self, stat: &PsiStat) -> f64 {
        match self {
            AvgWindow::Avg10 => stat.avg10,
            AvgWindow::Avg60 => stat.avg60,
            AvgWindow::Avg300 => stat.avg300,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            AvgWindow::Avg10 => "avg10",
            AvgWindow::Avg60 => "avg60",
            AvgWindow::Avg300 => "avg300",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PsiError {
    #[error("io error reading {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("unexpected PSI format in {path}: {reason}")]
    Format { path: String, reason: String },
    #[error("no 'some' line found in {path}")]
    MissingSome { path: String },
}

/// Parse the contents of one /proc/pressure/<resource> file.
pub fn parse(text: &str, path: &str) -> Result<PsiSample, PsiError> {
    let mut sample = PsiSample::default();
    let mut seen_some = false;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (kind, stat) = parse_line(line).ok_or_else(|| PsiError::Format {
            path: path.to_owned(),
            reason: format!("cannot parse line {line:?}"),
        })?;
        match kind {
            "some" => {
                sample.some = stat;
                seen_some = true;
            }
            "full" => sample.full = Some(stat),
            _ => {}
        }
    }

    if !seen_some {
        return Err(PsiError::MissingSome {
            path: path.to_owned(),
        });
    }
    Ok(sample)
}

fn parse_line(line: &str) -> Option<(&str, PsiStat)> {
    let mut words = line.split_whitespace();
    let kind = words.next()?;
    let mut stat = PsiStat::default();
    for kv in words {
        let (key, value) = kv.split_once('=')?;
        let v: f64 = value.parse().ok()?;
        match key {
            "avg10" => stat.avg10 = v,
            "avg60" => stat.avg60 = v,
            "avg300" => stat.avg300 = v,
            "total" => stat.total = v.max(0.0) as u64,
            // Unknown keys are ignored: the kernel has added fields before.
            _ => {}
        }
    }
    Some((kind, stat))
}

/// Read one resource from /proc/pressure.
pub fn read_resource(base: &Path, resource: Resource) -> Result<PsiSample, PsiError> {
    let path = base.join("pressure").join(resource.file_name());
    let text = std::fs::read_to_string(&path).map_err(|source| PsiError::Io {
        path: path.display().to_string(),
        source,
    })?;
    parse(&text, &path.display().to_string())
}

/// Read every resource from a /proc root.
pub fn read_snapshot(base: &Path) -> Result<PsiSnapshot, PsiError> {
    Ok(PsiSnapshot {
        cpu: read_resource(base, Resource::Cpu)?,
        memory: read_resource(base, Resource::Memory)?,
        io: read_resource(base, Resource::Io)?,
    })
}

/// A configured trigger condition.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct PressureTrigger {
    pub resource: Resource,
    pub enabled: bool,
    pub window: AvgWindow,
    /// Stall percentage, 0..=100, on the `some` line.
    pub threshold_pct: f64,
    /// Consecutive samples over threshold before firing.
    pub consecutive: u32,
}

impl Default for PressureTrigger {
    fn default() -> Self {
        Self {
            resource: Resource::Memory,
            enabled: true,
            window: AvgWindow::Avg10,
            threshold_pct: 20.0,
            consecutive: 4,
        }
    }
}

/// A trigger that has just fired, with everything a report needs to explain it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TriggerFired {
    pub resource: Resource,
    pub window: AvgWindow,
    pub value_pct: f64,
    pub threshold_pct: f64,
    pub consecutive: u32,
}

impl TriggerFired {
    /// One-line human-readable explanation, embedded verbatim in the dump.
    pub fn describe(&self) -> String {
        format!(
            "psi {} {}={:.2}% >= {:.2}% for {} consecutive samples",
            self.resource.as_str(),
            self.window.label(),
            self.value_pct,
            self.threshold_pct,
            self.consecutive,
        )
    }
}

#[derive(Clone, Copy, Debug)]
struct Slot {
    streak: u32,
    /// Cleared on fire; re-armed only once pressure drops below threshold.
    armed: bool,
}

/// Stateful trigger evaluation across polling rounds.
#[derive(Debug)]
pub struct PressureMonitor {
    triggers: Vec<PressureTrigger>,
    slots: BTreeMap<Resource, Slot>,
}

impl PressureMonitor {
    pub fn new(triggers: Vec<PressureTrigger>) -> Self {
        let slots = triggers
            .iter()
            .map(|t| {
                (
                    t.resource,
                    Slot {
                        streak: 0,
                        armed: true,
                    },
                )
            })
            .collect();
        Self { triggers, slots }
    }

    pub fn triggers(&self) -> &[PressureTrigger] {
        &self.triggers
    }

    /// Fold one polling round in and report which triggers fired.
    ///
    /// At most one trigger per resource can fire per round: firing clears that
    /// resource's arm, so a sustained stall produces one dump rather than one
    /// dump per sample.
    pub fn observe(&mut self, snapshot: &PsiSnapshot) -> Vec<TriggerFired> {
        let mut fired = Vec::new();
        for trigger in &self.triggers {
            if !trigger.enabled || trigger.consecutive == 0 {
                continue;
            }
            let value = AvgWindow::value(trigger.window, &snapshot.get(trigger.resource).some);
            let slot = self.slots.entry(trigger.resource).or_insert(Slot {
                streak: 0,
                armed: true,
            });

            if value < trigger.threshold_pct {
                slot.streak = 0;
                slot.armed = true;
                continue;
            }

            slot.streak = slot.streak.saturating_add(1);
            if slot.armed && slot.streak >= trigger.consecutive {
                slot.armed = false;
                fired.push(TriggerFired {
                    resource: trigger.resource,
                    window: trigger.window,
                    value_pct: value,
                    threshold_pct: trigger.threshold_pct,
                    consecutive: trigger.consecutive,
                });
            }
        }
        fired
    }
}

impl Default for PressureMonitor {
    fn default() -> Self {
        Self::new(vec![PressureTrigger::default()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CPU_FILE: &str = "some avg10=1.50 avg60=0.75 avg300=0.25 total=98765\n\
         full avg10=0.50 avg60=0.25 avg300=0.10 total=12345\n";
    const IO_SOME_ONLY: &str = "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";

    fn mem_with(avg10: f64) -> PsiSnapshot {
        PsiSnapshot {
            memory: PsiSample {
                some: PsiStat {
                    avg10,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn trigger(window: AvgWindow, pct: f64, consecutive: u32) -> PressureTrigger {
        PressureTrigger {
            resource: Resource::Memory,
            enabled: true,
            window,
            threshold_pct: pct,
            consecutive,
        }
    }

    #[test]
    fn parses_both_lines() {
        let s = parse(CPU_FILE, "cpu").unwrap();
        assert_eq!(s.some.avg10, 1.50);
        assert_eq!(s.some.avg60, 0.75);
        assert_eq!(s.some.avg300, 0.25);
        assert_eq!(s.some.total, 98765);
        assert_eq!(s.full.expect("full line").avg10, 0.50);
        assert_eq!(s.full.expect("full line").total, 12345);
    }

    #[test]
    fn full_line_is_optional() {
        let s = parse(IO_SOME_ONLY, "io").unwrap();
        assert_eq!(s.some.avg10, 0.0);
        assert_eq!(s.full, None);
    }

    #[test]
    fn missing_some_line_is_an_error() {
        let err = parse("full avg10=0.0 avg60=0.0 avg300=0.0 total=0\n", "x").unwrap_err();
        assert!(matches!(err, PsiError::MissingSome { .. }));
    }

    #[test]
    fn unknown_keys_are_tolerated() {
        let s = parse(
            "some avg10=1.0 avg60=2.0 avg300=3.0 total=4 future=99\n",
            "x",
        )
        .unwrap();
        assert_eq!(s.some.avg10, 1.0);
    }

    #[test]
    fn garbage_is_rejected_rather_than_parsed_as_zero() {
        assert!(parse("some avg10=notanumber\n", "x").is_err());
    }

    #[test]
    fn blank_lines_and_whitespace_are_tolerated() {
        let s = parse("\n  some avg10=5.0 avg60=0.0 avg300=0.0 total=1  \n\n", "x").unwrap();
        assert_eq!(s.some.avg10, 5.0);
    }

    #[test]
    fn each_window_reads_its_own_average() {
        let stat = PsiStat {
            avg10: 1.0,
            avg60: 2.0,
            avg300: 3.0,
            total: 0,
        };
        assert_eq!(AvgWindow::Avg10.value(&stat), 1.0);
        assert_eq!(AvgWindow::Avg60.value(&stat), 2.0);
        assert_eq!(AvgWindow::Avg300.value(&stat), 3.0);
    }

    #[test]
    fn does_not_fire_before_the_consecutive_count_is_reached() {
        let mut m = PressureMonitor::new(vec![trigger(AvgWindow::Avg10, 20.0, 3)]);
        for _ in 0..2 {
            assert!(m.observe(&mem_with(50.0)).is_empty());
        }
        assert_eq!(m.observe(&mem_with(50.0)).len(), 1);
    }

    #[test]
    fn a_single_spike_below_threshold_never_accumulates() {
        let mut m = PressureMonitor::new(vec![trigger(AvgWindow::Avg10, 20.0, 3)]);
        assert!(m.observe(&mem_with(50.0)).is_empty());
        assert!(m.observe(&mem_with(1.0)).is_empty(), "must reset streak");
        assert!(m.observe(&mem_with(50.0)).is_empty());
        assert!(m.observe(&mem_with(1.0)).is_empty());
    }

    #[test]
    fn sustained_stall_fires_once_not_once_per_sample() {
        let mut m = PressureMonitor::new(vec![trigger(AvgWindow::Avg10, 20.0, 2)]);
        assert!(m.observe(&mem_with(50.0)).is_empty());
        assert_eq!(m.observe(&mem_with(50.0)).len(), 1, "fires here");
        for _ in 0..20 {
            assert!(m.observe(&mem_with(50.0)).is_empty(), "must stay quiet");
        }
    }

    #[test]
    fn trigger_rearms_only_after_pressure_recedes() {
        let mut m = PressureMonitor::new(vec![trigger(AvgWindow::Avg10, 20.0, 1)]);
        assert_eq!(m.observe(&mem_with(50.0)).len(), 1);
        assert!(m.observe(&mem_with(50.0)).is_empty());
        assert!(m.observe(&mem_with(5.0)).is_empty(), "pressure receded");
        assert_eq!(m.observe(&mem_with(50.0)).len(), 1, "rearmed");
    }

    #[test]
    fn disabled_triggers_never_fire() {
        let mut t = trigger(AvgWindow::Avg10, 1.0, 1);
        t.enabled = false;
        let mut m = PressureMonitor::new(vec![t]);
        assert!(m.observe(&mem_with(100.0)).is_empty());
    }

    #[test]
    fn zero_consecutive_never_fires_instead_of_firing_immediately() {
        let mut m = PressureMonitor::new(vec![trigger(AvgWindow::Avg10, 1.0, 0)]);
        assert!(m.observe(&mem_with(100.0)).is_empty());
    }

    #[test]
    fn exact_threshold_counts_as_over() {
        let mut m = PressureMonitor::new(vec![trigger(AvgWindow::Avg10, 20.0, 1)]);
        assert_eq!(m.observe(&mem_with(20.0)).len(), 1);
    }

    #[test]
    fn independent_resources_fire_independently() {
        let mut m = PressureMonitor::new(vec![
            trigger(AvgWindow::Avg10, 20.0, 1),
            PressureTrigger {
                resource: Resource::Io,
                ..trigger(AvgWindow::Avg10, 20.0, 1)
            },
        ]);
        let snap = PsiSnapshot {
            memory: PsiSample {
                some: PsiStat {
                    avg10: 50.0,
                    ..Default::default()
                },
                ..Default::default()
            },
            io: PsiSample {
                some: PsiStat {
                    avg10: 5.0,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let fired = m.observe(&snap);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].resource, Resource::Memory);
    }

    #[test]
    fn fired_trigger_describes_itself() {
        let f = TriggerFired {
            resource: Resource::Memory,
            window: AvgWindow::Avg10,
            value_pct: 41.25,
            threshold_pct: 20.0,
            consecutive: 4,
        };
        assert_eq!(
            f.describe(),
            "psi memory avg10=41.25% >= 20.00% for 4 consecutive samples"
        );
    }

    #[test]
    fn snapshot_lookup_matches_resource() {
        let s = PsiSnapshot {
            cpu: PsiSample {
                some: PsiStat {
                    avg10: 1.0,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(s.get(Resource::Cpu).some.avg10, 1.0);
    }

    #[test]
    fn reads_from_a_fake_proc_tree() {
        let dir = std::env::temp_dir().join(format!("bb-psi-{}", std::process::id()));
        let pressure = dir.join("pressure");
        std::fs::create_dir_all(&pressure).unwrap();
        for r in Resource::ALL {
            std::fs::write(pressure.join(r.file_name()), CPU_FILE).unwrap();
        }

        let snap = read_snapshot(&dir).expect("snapshot");
        assert_eq!(snap.cpu.some.avg10, 1.50);
        assert_eq!(snap.memory.some.total, 98765);
        assert_eq!(snap.io.full.expect("full").avg10, 0.50);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_file_is_an_io_error() {
        let dir = std::env::temp_dir().join(format!("bb-psi-none-{}", std::process::id()));
        assert!(matches!(
            read_resource(&dir, Resource::Cpu),
            Err(PsiError::Io { .. })
        ));
    }
}
