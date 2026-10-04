//! The on-disk dump format.
//!
//! A dump is the product of the whole tool, so the schema is deliberate: it is
//! native JSON rather than Perfetto's Chrome JSON, because it has to carry the
//! trigger reason, host metadata and self-overhead counters, and because a
//! native format can absorb the v0.3 event types without breaking anyone.
//! `blackbox report --perfetto` converts it on demand.
//!
//! Timestamps in `events` are raw monotonic nanoseconds (`CLOCK_MONOTONIC`),
//! exactly as the kernel reported them, because that is the clock the scheduler
//! tracepoints use and interpolating it is lossy. `clock_offset_ns` anchors them
//! to wall time so a reader can render a real date without trusting the
//! individual events.

use serde::{Deserialize, Serialize};

/// Bumped whenever the meaning of an existing field changes.
///
/// The event record is also a BPF wire struct, so changing its layout requires
/// bumping this as well as rebuilding the BPF object.
pub const SCHEMA_VERSION: u32 = 1;

use crate::event::SchedSwitch;

/// A serialisable event, with comms as JSON strings rather than byte arrays.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DumpEvent {
    pub ts_ns: u64,
    pub cpu: u32,
    pub prev_pid: u32,
    pub prev_comm: String,
    /// 0 means the outgoing task was still runnable. See
    /// [`crate::event::TASK_RUNNING`].
    pub prev_state: i64,
    pub next_pid: u32,
    pub next_comm: String,
}

impl From<&SchedSwitch> for DumpEvent {
    fn from(ev: &SchedSwitch) -> Self {
        Self {
            ts_ns: ev.ts_ns,
            cpu: ev.cpu,
            prev_pid: ev.prev_pid,
            prev_comm: ev.prev_comm_str().to_owned(),
            prev_state: ev.prev_state,
            next_pid: ev.next_pid,
            next_comm: ev.next_comm_str().to_owned(),
        }
    }
}

/// Why this dump was written.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TriggerInfo {
    /// Machine-readable kind, e.g. `psi_memory` or `manual`.
    pub reason: String,
    /// Human-readable elaboration, shown verbatim in reports.
    pub detail: String,
}

/// The span of scheduler history the dump covers.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct WindowInfo {
    /// Monotonic nanoseconds (CLOCK_MONOTONIC) of the oldest and newest
    /// retained events. These are what the kernel actually reported, so they
    /// are authoritative for computing durations.
    pub start_monotonic_ns: u64,
    pub end_monotonic_ns: u64,
    /// The same instants in wall-clock nanoseconds since the epoch, so a dump
    /// can be dated without re-deriving the offset.
    pub start_unix_ns: u64,
    pub end_unix_ns: u64,
    /// Width of the retained window, which may be shorter than the configured
    /// maximum if the daemon started recently.
    pub span_ns: u64,
    /// True when the retained history hit a cap, meaning events were lost and
    /// any aggregate below is a lower bound rather than a complete picture.
    pub truncated: bool,
}

/// The daemon's own cost, recorded so a dump is self-describing about the
/// trustworthiness of its contents.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct OverheadInfo {
    /// Events currently retained in the history window.
    pub events_recorded: u64,
    /// Events dropped from the front because our own window was full.
    pub events_evicted: u64,
    /// Events the *kernel* ring buffer dropped because the daemon could not
    /// drain fast enough. This is the one that matters: it means the trace has
    /// holes and per-task totals may undercount.
    pub events_dropped_kernel: u64,
}

impl OverheadInfo {
    /// True when the trace may be missing events.
    pub fn lossy(&self) -> bool {
        self.events_dropped_kernel > 0
    }
}

/// One complete dump.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Dump {
    pub schema_version: u32,
    /// Wall-clock nanoseconds at the moment the dump was written.
    pub generated_unix_ns: u64,
    /// `CLOCK_REALTIME - CLOCK_MONOTONIC` at dump time. Add to a monotonic
    /// event timestamp to get wall-clock nanoseconds.
    pub clock_offset_ns: i64,
    pub trigger: TriggerInfo,
    pub window: WindowInfo,
    pub host: HostSnapshot,
    pub overhead: OverheadInfo,
    pub events: Vec<DumpEvent>,
}

/// Host facts worth having next to every dump, since a trace without them is
/// hard to act on later.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct HostSnapshot {
    pub hostname: String,
    pub kernel: String,
    pub boot_id: String,
    pub uptime_ns: u64,
}

impl Dump {
    /// Convert a monotonic event timestamp to wall-clock nanoseconds.
    pub fn unix_ns(&self, monotonic_ns: u64) -> u64 {
        (monotonic_ns as i64 + self.clock_offset_ns).max(0) as u64
    }

    /// Monotonic timestamps, chronological.
    pub fn monotonic_span(&self) -> u64 {
        self.events
            .windows(2)
            .map(|w| w[1].ts_ns.saturating_sub(w[0].ts_ns))
            .sum()
    }

    /// Verify the record and rebuild the on-CPU intervals.
    pub fn slices(&self) -> Vec<crate::oncpu::OnCpuSlice> {
        let events: Vec<SchedSwitch> = self
            .events
            .iter()
            .map(|e| {
                SchedSwitch::new(
                    e.ts_ns,
                    e.cpu,
                    e.prev_pid,
                    e.next_pid,
                    e.prev_state,
                    e.prev_comm.as_bytes(),
                    e.next_comm.as_bytes(),
                )
            })
            .collect();
        crate::oncpu::reconstruct(&events, self.window.end_monotonic_ns)
    }

    /// Off-CPU gaps implied by the event stream.
    pub fn gaps(&self) -> Vec<crate::oncpu::TaskGap> {
        crate::oncpu::gaps(&self.slices())
    }

    /// Reject anything that cannot be interpreted.
    ///
    /// Called on load so a corrupt or foreign file fails with a clear message
    /// instead of producing a plausible-looking but wrong report.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(format!(
                "unsupported schema_version {} (this build understands {SCHEMA_VERSION})",
                self.schema_version
            ));
        }
        if self.events.windows(2).any(|w| w[1].ts_ns < w[0].ts_ns) {
            return Err("events are not in chronological order".into());
        }
        Ok(())
    }

    /// Construct a dump, deriving the wall-clock fields from monotonic
    /// endpoints and an offset read at the same instant.
    /// Nine fields, one call: this constructor exists so the derived wall-clock and
    /// window fields cannot be built inconsistently at each call site.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trigger: TriggerInfo,
        window_start_mono: u64,
        window_end_mono: u64,
        events: Vec<DumpEvent>,
        overhead: OverheadInfo,
        host: HostSnapshot,
        generated_unix_ns: u64,
        clock_offset_ns: i64,
        truncated: bool,
    ) -> Self {
        let start_unix_ns = (window_start_mono as i64 + clock_offset_ns).max(0) as u64;
        let end_unix_ns = (window_end_mono as i64 + clock_offset_ns).max(0) as u64;
        Self {
            schema_version: SCHEMA_VERSION,
            generated_unix_ns,
            clock_offset_ns,
            trigger,
            window: WindowInfo {
                start_monotonic_ns: window_start_mono,
                end_monotonic_ns: window_end_mono,
                start_unix_ns,
                end_unix_ns,
                span_ns: window_end_mono.saturating_sub(window_start_mono),
                truncated,
            },
            host,
            overhead,
            events,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(ts_ns: u64, cpu: u32, prev: u32, next: u32, state: i64) -> DumpEvent {
        DumpEvent {
            ts_ns,
            cpu,
            prev_pid: prev,
            prev_comm: "prev".into(),
            prev_state: state,
            next_pid: next,
            next_comm: "next".into(),
        }
    }

    fn dump() -> Dump {
        Dump::new(
            TriggerInfo {
                reason: "manual".into(),
                detail: "requested".into(),
            },
            // Window deliberately extends past the last event, as it does in practice, so
            // the task still running at the end gets a non-zero slice.
            0,
            21_000_000_000,
            vec![
                ev(0, 0, 999, 1, 1),
                ev(10_000_000_000, 0, 1, 2, 0),
                ev(20_000_000_000, 0, 2, 1, 0),
            ],
            OverheadInfo {
                events_recorded: 3,
                events_evicted: 0,
                events_dropped_kernel: 0,
            },
            HostSnapshot::default(),
            1_700_000_000_000_000_000,
            1_700_000_000_000_000_000,
            false,
        )
    }

    #[test]
    fn monotonic_timestamps_convert_to_wall_clock() {
        let d = dump();
        assert_eq!(d.unix_ns(0), 1_700_000_000_000_000_000);
        assert_eq!(d.unix_ns(10_000_000_000), 1_700_000_010_000_000_000u64);
    }

    #[test]
    fn derived_window_fields_are_consistent() {
        let d = dump();
        assert_eq!(d.window.span_ns, 21_000_000_000);
        assert_eq!(d.window.start_monotonic_ns, 0);
        assert_eq!(d.window.end_monotonic_ns, 21_000_000_000);
        assert_eq!(
            d.window.end_unix_ns - d.window.start_unix_ns,
            d.window.span_ns
        );
    }

    #[test]
    fn slices_reconstruct_from_the_serialised_events() {
        let s = dump().slices();
        assert_eq!(s.len(), 3);
        assert_eq!(s[0].pid, 1);
        assert_eq!(s[0].duration_ns(), 10_000_000_000);
    }

    #[test]
    fn comms_survive_the_round_trip_through_strings() {
        let s = dump().slices();
        assert!(s.iter().all(|x| x.comm == "next"));
    }

    #[test]
    fn validation_rejects_a_foreign_schema_version() {
        let mut d = dump();
        d.schema_version = 99;
        assert!(d
            .validate()
            .unwrap_err()
            .contains("unsupported schema_version"));
    }

    #[test]
    fn validation_rejects_out_of_order_events() {
        let mut d = dump();
        d.events.swap(0, 2);
        assert!(d.validate().is_err());
    }

    #[test]
    fn validation_accepts_a_good_dump() {
        assert_eq!(dump().validate(), Ok(()));
    }

    #[test]
    fn round_trips_through_json() {
        let d = dump();
        let text = serde_json::to_string_pretty(&d).unwrap();
        let back: Dump = serde_json::from_str(&text).unwrap();
        assert_eq!(back, d);
        assert_eq!(back.validate(), Ok(()));
    }

    #[test]
    fn lossy_flag_reflects_only_kernel_side_drops() {
        let mut o = OverheadInfo {
            events_recorded: 10,
            events_evicted: 100,
            events_dropped_kernel: 0,
        };
        assert!(!o.lossy(), "our own eviction does not make the trace lossy");
        o.events_dropped_kernel = 1;
        assert!(o.lossy());
    }
}
