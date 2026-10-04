//! Perfetto export.
//!
//! Emits the Chrome JSON trace format rather than Perfetto's native protobuf.
//! Perfetto's Trace Processor accepts Chrome JSON directly, so `ui.perfetto.dev`
//! opens the output with nothing installed on the reader's machine, which is the
//! single biggest adoption lever this tool has. Hand-rolling protobuf for our
//! own event types would be a lot of code for no visible gain, so protobuf stays
//! a later optimisation if dump size ever matters.
//!
//! The event model is the classic one: one complete (`ph:"X"`) event per
//! on-CPU slice, per task, so each task gets a track and a stall shows up as a
//! gap in it.

use serde_json::{json, Value};

use crate::dump::Dump;
use crate::oncpu::OnCpuSlice;

/// Knobs for export size versus completeness.
#[derive(Clone, Copy, Debug)]
pub struct ExportOptions {
    /// Maximum on-CPU slices to emit. Beyond this the oldest are dropped, since
    /// the moments just before the trigger are the interesting ones.
    pub max_slices: usize,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            max_slices: 200_000,
        }
    }
}

/// Convert a dump to Chrome JSON.
pub fn to_chrome_json(dump: &Dump) -> Result<String, serde_json::Error> {
    to_chrome_json_with(dump, ExportOptions::default())
}

pub fn to_chrome_json_with(dump: &Dump, opts: ExportOptions) -> Result<String, serde_json::Error> {
    let all = dump.slices();
    let (kept, dropped) = trim(&all, opts.max_slices);
    let base_ns = dump.window.start_monotonic_ns;

    let mut events: Vec<Value> = Vec::with_capacity(kept.len() * 2 + 4);

    // Process-name metadata first, so tracks are labelled from the outset.
    // Declared per unique pid: Chrome only accepts one per pid.
    for (pid, comm) in unique_tasks(&kept) {
        events.push(json!({
            "name": "process_name",
            "ph": "M",
            "pid": pid,
            "tid": pid,
            "args": { "name": comm },
        }));
    }

    for s in &kept {
        events.push(json!({
            "name": "on-cpu",
            "cat": "sched",
            "ph": "X",
            // Chrome trace timestamps are microseconds.
            "ts": ns_to_us(s.start_ns.saturating_sub(base_ns)),
            "dur": ns_to_us(s.duration_ns()).max(1),
            "pid": s.pid,
            "tid": s.pid,
            "args": { "cpu": s.cpu, "comm": s.comm },
        }));
    }

    // Mark where the trigger fired, so the export is self-locating.
    events.push(json!({
        "name": format!("trigger: {}", dump.trigger.reason),
        "cat": "blackbox",
        "ph": "I",
        "s": "t",
        "ts": ns_to_us(dump.window.end_monotonic_ns.saturating_sub(base_ns)),
        "pid": 0,
        "tid": 0,
        "args": { "detail": dump.trigger.detail },
    }));

    let trace = json!({
        "displayTimeUnit": "ms",
        "traceEvents": events,
        "otherData": {
            "blackbox": {
                "schemaVersion": dump.schema_version,
                "trigger": dump.trigger,
                "host": dump.host,
                "window": dump.window,
                "overhead": dump.overhead,
                "slicesEmitted": kept.len(),
                "slicesDroppedForSize": dropped,
            },
        },
    });

    serde_json::to_string(&trace)
}

fn ns_to_us(ns: u64) -> u64 {
    ns / 1_000
}

/// Drop the oldest slices once over budget, reporting how many went.
fn trim(slices: &[OnCpuSlice], max: usize) -> (Vec<OnCpuSlice>, usize) {
    if slices.len() <= max {
        return (slices.to_vec(), 0);
    }
    let start = slices.len() - max;
    (slices[start..].to_vec(), start)
}

fn unique_tasks(slices: &[OnCpuSlice]) -> Vec<(u32, String)> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for s in slices {
        if seen.insert(s.pid) {
            out.push((s.pid, s.comm.clone()));
        }
    }
    out.sort_by_key(|(pid, _)| *pid);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dump::{DumpEvent, OverheadInfo, TriggerInfo};

    const NS: u64 = 1_000_000_000;

    fn ev(ts_ns: u64, cpu: u32, prev: u32, next: u32, state: i64) -> DumpEvent {
        DumpEvent {
            ts_ns,
            cpu,
            prev_pid: prev,
            prev_comm: "prev".into(),
            prev_state: state,
            next_pid: next,
            next_comm: format!("task{next}"),
        }
    }

    fn dump_with(events: Vec<DumpEvent>, end: u64) -> Dump {
        Dump::new(
            TriggerInfo {
                reason: "manual".into(),
                detail: "test".into(),
            },
            0,
            end,
            events,
            OverheadInfo::default(),
            crate::dump::HostSnapshot::default(),
            1_700_000_000_000_000_000,
            1_700_000_000_000_000_000,
            false,
        )
    }

    fn sample() -> Dump {
        dump_with(
            vec![
                ev(0, 0, 999, 1, 1),
                ev(NS, 0, 1, 2, 0),
                ev(2 * NS, 0, 2, 1, 0),
            ],
            3 * NS,
        )
    }

    fn parse(s: &str) -> Value {
        serde_json::from_str(s).expect("valid JSON")
    }

    #[test]
    fn output_is_valid_chrome_json_with_the_expected_top_level_keys() {
        let v = parse(&to_chrome_json(&sample()).unwrap());
        assert!(v.get("traceEvents").unwrap().is_array());
        assert!(v.get("otherData").unwrap().get("blackbox").is_some());
        assert_eq!(v["displayTimeUnit"], "ms");
    }

    #[test]
    fn emits_one_complete_event_per_on_cpu_slice() {
        let v = parse(&to_chrome_json(&sample()).unwrap());
        let slices: Vec<&Value> = v["traceEvents"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["ph"] == "X")
            .collect();
        // task1, task2, task1 across the window.
        assert_eq!(slices.len(), 3);
        assert!(slices.iter().all(|e| e["cat"] == "sched"));
    }

    #[test]
    fn timestamps_are_microseconds_relative_to_window_start() {
        let v = parse(&to_chrome_json(&sample()).unwrap());
        let first = v["traceEvents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["ph"] == "X")
            .unwrap();
        assert_eq!(first["ts"], 0);
        assert_eq!(first["dur"], 1_000_000);
    }

    #[test]
    fn zero_length_slices_still_get_one_microsecond() {
        // Perfetto drops zero-duration X events, which would silently lose data.
        let d = dump_with(vec![ev(0, 0, 999, 1, 1), ev(0, 0, 1, 2, 0)], 0);
        let v = parse(&to_chrome_json(&d).unwrap());
        for e in v["traceEvents"].as_array().unwrap() {
            if e["ph"] == "X" {
                assert!(e["dur"].as_u64().unwrap() >= 1);
            }
        }
    }

    #[test]
    fn process_names_are_declared_once_per_pid() {
        let v = parse(&to_chrome_json(&sample()).unwrap());
        let meta: Vec<&Value> = v["traceEvents"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["name"] == "process_name")
            .collect();
        assert_eq!(meta.len(), 2, "task1 and task2 only");
        let mut pids: Vec<u64> = meta.iter().map(|e| e["pid"].as_u64().unwrap()).collect();
        pids.sort_unstable();
        assert_eq!(pids, vec![1, 2]);
    }

    #[test]
    fn trigger_marker_is_present_and_at_the_window_end() {
        let v = parse(&to_chrome_json(&sample()).unwrap());
        let t = v["traceEvents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["name"].as_str().unwrap().starts_with("trigger:"))
            .expect("trigger marker");
        assert_eq!(t["ts"], 3_000_000);
        assert_eq!(t["args"]["detail"], "test");
    }

    #[test]
    fn cpu_is_recorded_in_args() {
        let v = parse(&to_chrome_json(&sample()).unwrap());
        let s = v["traceEvents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["ph"] == "X")
            .unwrap();
        assert_eq!(s["args"]["cpu"], 0);
        assert_eq!(s["args"]["comm"], "task1");
    }

    #[test]
    fn metadata_records_trigger_and_overhead() {
        let v = parse(&to_chrome_json(&sample()).unwrap());
        let b = &v["otherData"]["blackbox"];
        assert_eq!(b["trigger"]["reason"], "manual");
        assert_eq!(b["schemaVersion"], crate::dump::SCHEMA_VERSION);
        assert!(b["overhead"].is_object());
    }

    #[test]
    fn slice_budget_drops_the_oldest_and_says_so() {
        // Alternate the running task so each event produces a distinct slice,
        // rather than repeating one pid and merging into a single interval.
        let events: Vec<DumpEvent> = (0..50u64)
            .map(|i| {
                let (prev, next) = if i % 2 == 1 { (1, 2) } else { (2, 1) };
                ev(i * NS, 0, prev, next, 0)
            })
            .collect();
        let d = dump_with(events, 50 * NS);
        assert_eq!(d.slices().len(), 50, "fixture should yield 50 slices");

        let opts = ExportOptions { max_slices: 10 };
        let v = parse(&to_chrome_json_with(&d, opts).unwrap());
        let n = v["traceEvents"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["ph"] == "X")
            .count();
        assert_eq!(n, 10);
        assert_eq!(v["otherData"]["blackbox"]["slicesDroppedForSize"], 40);
    }

    #[test]
    fn within_budget_nothing_is_dropped() {
        let v = parse(&to_chrome_json(&sample()).unwrap());
        assert_eq!(v["otherData"]["blackbox"]["slicesDroppedForSize"], 0);
        assert_eq!(v["otherData"]["blackbox"]["slicesEmitted"], 3);
    }

    #[test]
    fn empty_dump_still_produces_a_loadable_trace() {
        let d = dump_with(vec![], 0);
        let s = to_chrome_json(&d).unwrap();
        let v = parse(&s);
        assert!(v["traceEvents"].is_array());
    }

    #[test]
    fn export_is_deterministic() {
        assert_eq!(
            to_chrome_json(&sample()).unwrap(),
            to_chrome_json(&sample()).unwrap()
        );
    }
}
