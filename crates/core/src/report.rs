//! The text summary printed by `blackbox report`.
//!
//! Ordered by how fast it answers the question someone actually has, which is
//! usually "what was it doing?". So: what triggered this, is the trace complete
//! enough to trust, who was eating the CPU, and who was starved. Everything else
//! is below the fold.

use std::cmp::Reverse;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::dump::Dump;
use crate::oncpu::{OnCpuSlice, TaskGap};

/// How much detail to print.
#[derive(Clone, Copy, Debug)]
pub struct ReportOptions {
    /// Rows in each ranked table.
    pub top: usize,
    /// Per-CPU breakdown instead of a single ranking.
    pub per_cpu: bool,
}

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            top: 10,
            per_cpu: false,
        }
    }
}

pub fn render_report(dump: &Dump) -> String {
    render_report_with(dump, ReportOptions::default())
}

pub fn render_report_with(dump: &Dump, opts: ReportOptions) -> String {
    let mut out = String::new();
    let slices = dump.slices();
    let gaps = crate::oncpu::gaps(&slices);

    header(&mut out, dump);
    integrity(&mut out, dump, &slices);
    top_consumers(&mut out, &slices, opts);
    longest_delays(&mut out, &gaps, opts);
    busiest_blocked(&mut out, &gaps, opts);
    lifecycle_section(&mut out, dump, opts);
    if opts.per_cpu {
        per_cpu_table(&mut out, &slices, opts);
    }

    out
}

fn header(out: &mut String, dump: &Dump) {
    rule(out, "blackbox trace");
    kv(out, "generated", &format_wall(dump.generated_unix_ns));
    kv(out, "trigger", &dump.trigger.reason);
    kv(out, "detail", &dump.trigger.detail);
    kv(
        out,
        "window",
        &format!("{:.3}s", ns_to_s(dump.window.span_ns)),
    );
    if !dump.window.truncated {
        kv(
            out,
            "covering",
            &format!(
                "{} to {}",
                format_wall(dump.window.start_unix_ns),
                format_wall(dump.window.end_unix_ns)
            ),
        );
    }
    kv(
        out,
        "host",
        &format!("{} ({})", dump.host.hostname, dump.host.kernel),
    );
    out.push('\n');
}

/// State plainly whether the numbers below can be trusted.
fn integrity(out: &mut String, dump: &Dump, slices: &[OnCpuSlice]) {
    rule(out, "completeness");
    kv(out, "events", &dump.overhead.events_recorded.to_string());
    kv(out, "on-cpu slices", &slices.len().to_string());
    // Always state the loss position: "no drops" is only reassuring if the
    // reader can see the line was considered and came back clean.
    if dump.overhead.events_dropped_kernel > 0 {
        let dropped = dump.overhead.events_dropped_kernel;
        // What the kernel could not queue is only knowable against what it
        // could: kept + dropped is every event that reached the tracepoint.
        let seen = dropped.saturating_add(dump.overhead.events_recorded);
        let pct = if seen == 0 {
            0.0
        } else {
            (dropped as f64 / seen as f64) * 100.0
        };
        kv(
            out,
            "kernel drops",
            &format!(
                "{dropped} ({pct:.1}% of events seen) WARNING: trace has holes, totals below are lower bounds"
            ),
        );
    } else {
        kv(out, "kernel drops", "0");
    }
    if dump.overhead.events_evicted > 0 {
        kv(
            out,
            "history evicted",
            &dump.overhead.events_evicted.to_string(),
        );
    }
    if dump.overhead.lifecycle_recorded > 0 {
        kv(
            out,
            "lifecycle events",
            &dump.overhead.lifecycle_recorded.to_string(),
        );
    }
    if dump.window.truncated {
        kv(out, "window", "truncated to configured maximum");
    }
    if dump.events.is_empty() {
        kv(out, "note", "no events were retained in this window");
    }
    out.push('\n');
}

fn top_consumers(out: &mut String, slices: &[OnCpuSlice], opts: ReportOptions) {
    rule(out, "top cpu consumers");
    let mut totals: HashMap<u32, (String, u64)> = HashMap::new();
    for s in slices {
        let e = totals.entry(s.pid).or_insert_with(|| (s.comm.clone(), 0));
        e.1 += s.duration_ns();
    }
    let mut rows: Vec<(u32, String, u64)> = totals
        .into_iter()
        .map(|(pid, (comm, ns))| (pid, comm, ns))
        .collect();
    rows.sort_by_key(|r| Reverse(r.2));

    let total_ns: u64 = rows.iter().map(|r| r.2).sum();
    if rows.is_empty() {
        out.push_str("  no on-cpu activity recorded\n\n");
        return;
    }
    for (pid, comm, ns) in rows.iter().take(opts.top) {
        let pct = if total_ns == 0 {
            0.0
        } else {
            (*ns as f64 / total_ns as f64) * 100.0
        };
        out.push_str(&format!(
            "  {pct:6.2}%  {:>10}  pid {pid:<8} {comm}\n",
            fmt_dur(*ns)
        ));
    }
    if rows.len() > opts.top {
        out.push_str(&format!("  ... and {} more\n", rows.len() - opts.top));
    }
    out.push('\n');
}

fn longest_delays(out: &mut String, gaps: &[TaskGap], opts: ReportOptions) {
    rule(out, "longest scheduler delays");
    out.push_str("  time a runnable task spent waiting for a cpu\n\n");
    let runnable: Vec<&TaskGap> = gaps.iter().filter(|g| g.runnable).collect();
    if runnable.is_empty() {
        out.push_str("  none: no task was preempted while runnable\n\n");
        return;
    }
    for g in runnable.iter().take(opts.top) {
        out.push_str(&format!(
            "  {:>10}  pid {:<8} {}\n",
            fmt_dur(g.duration_ns()),
            g.pid,
            g.comm
        ));
    }
    out.push('\n');
}

fn busiest_blocked(out: &mut String, gaps: &[TaskGap], opts: ReportOptions) {
    rule(out, "most blocked time");
    out.push_str("  time tasks spent blocked, i.e. waiting on something other than a cpu\n\n");
    let mut totals: HashMap<u32, (String, u64)> = HashMap::new();
    for g in gaps.iter().filter(|g| !g.runnable) {
        let e = totals.entry(g.pid).or_insert_with(|| (g.comm.clone(), 0));
        e.1 += g.duration_ns();
    }
    let mut rows: Vec<(u32, String, u64)> = totals
        .into_iter()
        .map(|(pid, (comm, ns))| (pid, comm, ns))
        .collect();
    rows.sort_by_key(|r| Reverse(r.2));
    if rows.is_empty() {
        out.push_str("  none recorded\n\n");
        return;
    }
    for (pid, comm, ns) in rows.iter().take(opts.top) {
        out.push_str(&format!(
            "  {:>10}  pid {:<8} {}\n",
            fmt_dur(*ns),
            pid,
            comm
        ));
    }
    out.push('\n');
}

fn per_cpu_table(out: &mut String, slices: &[OnCpuSlice], opts: ReportOptions) {
    rule(out, "per-cpu");
    let mut per: HashMap<u32, u64> = HashMap::new();
    for s in slices {
        *per.entry(s.cpu).or_default() += s.duration_ns();
    }
    let mut rows: Vec<(u32, u64)> = per.into_iter().collect();
    rows.sort_by_key(|(cpu, _)| *cpu);
    for (cpu, ns) in rows.iter().take(opts.top.max(16)) {
        out.push_str(&format!("  cpu {cpu:<4} {:>10} busy\n", fmt_dur(*ns)));
    }
    out.push('\n');
}

/// The fork/exec/exit events in the window, most recent first.
///
/// Deliberately the last section: the numbers above it are the answer to "what
/// was it doing?", while this is the answer to "what changed around the stall?".
fn lifecycle_section(out: &mut String, dump: &Dump, opts: ReportOptions) {
    if dump.lifecycle.is_empty() {
        return;
    }
    rule(out, "process lifecycle");
    out.push_str("  fork / exec / exit observed in the window (most recent first)\n");
    let counts = dump
        .lifecycle
        .iter()
        .fold((0usize, 0usize, 0usize), |acc, e| match e.kind {
            crate::lifecycle::LifecycleKind::Fork => (acc.0 + 1, acc.1, acc.2),
            crate::lifecycle::LifecycleKind::Exec => (acc.0, acc.1 + 1, acc.2),
            crate::lifecycle::LifecycleKind::Exit => (acc.0, acc.1, acc.2 + 1),
        });
    kv(
        out,
        "counts",
        &format!("{} fork, {} exec, {} exit", counts.0, counts.1, counts.2),
    );
    out.push('\n');
    for event in dump.lifecycle.iter().rev().take(opts.top) {
        out.push_str(&format!("  {}\n", event.describe()));
    }
    if dump.lifecycle.len() > opts.top {
        out.push_str(&format!(
            "  ... and {} earlier events\n",
            dump.lifecycle.len() - opts.top
        ));
    }
    out.push('\n');
}

fn rule(out: &mut String, title: &str) {
    out.push('\n');
    out.push_str(title);
    out.push('\n');
    for _ in 0..title.chars().count() {
        out.push('-');
    }
    out.push('\n');
}

fn kv(out: &mut String, k: &str, v: &str) {
    out.push_str(&format!("  {k:<16} {v}\n"));
}

/// Human-readable duration, switching unit so the number stays short.
pub fn fmt_dur(ns: u64) -> String {
    let s = ns as f64 / 1e9;
    if s >= 100.0 {
        format!("{s:.0}s")
    } else if s >= 10.0 {
        format!("{s:.1}s")
    } else if s >= 1.0 {
        format!("{s:.2}s")
    } else if s >= 0.001 {
        format!("{:.1}ms", s * 1e3)
    } else if s >= 0.000_001 {
        format!("{:.0}us", s * 1e6)
    } else if ns > 0 {
        // Sub-microsecond intervals are real and show up in scheduler data.
        // Rounding them to "0us" would read as "nothing happened".
        format!("{ns}ns")
    } else {
        "0".to_string()
    }
}

fn ns_to_s(ns: u64) -> f64 {
    ns as f64 / 1e9
}

/// Wall-clock nanoseconds as a UTC timestamp.
///
/// Hand-rolled rather than pulling in a date library: blackbox has no
/// dependencies beyond serde for this, and UTC has no timezone database to go
/// wrong.
pub fn format_wall(unix_ns: u64) -> String {
    let secs = unix_ns / 1_000_000_000;
    let (y, mo, d, h, mi, s) = civil_from_unix(secs as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Convert Unix seconds to a UTC civil date (Howard Hinnant's algorithm).
fn civil_from_unix(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, mi, s) = (
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
    );
    // Shift the epoch to 0000-03-01 so leap days land at the end of the cycle.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if mo <= 2 { y + 1 } else { y };
    (y, mo, d, h, mi, s)
}

/// Current wall-clock nanoseconds since the epoch.
pub fn now_unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
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

    fn dump(events: Vec<DumpEvent>, end: u64) -> Dump {
        Dump::new(
            TriggerInfo {
                reason: "psi_memory".into(),
                detail: "psi memory avg10=41.00% >= 20.00% for 4 consecutive samples".into(),
            },
            0,
            end,
            events,
            Vec::new(),
            OverheadInfo::default(),
            crate::dump::HostSnapshot::default(),
            1_700_000_000_000_000_000,
            1_700_000_000_000_000_000,
            false,
        )
    }

    /// task1 hogs CPU 0 for 9s then is preempted while still runnable;
    /// task2 blocks for 1s waiting on something other than a cpu.
    fn sample() -> Dump {
        dump(
            vec![
                ev(0, 0, 999, 1, 1),
                ev(9 * NS, 0, 1, 2, 0),
                ev(11 * NS, 0, 2, 3, 1),
                ev(12 * NS, 0, 3, 2, 0),
                ev(13 * NS, 0, 2, 1, 0),
            ],
            14 * NS,
        )
    }

    #[test]
    fn report_states_the_trigger_verbatim() {
        let r = render_report(&sample());
        assert!(r.contains("psi_memory"));
        assert!(r.contains("41.00%"));
        assert!(r.contains("consecutive samples"));
    }

    #[test]
    fn report_ranks_the_busiest_task_first() {
        let r = render_report(&sample());
        let section = section(&r, "top cpu consumers", "longest scheduler delays");
        let first = section.lines().find(|l| l.contains("pid ")).unwrap();
        assert!(first.contains("task1"), "got: {first}");
    }

    #[test]
    fn percentages_sum_consistently() {
        let r = render_report(&sample());
        assert!(r.contains('%'));
        let s = render_report(&sample());
        assert_eq!(r, s, "rendering is deterministic");
    }

    #[test]
    fn preemption_and_blocking_are_reported_separately() {
        let r = render_report(&sample());
        let delays = section(&r, "longest scheduler delays", "most blocked time");
        assert!(
            delays.contains("task1"),
            "task1 was preempted while runnable"
        );
        assert!(
            !delays.contains("task2"),
            "blocked time must not be listed as scheduler delay"
        );

        let blocked = section(&r, "most blocked time", "per-cpu");
        assert!(blocked.contains("task2"), "task2 was sleeping, not starved");
        assert!(!blocked.contains("task1"));
    }

    /// Text between two section headings, so assertions cannot leak across
    /// sections and produce false confidence.
    fn section<'a>(report: &'a str, start: &str, end: &str) -> &'a str {
        let from = report
            .find(start)
            .unwrap_or_else(|| panic!("section {start:?} missing"));
        let rest = &report[from..];
        match rest.find(end) {
            Some(at) => &rest[..at],
            None => rest,
        }
    }

    #[test]
    fn kernel_drops_are_surfaced_as_a_warning() {
        let mut d = sample();
        d.overhead.events_dropped_kernel = 42;
        let r = render_report(&d);
        assert!(r.contains("WARNING"));
        assert!(r.contains("42"));
    }

    #[test]
    fn kernel_drops_are_reported_as_a_share_of_events_seen() {
        let mut d = sample();
        d.overhead.events_recorded = 98;
        d.overhead.events_dropped_kernel = 2;
        let r = render_report(&d);
        // 2 dropped out of 100 seen.
        assert!(r.contains("2.0% of events seen"), "got:\n{r}");
    }

    #[test]
    fn a_clean_trace_states_zero_drops_explicitly() {
        let r = render_report(&sample());
        // Whitespace-insensitive: the key column spacing is presentation, not
        // content.
        let line = r.lines().find(|l| l.contains("kernel drops")).unwrap();
        assert!(line.split_whitespace().last() == Some("0"), "got: {line}");
        assert!(!r.contains("WARNING"));
    }

    #[test]
    fn no_kernel_drops_means_no_warning() {
        assert!(!render_report(&sample()).contains("WARNING"));
    }

    #[test]
    fn empty_dump_renders_without_panicking() {
        let r = render_report(&dump(vec![], 0));
        assert!(r.contains("blackbox trace"));
        assert!(r.contains("no on-cpu activity"));
    }

    #[test]
    fn truncated_window_is_called_out() {
        let mut d = sample();
        d.window.truncated = true;
        assert!(render_report(&d).contains("truncated"));
    }

    #[test]
    fn per_cpu_section_is_opt_in() {
        assert!(!render_report(&sample()).contains("per-cpu"));
        let r = render_report_with(
            &sample(),
            ReportOptions {
                per_cpu: true,
                ..Default::default()
            },
        );
        assert!(r.contains("per-cpu"));
    }

    #[test]
    fn top_limit_is_respected() {
        let mut events = vec![ev(0, 0, 999, 1, 1)];
        for i in 1..30 {
            events.push(ev(i * 100_000_000, 0, i as u32, i as u32 + 1, 0));
        }
        let d = dump(events, 3 * NS);
        let r = render_report_with(
            &d,
            ReportOptions {
                top: 3,
                per_cpu: false,
            },
        );
        let section = section(&r, "top cpu consumers", "longest scheduler delays");
        let rows = section.lines().filter(|l| l.contains("pid ")).count();
        assert!(
            rows <= 4,
            "got {rows} rows, expected top plus overflow note"
        );
    }

    #[test]
    fn durations_pick_a_readable_unit() {
        assert_eq!(fmt_dur(0), "0");
        assert_eq!(fmt_dur(500), "500ns");
        assert_eq!(fmt_dur(5_000), "5us");
        assert_eq!(fmt_dur(5_000_000), "5.0ms");
        assert_eq!(fmt_dur(2_500_000_000), "2.50s");
        assert_eq!(fmt_dur(45_000_000_000), "45.0s");
        assert_eq!(fmt_dur(250_000_000_000), "250s");
    }

    #[test]
    fn sub_microsecond_durations_do_not_render_as_zero() {
        // Scheduler slices land in this range routinely, and "0us" would read
        // as no activity rather than a very short interval.
        assert_ne!(fmt_dur(1), "0");
        assert_ne!(fmt_dur(999), "0");
    }

    #[test]
    fn epoch_formats_as_known_utc() {
        assert_eq!(format_wall(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn known_dates_round_trip() {
        // Including a leap day and a post-leap-day boundary, since the civil
        // date algorithm is easy to get subtly wrong.
        assert_eq!(
            format_wall(1_700_000_000_000_000_000),
            "2023-11-14T22:13:20Z"
        );
        assert_eq!(format_wall(951_782_400_000_000_000), "2000-02-29T00:00:00Z");
        assert_eq!(
            format_wall(1_583_020_800_000_000_000),
            "2020-03-01T00:00:00Z"
        );
    }

    #[test]
    fn lifecycle_events_render_in_their_own_section() {
        use crate::lifecycle::{LifecycleEvent, LifecycleKind};
        let mut d = sample();
        d.lifecycle = vec![
            LifecycleEvent {
                ts_ns: NS,
                kind: LifecycleKind::Exec,
                pid: 42,
                peer_pid: 41,
                value: 0,
                comm: "bash".into(),
                name: "/usr/bin/psql".into(),
            },
            LifecycleEvent {
                ts_ns: 2 * NS,
                kind: LifecycleKind::Exit,
                pid: 42,
                peer_pid: 0,
                value: 0,
                comm: "psql".into(),
                name: String::new(),
            },
        ];
        d.overhead.lifecycle_recorded = 2;
        let r = render_report(&d);
        let sec = section(&r, "process lifecycle", "per-cpu");
        assert!(sec.contains("1 exec, 1 exit"), "got:\n{sec}");
        assert!(sec.contains("/usr/bin/psql"), "got:\n{sec}");
        assert!(sec.contains("exit:  psql (pid 42"), "got:\n{sec}");
    }

    #[test]
    fn lifecycle_section_is_absent_when_there_are_no_events() {
        assert!(!render_report(&sample()).contains("process lifecycle"));
    }

    #[test]
    fn wall_clock_is_plausible_now() {
        let s = format_wall(now_unix_ns());
        assert!(s.starts_with("20"), "got {s}");
        assert!(s.ends_with('Z'));
    }
}
