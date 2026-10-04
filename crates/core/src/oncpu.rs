//! Turning a stream of switch events back into on-CPU intervals.
//!
//! `sched_switch` tells us who left and who arrived, never how long anybody ran.
//! But the transitions carry enough information to recover durations exactly:
//! on each CPU the events arrive in order, so an interval is bounded by the two
//! switches that surround it.
//!
//! Doing this in userspace rather than keeping per-CPU state in BPF is
//! deliberate. Kernel-side tracking would mean a per-CPU map that must stay
//! coherent with the switch stream under concurrency; reconstructing afterwards
//! is impossible to get wrong and costs nothing on the hot path.
//!
//! The payoff beyond "top CPU consumer" is the `prev_state` carried on each
//! interval, which distinguishes scheduler latency from time genuinely blocked:
//! a task that was still `TASK_RUNNING` when it lost the CPU owed the CPU time
//! it did not get, while a task in an interruptible sleep was waiting on
//! something else.

use std::cmp::Reverse;
use std::collections::HashMap;

use crate::event::{SchedSwitch, TASK_RUNNING};

/// One uninterrupted stretch of wall time a task held a CPU.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnCpuSlice {
    pub pid: u32,
    pub comm: String,
    pub cpu: u32,
    pub start_ns: u64,
    pub end_ns: u64,
    /// `prev_state` observed when this task was switched out, if the slice was
    /// closed by a real switch. `None` for the trailing still-running slice.
    pub end_state: Option<i64>,
}

impl OnCpuSlice {
    pub fn duration_ns(&self) -> u64 {
        self.end_ns.saturating_sub(self.start_ns)
    }

    /// True when the task lost the CPU while still runnable, i.e. it was
    /// preempted rather than blocked.
    pub fn was_preempted(&self) -> bool {
        self.end_state == Some(TASK_RUNNING)
    }
}

/// A period when a task held no CPU, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskGap {
    pub pid: u32,
    pub comm: String,
    pub start_ns: u64,
    pub end_ns: u64,
    /// True when the task was runnable-but-not-running, which is scheduler
    /// latency. False when it was blocked on something.
    pub runnable: bool,
}

impl TaskGap {
    pub fn duration_ns(&self) -> u64 {
        self.end_ns.saturating_sub(self.start_ns)
    }
}

/// Rebuild per-CPU on-CPU intervals from a chronological event stream.
///
/// `events` must be sorted by `ts_ns`; [`crate::history::HistoryRing::snapshot`]
/// guarantees that. `window_end_ns` closes the interval of the task that was
/// still running when observation stopped.
///
/// The task occupying a CPU at the very start of the window is unknowable from
/// switch events alone, so that CPU's first slice begins at the first observed
/// switch. The resulting undercount is bounded by the window, and is reported
/// as such rather than being papered over.
pub fn reconstruct(events: &[SchedSwitch], window_end_ns: u64) -> Vec<OnCpuSlice> {
    let mut by_cpu: HashMap<u32, Vec<&SchedSwitch>> = HashMap::new();
    for ev in events {
        by_cpu.entry(ev.cpu).or_default().push(ev);
    }

    let mut out = Vec::new();
    for (cpu, evs) in by_cpu {
        // The task currently occupying this CPU, and since when.
        let mut current: Option<(u32, String, u64)> = None;
        let mut prev_slice: Option<OnCpuSlice> = None;

        for ev in evs {
            // Close whatever was running on this CPU at the moment of the switch.
            if let Some((pid, comm, start)) = current.take() {
                if start <= ev.ts_ns {
                    push_slice(
                        &mut out,
                        &mut prev_slice,
                        OnCpuSlice {
                            pid,
                            comm,
                            cpu,
                            start_ns: start,
                            end_ns: ev.ts_ns,
                            end_state: Some(ev.prev_state),
                        },
                    );
                }
                // start > ev.ts_ns means out-of-order delivery within a CPU;
                // dropping the interval is better than inventing a negative one.
            }
            current = Some((ev.next_pid, ev.next_comm_str().to_owned(), ev.ts_ns));
        }

        // The trailing task was never switched out: close it at the window edge.
        if let Some((pid, comm, start)) = current {
            let end = window_end_ns.max(start);
            push_slice(
                &mut out,
                &mut prev_slice,
                OnCpuSlice {
                    pid,
                    comm,
                    cpu,
                    start_ns: start,
                    end_ns: end,
                    end_state: None,
                },
            );
        }

        // The pending slice exists only so consecutive fragments of one task
        // can merge; it must be flushed before moving to the next CPU.
        if let Some(last) = prev_slice.take() {
            out.push(last);
        }
    }

    out.sort_by_key(|s| (s.start_ns, s.cpu));
    out
}

/// Append a slice, merging with the previous one when it is the same task on
/// the same CPU over contiguous time.
///
/// Consecutive switches back to a task that never really left would otherwise
/// produce a run of zero-length fragments, which wreck both the Perfetto
/// rendering and the top-consumer ranking.
fn push_slice(out: &mut Vec<OnCpuSlice>, prev: &mut Option<OnCpuSlice>, slice: OnCpuSlice) {
    if slice.duration_ns() == 0 {
        return;
    }
    if let Some(last) = prev.as_ref() {
        if last.pid == slice.pid && last.cpu == slice.cpu && last.end_ns == slice.start_ns {
            let last = prev.as_mut().expect("checked above");
            last.end_ns = slice.end_ns;
            last.end_state = slice.end_state;
            return;
        }
    }
    if let Some(last) = prev.take() {
        out.push(last);
    }
    *prev = Some(slice);
}

/// Derive off-CPU gaps from on-CPU slices.
///
/// A gap is runnable when the task was preempted on the way out, and blocked
/// otherwise. Sorting by start makes each task's intervals a proper sequence, so
/// only genuine gaps are emitted rather than overlaps.
pub fn gaps(slices: &[OnCpuSlice]) -> Vec<TaskGap> {
    let mut per_pid: HashMap<u32, Vec<&OnCpuSlice>> = HashMap::new();
    for s in slices {
        per_pid.entry(s.pid).or_default().push(s);
    }

    let mut out = Vec::new();
    for (pid, mut v) in per_pid {
        v.sort_by_key(|s| s.start_ns);
        let comm = v.first().map(|s| s.comm.clone()).unwrap_or_default();
        for w in v.windows(2) {
            let (a, b) = (w[0], w[1]);
            if b.start_ns <= a.end_ns {
                continue;
            }
            out.push(TaskGap {
                pid,
                comm: comm.clone(),
                start_ns: a.end_ns,
                end_ns: b.start_ns,
                runnable: a.was_preempted(),
            });
        }
    }
    out.sort_by_key(|g| Reverse(g.duration_ns()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS: u64 = 1_000_000_000;

    fn ev(ts: u64, cpu: u32, prev: u32, next: u32, state: i64) -> SchedSwitch {
        SchedSwitch::new(ts, cpu, prev, next, state, b"prev", b"next")
    }

    #[test]
    fn reconstructs_a_single_cpu_timeline() {
        // A runs 0..10, B runs 10..20, A runs 20..25.
        let events = vec![
            ev(0, 0, 999, 1, 1),
            ev(10 * NS, 0, 1, 2, 0),
            ev(20 * NS, 0, 2, 1, 0),
        ];
        let s = reconstruct(&events, 25 * NS);
        assert_eq!(s.len(), 3);
        assert_eq!((s[0].pid, s[0].start_ns, s[0].end_ns), (1, 0, 10 * NS));
        assert_eq!(
            (s[1].pid, s[1].start_ns, s[1].end_ns),
            (2, 10 * NS, 20 * NS)
        );
        assert_eq!(
            (s[2].pid, s[2].start_ns, s[2].end_ns),
            (1, 20 * NS, 25 * NS)
        );
    }

    #[test]
    fn total_on_cpu_time_equals_window_span() {
        // The reconstruction must not lose or invent time.
        let events = vec![
            ev(0, 0, 999, 1, 1),
            ev(10 * NS, 0, 1, 2, 0),
            ev(10 * NS + 500_000_000, 0, 2, 3, 0),
            ev(20 * NS, 0, 3, 1, 0),
        ];
        let s = reconstruct(&events, 20 * NS);
        let total: u64 = s.iter().map(OnCpuSlice::duration_ns).sum();
        assert_eq!(total, 20 * NS);
    }

    #[test]
    fn cpus_are_reconstructed_independently() {
        let events = vec![
            ev(0, 0, 999, 1, 1),
            ev(0, 1, 999, 2, 1),
            ev(5 * NS, 0, 1, 3, 0),
            ev(9 * NS, 1, 2, 4, 0),
        ];
        let s = reconstruct(&events, 10 * NS);
        assert_eq!(s.len(), 4);
        // Global ordering is by start time, so the two cpus interleave.
        let cpus: Vec<u32> = s.iter().map(|x| x.cpu).collect();
        assert_eq!(cpus, vec![0, 1, 0, 1]);
        let on_cpu0: Vec<u32> = s.iter().filter(|x| x.cpu == 0).map(|x| x.pid).collect();
        let on_cpu1: Vec<u32> = s.iter().filter(|x| x.cpu == 1).map(|x| x.pid).collect();
        assert_eq!(on_cpu0, vec![1, 3], "task 1 then task 3");
        assert_eq!(on_cpu1, vec![2, 4], "task 2 then task 4");
    }

    #[test]
    fn trailing_task_is_closed_at_window_end_without_a_state() {
        let events = vec![ev(0, 0, 999, 7, 1)];
        let s = reconstruct(&events, 42 * NS);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].end_ns, 42 * NS);
        assert_eq!(s[0].end_state, None);
        assert!(!s[0].was_preempted());
    }

    #[test]
    fn window_end_before_last_event_does_not_invent_negative_time() {
        let events = vec![ev(10 * NS, 0, 999, 1, 1)];
        let s = reconstruct(&events, 5 * NS);
        // Nothing sensible can be said about a window that ends before the only
        // event in it; what must not happen is a negative or bogus duration.
        assert!(s.iter().all(|x| x.duration_ns() == 0));
        assert!(s.len() <= 1);
    }

    #[test]
    fn zero_length_slices_are_discarded() {
        // Two switches at the identical timestamp cannot produce a real interval.
        let events = vec![ev(5 * NS, 0, 999, 1, 1), ev(5 * NS, 0, 1, 2, 0)];
        let s = reconstruct(&events, 5 * NS);
        assert!(s.iter().all(|x| x.duration_ns() > 0));
    }

    #[test]
    fn identical_adjacent_slices_are_merged() {
        // Task 2 is scheduled for an instant at 10s and displaced immediately.
        // That produces a zero-length fragment, and task 1's own time is
        // contiguous either side of it.
        let events = vec![
            ev(0, 0, 999, 1, 1),
            ev(10 * NS, 0, 1, 2, 0),
            ev(10 * NS, 0, 2, 1, 0),
            ev(20 * NS, 0, 1, 3, 0),
        ];
        let s = reconstruct(&events, 21 * NS);
        assert_eq!(s.len(), 2, "the instant fragment is dropped and 1 merges");
        assert_eq!(s[0].pid, 1);
        assert_eq!(s[0].start_ns, 0);
        assert_eq!(s[0].end_ns, 20 * NS, "task 1's time is contiguous");
        assert_eq!(s[1].pid, 3);
    }

    #[test]
    fn empty_input_yields_no_slices() {
        assert!(reconstruct(&[], 0).is_empty());
    }

    #[test]
    fn slices_are_sorted_globally_by_start_time() {
        let events = vec![
            ev(5 * NS, 1, 999, 2, 1),
            ev(0, 0, 999, 1, 1),
            ev(9 * NS, 0, 1, 3, 0),
        ];
        let s = reconstruct(&events, 10 * NS);
        let starts: Vec<u64> = s.iter().map(|x| x.start_ns).collect();
        let mut sorted = starts.clone();
        sorted.sort_unstable();
        assert_eq!(starts, sorted);
    }

    #[test]
    fn gaps_separate_runnable_latency_from_blocked_time() {
        let events = vec![
            ev(0, 0, 999, 1, 1),
            // Task 1 preempted while still runnable.
            ev(10 * NS, 0, 1, 2, TASK_RUNNING),
            // Task 2 blocks in an interruptible sleep.
            ev(12 * NS, 0, 2, 3, 1),
            ev(13 * NS, 0, 3, 2, 0),
            ev(14 * NS, 0, 2, 1, 0),
        ];
        let slices = reconstruct(&events, 15 * NS);
        let g = gaps(&slices);

        let for_one = g.iter().find(|x| x.pid == 1).expect("gap for task 1");
        assert!(for_one.runnable, "preempted task owes scheduler latency");
        assert_eq!(for_one.duration_ns(), 4 * NS);

        // Task 2 must come back for a gap to exist at all; what matters is that
        // the gap it left is classified as blocked, not as starved.
        let for_two = g.iter().find(|x| x.pid == 2).expect("gap for task 2");
        assert!(!for_two.runnable, "sleeping task is not scheduler latency");
        assert_eq!(for_two.duration_ns(), NS);
    }

    #[test]
    fn gaps_are_sorted_longest_first() {
        let events = vec![
            ev(0, 0, 999, 1, 1),
            ev(NS, 0, 1, 2, 0),
            ev(2 * NS, 0, 2, 1, 0),
            ev(30 * NS, 0, 1, 2, 0),
        ];
        let slices = reconstruct(&events, 31 * NS);
        let g = gaps(&slices);
        assert!(g.len() >= 2);
        assert!(g[0].duration_ns() >= g[1].duration_ns());
    }

    #[test]
    fn overlapping_slices_do_not_produce_negative_gaps() {
        // Out-of-order arrivals can leave intervals that touch or overlap.
        let slices = vec![
            OnCpuSlice {
                pid: 1,
                comm: "a".into(),
                cpu: 0,
                start_ns: 0,
                end_ns: 10,
                end_state: Some(0),
            },
            OnCpuSlice {
                pid: 1,
                comm: "a".into(),
                cpu: 0,
                start_ns: 5,
                end_ns: 20,
                end_state: Some(0),
            },
        ];
        assert!(gaps(&slices).is_empty());
    }
}
