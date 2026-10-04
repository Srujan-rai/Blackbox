//! The bounded, continuously-drained history window.
//!
//! This lives in userspace, not in BPF, and that is the central design decision
//! of the project. A BPF ring buffer cannot keep history: it overwrites with the
//! newest events and drops the oldest unread ones. So the ring buffer is only
//! ever used as a lock-free transport from the kernel, and the actual "last N
//! seconds" window is this structure, refilled continuously by the daemon.
//!
//! The consequence, documented in the README: history only exists while
//! `blackboxd` is running.

use std::collections::VecDeque;

use crate::event::SchedSwitch;

/// Default window: 30 seconds of history at up to 250k events.
///
/// 250k `sched_switch` events is roughly 8k/s, comfortably above what a busy
/// 64-core box generates, and costs 16 MB.
pub const DEFAULT_MAX_EVENTS: usize = 250_000;
pub const DEFAULT_MAX_SECONDS: u64 = 30;

/// A bounded event window with both a count and a time cap.
#[derive(Debug)]
pub struct HistoryRing {
    events: VecDeque<SchedSwitch>,
    max_events: usize,
    max_duration_ns: u64,
    evicted: u64,
}

impl HistoryRing {
    pub fn new(max_events: usize, max_seconds: u64) -> Self {
        Self {
            events: VecDeque::with_capacity(max_events.min(8192)),
            max_events: max_events.max(1),
            max_duration_ns: max_seconds.saturating_mul(1_000_000_000),
            evicted: 0,
        }
    }

    /// Append an event, then evict from the front until both caps hold.
    pub fn push(&mut self, ev: SchedSwitch) {
        self.events.push_back(ev);
        self.evict_to_count();
        self.evict_to_time();
    }

    fn evict_to_count(&mut self) {
        while self.events.len() > self.max_events {
            self.events.pop_front();
            self.evicted += 1;
        }
    }

    /// Evict until the window is no wider than the cap.
    ///
    /// Keeps at least one event so that a lone event is never evicted by its own
    /// timestamp, and guards on non-monotonic arrival: the ring buffer delivers
    /// events in approximately timestamp order, but across CPUs a later-arriving
    /// record can carry a slightly earlier timestamp.
    fn evict_to_time(&mut self) {
        loop {
            let span = match (self.events.front(), self.events.back()) {
                (Some(first), Some(last)) => last.ts_ns.saturating_sub(first.ts_ns),
                _ => 0,
            };
            if span <= self.max_duration_ns || self.events.len() <= 1 {
                return;
            }
            self.events.pop_front();
            self.evicted += 1;
        }
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Number of events dropped from the front because the window was full.
    ///
    /// This is *our* backpressure, distinct from kernel-side drops.
    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    pub fn max_events(&self) -> usize {
        self.max_events
    }

    pub fn max_duration_ns(&self) -> u64 {
        self.max_duration_ns
    }

    /// Timestamp of the oldest retained event, if any.
    pub fn start_ns(&self) -> Option<u64> {
        self.events.front().map(|e| e.ts_ns)
    }

    /// Timestamp of the newest retained event, if any.
    pub fn end_ns(&self) -> Option<u64> {
        self.events.back().map(|e| e.ts_ns)
    }

    pub fn iter(&self) -> impl Iterator<Item = &SchedSwitch> {
        self.events.iter()
    }

    /// Chronological snapshot, oldest first.
    ///
    /// Sorts because arrival order across CPUs is only approximately
    /// timestamp-ordered. The sort cost is paid once, at dump time.
    pub fn snapshot(&self) -> Vec<SchedSwitch> {
        let mut out: Vec<SchedSwitch> = self.events.iter().copied().collect();
        out.sort_by_key(|e| e.ts_ns);
        out
    }

    /// Drop all events but keep running counters.
    ///
    /// `evicted` is deliberately *not* reset: it is a lifetime measure of how
    /// much history the daemon failed to retain, and cumulative totals are what
    /// you want in a status readout after the fact.
    pub fn clear(&mut self) {
        self.events.clear();
    }
}

impl Default for HistoryRing {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_EVENTS, DEFAULT_MAX_SECONDS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(ts_ns: u64) -> SchedSwitch {
        SchedSwitch::new(ts_ns, 0, 1, 2, 0, b"a", b"b")
    }

    #[test]
    fn evicts_oldest_when_count_cap_is_hit() {
        let mut h = HistoryRing::new(3, 1_000);
        for i in 0..5 {
            h.push(ev(i));
        }
        assert_eq!(h.len(), 3);
        assert_eq!(h.evicted(), 2);
        // Oldest retained is the third event.
        assert_eq!(h.start_ns(), Some(2));
        assert_eq!(h.end_ns(), Some(4));
    }

    #[test]
    fn evicts_oldest_when_time_cap_is_hit() {
        // 1 second cap, 400ms between events.
        let mut h = HistoryRing::new(1000, 1);
        for i in 0..10 {
            h.push(ev(i * 400_000_000));
        }
        // 0, 0.4, 0.8, 1.2 -> span from 0.4 to 1.2 is 0.8s, within cap.
        assert!(h.start_ns().unwrap() >= 400_000_000);
        assert!(h.end_ns().unwrap() - h.start_ns().unwrap() <= 1_000_000_000);
    }

    #[test]
    fn retains_a_single_event_even_if_its_own_span_exceeds_the_cap() {
        let mut h = HistoryRing::new(10, 1);
        h.push(ev(0));
        h.push(ev(5_000_000_000));
        // Would-be eviction must not empty the ring.
        assert_eq!(h.len(), 1);
        assert_eq!(h.start_ns(), Some(5_000_000_000));
    }

    #[test]
    fn zero_max_events_is_clamped_to_one() {
        let mut h = HistoryRing::new(0, 1);
        h.push(ev(1));
        h.push(ev(2));
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn eviction_survives_out_of_order_arrival() {
        // An older event arriving late must not cause underflow or eviction of
        // the whole window.
        let mut h = HistoryRing::new(100, 1);
        for i in 0..5 {
            h.push(ev(i * 100_000_000));
        }
        h.push(ev(0));
        assert!(!h.is_empty());
        assert!(h.end_ns().unwrap() >= h.start_ns().unwrap());
    }

    #[test]
    fn snapshot_is_chronological_even_when_pushed_out_of_order() {
        let mut h = HistoryRing::new(100, 100);
        h.push(ev(30));
        h.push(ev(10));
        h.push(ev(20));
        let snap = h.snapshot();
        assert_eq!(
            snap.iter().map(|e| e.ts_ns).collect::<Vec<_>>(),
            vec![10, 20, 30]
        );
    }

    #[test]
    fn clear_keeps_lifetime_eviction_count() {
        let mut h = HistoryRing::new(2, 100);
        for i in 0..5 {
            h.push(ev(i));
        }
        assert_eq!(h.evicted(), 3);
        h.clear();
        assert!(h.is_empty());
        assert_eq!(h.evicted(), 3);
    }

    #[test]
    fn capacity_does_not_preallocate_the_whole_window() {
        let h = HistoryRing::new(1_000_000, 30);
        assert!(h.events.capacity() <= 8192);
    }
}
