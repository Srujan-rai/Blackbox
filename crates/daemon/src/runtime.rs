use blackbox_core::history::HistoryRing;
use blackbox_core::psi::{PressureMonitor, PsiSnapshot, TriggerFired};

#[derive(Debug)]
pub struct Runtime {
    history: HistoryRing,
    monitor: PressureMonitor,
}

impl Runtime {
    pub fn new(history: HistoryRing, monitor: PressureMonitor) -> Self {
        Self { history, monitor }
    }

    pub fn observe_psi(&mut self, snapshot: &PsiSnapshot) -> Vec<TriggerFired> {
        self.monitor.observe(snapshot)
    }

    pub fn history_mut(&mut self) -> &mut HistoryRing {
        &mut self.history
    }

    pub fn history(&self) -> &HistoryRing {
        &self.history
    }
}
