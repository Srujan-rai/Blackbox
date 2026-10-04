//! blackboxd: collects sched_switch events via BPF ring buffer, polls PSI for
//! pressure-triggered dumps, and writes self-describing dump files.

fn main() -> anyhow::Result<()> {
    // Empty placeholder for now; the daemon will be fleshed out in the next
    // slice once the IPC/CLI and runtime skeleton are in place.
    Ok(())
}