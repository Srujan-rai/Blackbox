use anyhow::{anyhow, Context, Result};
use aya::{
    maps::{Array, MapData, RingBuf},
    programs::TracePoint,
    Ebpf,
};
use aya_log::EbpfLogger;
use blackbox_core::config::MAX_FILTER_PIDS;
use std::path::Path;

/// Load `blackbox-bpf.o`, attach its tracepoints, and hand back both ring
/// buffers.
///
/// `sched_switch` is required: without it there is no trace at all, so a
/// failure there is a load failure. The three lifecycle tracepoints
/// (fork/exec/exit) are best-effort — if a kernel lacks one, the daemon logs
/// it and keeps collecting switches, because a partial trace beats none.
///
/// `filter_pids` populates the kernel-side `FILTER` map: a non-empty list
/// narrows what is emitted to events involving those pids (see
/// `blackbox_core::config::BpfConfig`). Longer lists are truncated at
/// [`MAX_FILTER_PIDS`]; config validation has already rejected them, this is
/// defence in depth.
///
/// The returned `Ebpf` is not just a handle: it owns the programs' links, so
/// dropping it detaches the tracepoints. Callers must keep it alive for as
/// long as they want events (the collector thread holds it for its whole
/// lifetime, which makes shutdown = detach).
pub fn load_and_attach(
    bpf_obj: &Path,
    filter_pids: &[u32],
) -> Result<(Ebpf, RingBuf<MapData>, RingBuf<MapData>)> {
    let mut ebpf =
        aya::Ebpf::load_file(bpf_obj).with_context(|| format!("loading {}", bpf_obj.display()))?;
    // The aya-log reader is optional and must not fail the load. Our BPF
    // program does not use aya-log, so its `AYA_LOGS` map is absent and init
    // returns MapNotFound every time — treating that as an error would make
    // every load fail even though nothing is actually wrong.
    match EbpfLogger::init(&mut ebpf) {
        // A future program that does log gets picked up here (its records go
        // through the `log` crate, which the daemon does not currently route
        // anywhere — fine, because today there are none).
        Ok(_) => {}
        Err(aya_log::Error::MapNotFound) => {}
        Err(e) => eprintln!("blackboxd: aya-log reader failed to start: {e}"),
    }

    // Populate the pid filter BEFORE attaching anything: a tracepoint firing
    // with an empty FILTER map (slot 0 == 0) emits every event. The window
    // between attach and map-write would otherwise let a handful of unfiltered
    // records into the trace.
    configure_filter(&mut ebpf, filter_pids)?;

    attach_required(&mut ebpf, "sched_switch", "sched", "sched_switch")?;
    for event in [
        "sched_process_fork",
        "sched_process_exec",
        "sched_process_exit",
    ] {
        if let Err(err) = attach_required(&mut ebpf, event, "sched", event) {
            eprintln!("blackboxd: lifecycle tracepoint {event} not available: {err:#}");
        }
    }

    let events_map = ebpf
        .take_map("EVENTS")
        .ok_or_else(|| anyhow!("map 'EVENTS' not found"))?;
    let ringbuf = RingBuf::try_from(events_map)?;
    let lifecycle_map = ebpf
        .take_map("LIFECYCLE")
        .ok_or_else(|| anyhow!("map 'LIFECYCLE' not found"))?;
    let lifecycle = RingBuf::try_from(lifecycle_map)?;
    Ok((ebpf, ringbuf, lifecycle))
}

/// Fill the kernel-side `FILTER` array from the config.
///
/// Slot 0 is the count (0 = no filtering); slots 1.. hold pids. The BPF
/// programs read this on every event, so it is written once at startup and
/// never touched again — there is deliberately no live-update path.
///
/// This deliberately uses `map_mut` (a borrow) rather than `take_map`:
/// `take_map` removes the map from the object, so a program that is *loaded
/// afterwards* fails to resolve its reference with "fd is not pointing to
/// valid bpf_map". The map must stay owned by the object until every program
/// is loaded; writing through a borrow keeps that guarantee. When the `Array`
/// handle drops, the kernel map itself survives (owned by the loaded object).
fn configure_filter(ebpf: &mut Ebpf, filter_pids: &[u32]) -> Result<()> {
    let filter_map = ebpf
        .map_mut("FILTER")
        .ok_or_else(|| anyhow!("map 'FILTER' not found"))?;
    let mut filter: Array<&mut MapData, u32> = filter_map.try_into()?;
    let count = filter_pids.len().min(MAX_FILTER_PIDS) as u32;
    filter.set(0, count, 0)?;
    for (i, pid) in filter_pids.iter().take(MAX_FILTER_PIDS).enumerate() {
        filter.set((i + 1) as u32, *pid, 0)?;
    }
    Ok(())
}

/// Look up a tracepoint program, load it and attach it to its event.
fn attach_required(ebpf: &mut Ebpf, program: &str, category: &str, event: &str) -> Result<()> {
    let prog: &mut TracePoint = ebpf
        .program_mut(program)
        .ok_or_else(|| anyhow!("program '{program}' not found"))?
        .try_into()?;
    prog.load()?;
    prog.attach(category, event)?;
    Ok(())
}

/// Turn a load/attach failure into an operator-facing explanation.
///
/// aya's errors are precise but not actionable — "error loading /path:
/// Permission denied" does not tell anyone what to do next, and a daemon that
/// will run degraded owes them that, because the alternative is reading logs
/// to find out why `events_recorded` never climbs.
pub fn describe_failure(err: &anyhow::Error, object: &Path) -> String {
    let mut msg = format!(
        "cannot collect sched_switch events from {}: {err:#}",
        object.display()
    );

    // Walk the chain for the underlying io errors: the causes an operator can
    // actually fix are permissions, a missing file, and a missing tracefs.
    let kinds: Vec<std::io::ErrorKind> = err
        .chain()
        .filter_map(|e| e.downcast_ref::<std::io::Error>())
        .map(|e| e.kind())
        .collect();
    let text = format!("{err:#}").to_lowercase();

    if kinds.contains(&std::io::ErrorKind::PermissionDenied) || text.contains("not permitted") {
        msg.push_str(
            "; loading BPF needs root or CAP_BPF+CAP_PERFMON, \
             and attaching needs read access to tracefs",
        );
    } else if text.contains("tracefs") {
        msg.push_str("; tracefs is not mounted — mount -t tracefs tracefs /sys/kernel/tracing");
    } else if kinds.contains(&std::io::ErrorKind::NotFound) || text.contains("no such file") {
        msg.push_str(
            "; the object (or a kernel interface it needs) is missing — \
             rebuild with ./crates/bpf/build.sh release or point [bpf].object_path at it",
        );
    } else if text.contains("btf")
        || text.contains("reloc")
        || text.contains("verifier")
        || text.contains("parsing")
    {
        msg.push_str(
            "; the object may not match this kernel — rebuild it on this machine, \
             and check that /sys/kernel/btf/vmlinux exists (CONFIG_DEBUG_INFO_BTF)",
        );
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn err_with_io(kind: std::io::ErrorKind) -> anyhow::Error {
        anyhow::Error::from(std::io::Error::from(kind))
    }

    #[test]
    fn permission_errors_get_the_capabilities_hint() {
        let msg = describe_failure(
            &err_with_io(std::io::ErrorKind::PermissionDenied),
            Path::new("./blackbox-bpf.o"),
        );
        assert!(msg.contains("CAP_BPF"), "got: {msg}");
        assert!(
            msg.contains("./blackbox-bpf.o"),
            "must name the object: {msg}"
        );
    }

    #[test]
    fn eperm_from_a_syscall_error_is_recognised_too() {
        // bpf(2) failures surface as raw os errors ("Operation not
        // permitted") rather than a kind we can downcast through every layer.
        let err = anyhow::Error::msg("BPF syscall error: Operation not permitted (os error 1)");
        let msg = describe_failure(&err, Path::new("/x/blackbox-bpf.o"));
        assert!(msg.contains("CAP_BPF"), "got: {msg}");
    }

    #[test]
    fn missing_object_gets_the_rebuild_hint() {
        let msg = describe_failure(
            &err_with_io(std::io::ErrorKind::NotFound),
            &PathBuf::from("/nowhere/blackbox-bpf.o"),
        );
        assert!(msg.contains("build.sh"), "got: {msg}");
    }

    #[test]
    fn missing_tracefs_gets_a_mount_command() {
        let err = anyhow::Error::msg("tracefs not found");
        let msg = describe_failure(&err, Path::new("./blackbox-bpf.o"));
        assert!(msg.contains("mount -t tracefs"), "got: {msg}");
    }

    #[test]
    fn unrecognised_failures_still_report_the_full_chain() {
        let err = anyhow::Error::msg("some novel kernel refusal");
        let msg = describe_failure(&err, Path::new("./blackbox-bpf.o"));
        assert!(msg.contains("some novel kernel refusal"), "got: {msg}");
        // No hint is better than a wrong one.
        assert!(!msg.contains("CAP_BPF"), "got: {msg}");
    }
}
