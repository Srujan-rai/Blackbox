use anyhow::{anyhow, Result};
use aya::{maps::RingBuf, programs::TracePoint, Ebpf};
use aya_log::EbpfLogger;
use std::path::Path;

pub fn load_and_attach(
    bpf_obj: &Path,
) -> Result<(Ebpf, RingBuf<blackbox_core::event::SchedSwitch>)> {
    let mut ebpf = aya::Ebpf::load_file(bpf_obj)?;
    EbpfLogger::init(&mut ebpf)?;
    let program: &mut TracePoint = ebpf
        .program_mut("sched_switch")
        .ok_or_else(|| anyhow!("program 'sched_switch' not found"))?
        .try_into()?;
    program.load()?;
    program.attach("sched", "sched_switch")?;
    let events_map = ebpf
        .take_map("EVENTS")
        .ok_or_else(|| anyhow!("map 'EVENTS' not found"))?;
    let ringbuf: RingBuf<blackbox_core::event::SchedSwitch> = RingBuf::try_from(events_map)?;
    Ok((ebpf, ringbuf))
}
