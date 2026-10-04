use anyhow::{anyhow, Result};
use aya::{maps::RingBuf, programs::TracePoint, util::online_cpus, Ebpf};
use aya_log::EbpfLogger;
use std::path::Path;

pub fn load_and_attach(bpf_obj: &Path) -> Result<(Ebpf, RingBuf<'static>)> {
    let mut ebpf = aya::Ebpf::load_file(bpf_obj)?;
    EbpfLogger::init(&mut ebpf)?;
    let program: &mut TracePoint = ebpf
        .program_mut("sched_switch")
        .ok_or_else(|| anyhow!("program 'sched_switch' not found"))?
        .try_into()?;
    program.load()?;
    for cpu in online_cpus()? {
        program.attach("sched", "sched_switch", cpu)?;
    }
    let ringbuf = ebpf.take_map("EVENTS").ok_or_else(|| anyhow!("map 'EVENTS' not found"))?;
    let ringbuf: RingBuf<'static> = RingBuf::try_from(ringbuf)?;
    Ok((ebpf, ringbuf))
}