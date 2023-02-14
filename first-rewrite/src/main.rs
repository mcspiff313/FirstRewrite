use anyhow::Context;
use aya::maps::HashMap;
use aya::programs::CgroupSockAddr;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use first_rewrite_common::*;
use log::{info, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    src: u16,
    #[clap(short, long)]
    dst: u16,
    #[clap(short, long, default_value = "/sys/fs/cgroup/")]
    cgroup_path: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/first-rewrite"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/first-rewrite"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut CgroupSockAddr = bpf.program_mut("first_rewrite").unwrap().try_into()?;
    program.load()?;
    let cgroup = std::fs::File::open(opt.cgroup_path)?;
    program.attach(cgroup)
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
    let mut blocklist: HashMap<_, u8, u16> = HashMap::try_from(bpf.map_mut("PORTS")?)?;
    blocklist.insert(SRC, opt.src, 0)?;
    blocklist.insert(DST, opt.dst, 0)?;
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
