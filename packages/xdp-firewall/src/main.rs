//! XDP Firewall Control Plane
//!
//! Userspace controller for eBPF XDP packet filter.

use aya::{include_bytes_aligned, maps::HashMap, Ebpf};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Load eBPF program
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../xdp-firewall-ebpf/target/bpfel-unknown-none/debug/xdp-firewall"
    ))?;

    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../xdp-firewall-ebpf/target/bpfel-unknown-none/release/xdp-firewall"
    ))?;

    // Initialize logger
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }

    // Attach XDP program
    let program: &mut aya::programs::Xdp =
        bpf.program_mut("aim_xdp_filter").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, aya::programs::XdpFlags::default())?;

    info!("XDP firewall attached to {}", opt.iface);
    info!("Waiting for Ctrl-C...");

    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
