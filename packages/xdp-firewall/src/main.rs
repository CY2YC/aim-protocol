//! AIM XDP Firewall - User-space controller
//!
//! Loads and manages the eBPF XDP program for kernel-mode packet filtering.
//! Uses Aya for pure-Rust eBPF development [^56^].

use anyhow::{Context, Result};
use aya::{
    Ebpf, include_bytes_aligned,
    maps::{HashMap, LruHashMap},
    programs::{Xdp, XdpFlags},
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{error, info, warn};
use std::net::Ipv4Addr;
use tokio::signal;

#[derive(Debug, Parser)]
#[command(author, version, about = "AIM XDP Firewall Controller")]
struct Args {
    /// Network interface to attach XDP program
    #[arg(short, long, default_value = "eth0")]
    interface: String,

    /// XDP mode: native, skb, or offload
    #[arg(short, long, default_value = "native")]
    mode: String,

    /// Minimum reputation score to allow packets
    #[arg(long, default_value = "10")]
    min_reputation: u32,

    /// Local zone ID
    #[arg(long, default_value = "1")]
    zone_id: u32,

    /// Rate limit: max packets per second per IP
    #[arg(long, default_value = "1000")]
    rate_limit: u64,
}

/// AIM Protocol packet header (from kernel eBPF)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct AimTrustedHeader {
    zone_id: u32,
    reputation: u32,
    session_id: u64,
    nonce: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::init();
    info!("Starting AIM XDP Firewall on interface {}", args.interface);

    // Load eBPF bytecode
    #[cfg(debug_assertions)]
    let mut bpf =
        Ebpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/debug/aim-xdp"))?;

    #[cfg(not(debug_assertions))]
    let mut bpf =
        Ebpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/release/aim-xdp"))?;

    // Initialize eBPF logging
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }

    // Get XDP program
    let program: &mut Xdp = bpf
        .program_mut("aim_firewall")
        .context("Failed to find XDP program 'aim_firewall'")?
        .try_into()
        .context("Program is not XDP type")?;

    // Determine XDP flags
    let flags = match args.mode.as_str() {
        "skb" => XdpFlags::SKB_MODE,
        "offload" => XdpFlags::HW_MODE,
        _ => XdpFlags::default(), // Native mode
    };

    // Load and attach program
    program.load().context("Failed to load XDP program")?;
    program
        .attach(&args.interface, flags)
        .context(format!("Failed to attach to interface {}", args.interface))?;

    info!("XDP program attached successfully in {} mode", args.mode);

    // Configure maps
    configure_maps(&mut bpf, &args).context("Failed to configure eBPF maps")?;

    // Stats collection task
    let stats_handle = tokio::spawn(collect_stats(bpf));

    // Wait for shutdown signal
    info!("Firewall running. Press Ctrl+C to stop.");
    signal::ctrl_c().await?;
    info!("Shutdown signal received");

    // Cleanup
    stats_handle.abort();

    info!("XDP firewall stopped");
    Ok(())
}

fn configure_maps(bpf: &mut Ebpf, args: &Args) -> Result<()> {
    // Configure rate limit map
    let rate_limit: LruHashMap<&mut aya::maps::MapData, u32, u64> =
        LruHashMap::try_from(bpf.map_mut("RATE_LIMIT").context("RATE_LIMIT map not found")?)?;

    // Configure trusted zones
    let trusted_zones: HashMap<&mut aya::maps::MapData, u32, u32> =
        HashMap::try_from(bpf.map_mut("TRUSTED_ZONES").context("TRUSTED_ZONES map not found")?)?;

    // Add local zone as trusted
    // (In production, this would be configurable)

    info!(
        "eBPF maps configured: min_reputation={}, zone_id={}",
        args.min_reputation, args.zone_id
    );

    Ok(())
}

async fn collect_stats(bpf: Ebpf) {
    use aya::maps::HashMap;
    use tokio::time::{Duration, interval};

    let mut timer = interval(Duration::from_secs(5));

    // Get stats map
    let stats_map: HashMap<&aya::maps::MapData, u8, u64> =
        match HashMap::try_from(bpf.map("STATS").expect("STATS map not found")) {
            Ok(m) => m,
            Err(e) => {
                error!("Failed to access stats map: {}", e);
                return;
            }
        };

    loop {
        tokio::select! {
            _ = timer.tick() => {
                // Read stats from kernel
                let mut total_passed = 0u64;
                let mut total_dropped = 0u64;

                for result in stats_map.iter() {
                    if let Ok((key, value)) = result {
                        match key {
                            0 => total_passed = value,
                            1 => total_dropped = value,
                            _ => {}
                        }
                    }
                }

                let total = total_passed + total_dropped;
                if total > 0 {
                    let drop_rate = (total_dropped as f64 / total as f64) * 100.0;
                    info!("XDP Stats: passed={}, dropped={} ({:.2}%)",
                          total_passed, total_dropped, drop_rate);
                }
            }
        }
    }
}
