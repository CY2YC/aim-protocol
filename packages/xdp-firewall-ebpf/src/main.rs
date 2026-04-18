#![no_std]
#![no_main]

//! AIM Protocol XDP Firewall - Kernel-space eBPF Program
//! 
//! Performs high-performance packet filtering at the kernel level.
//! Uses Aya framework for pure-Rust eBPF development [^56^].

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_ktime_get_ns, bpf_get_smp_processor_id},
    macros::{map, xdp},
    maps::{HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::XdpContext,
};
use aya_log_ebpf::{debug, info, warn};
use core::mem;

// AIM Protocol packet header format
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AimTrustedHeader {
    /// Zone ID for multi-zone deployments
    pub zone_id: u32,
    /// Reputation score (0-10000)
    pub reputation: u32,
    /// Session identifier
    pub session_id: u64,
    /// Anti-replay nonce
    pub nonce: u64,
}

// Ethernet header constants
const ETH_HDR_LEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;

// IPv4 header constants
const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;
const IP_HDR_MIN_LEN: usize = 20;

// AIM Protocol constants
const MIN_REPUTATION: u32 = 10;
const RATE_LIMIT_NS: u64 = 1_000_000_000; // 1 second in nanoseconds

/// Rate limiting map: IP -> last packet timestamp
/// Uses LRU to prevent unbounded growth
#[map]
static RATE_LIMIT: LruHashMap<u32, u64> = LruHashMap::with_max_entries(16384, 0);

/// Trusted zone whitelist
#[map]
static TRUSTED_ZONES: HashMap<u32, u32> = HashMap::with_max_entries(256, 0);

/// Per-CPU packet statistics
#[map]
static CPU_STATS: PerCpuArray<PacketStats> = PerCpuArray::with_max_entries(1, 0);

/// Ring buffer for event logging
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Packet statistics structure
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PacketStats {
    pub passed: u64,
    pub dropped: u64,
    pub rate_limited: u64,
    pub invalid_header: u64,
}

/// Event types for ring buffer
#[repr(u8)]
#[derive(Clone, Copy)]
enum EventType {
    Pass = 0,
    Drop = 1,
    RateLimit = 2,
    InvalidHeader = 3,
}

/// Event structure for ring buffer
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FirewallEvent {
    pub event_type: u8,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub zone_id: u32,
    pub reputation: u32,
    pub timestamp_ns: u64,
}

/// Main XDP entry point
#[xdp]
pub fn aim_firewall(ctx: XdpContext) -> u32 {
    match try_aim_firewall(&ctx) {
        Ok(action) => action,
        Err(_) => {
            // Log error and drop on failure
            log_event(&ctx, EventType::InvalidHeader, 0, 0, 0, 0);
            increment_stat(|s| s.invalid_header += 1);
            xdp_action::XDP_DROP
        }
    }
}

/// Core firewall logic
fn try_aim_firewall(ctx: &XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // Parse Ethernet header
    if data + ETH_HDR_LEN > data_end {
        return Err(());
    }

    // Check EtherType (IPv4 only for now)
    let ethertype = unsafe { *((data + 12) as *const u16) };
    if ethertype != ETH_P_IP.to_be() {
        // Non-IPv4: pass through (not our concern)
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse IPv4 header
    let ip_start = data + ETH_HDR_LEN;
    if ip_start + IP_HDR_MIN_LEN > data_end {
        return Err(());
    }

    // Extract IP addresses and protocol
    let src_ip = unsafe { *((ip_start + 12) as *const u32) };
    let dst_ip = unsafe { *((ip_start + 16) as *const u32) };
    let protocol = unsafe { *((ip_start + 9) as *const u8) };
    let ip_header_len = (unsafe { *(ip_start as *const u8) } & 0x0F) as usize * 4;

    // Only process TCP/UDP for AIM protocol
    if protocol != IP_PROTO_TCP && protocol != IP_PROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }

    // Check rate limiting
    let now = unsafe { bpf_ktime_get_ns() };
    if let Some(last_ts) = unsafe { RATE_LIMIT.get(&src_ip) } {
        if now - *last_ts < RATE_LIMIT_NS {
            // Rate limited
            log_event(ctx, EventType::RateLimit, src_ip, dst_ip, 0, 0);
            increment_stat(|s| s.rate_limited += 1);
            return Ok(xdp_action::XDP_DROP);
        }
    }

    // Update rate limit timestamp
    let _ = RATE_LIMIT.insert(&src_ip, &now, 0);

    // Calculate transport header offset
    let transport_start = ip_start + ip_header_len;
    
    // For TCP: header is variable length, minimum 20 bytes
    // For UDP: header is fixed 8 bytes
    let aim_header_offset = if protocol == IP_PROTO_TCP {
        let tcp_header_len = (unsafe { *((transport_start + 12) as *const u8) } >> 4) as usize * 4;
        transport_start + tcp_header_len
    } else {
        transport_start + 8 // UDP header
    };

    // Check if AIM header fits
    if aim_header_offset + mem::size_of::<AimTrustedHeader>() > data_end {
        // No AIM header present - treat as untrusted
        log_event(ctx, EventType::Drop, src_ip, dst_ip, 0, 0);
        increment_stat(|s| s.dropped += 1);
        return Ok(xdp_action::XDP_DROP);
    }

    // Parse AIM trusted header
    let aim_hdr = unsafe { &*(aim_header_offset as *const AimTrustedHeader) };
    
    // Byte-swap from network order
    let zone_id = u32::from_be(aim_hdr.zone_id);
    let reputation = u32::from_be(aim_hdr.reputation);

    // Validate zone
    if let Some(trusted) = unsafe { TRUSTED_ZONES.get(&zone_id) } {
        if *trusted == 0 {
            // Zone explicitly blacklisted
            log_event(ctx, EventType::Drop, src_ip, dst_ip, zone_id, reputation);
            increment_stat(|s| s.dropped += 1);
            return Ok(xdp_action::XDP_DROP);
        }
    } else {
        // Unknown zone - check if we allow unknown zones (default: no)
        // For now, require explicit zone trust
        log_event(ctx, EventType::Drop, src_ip, dst_ip, zone_id, reputation);
        increment_stat(|s| s.dropped += 1);
        return Ok(xdp_action::XDP_DROP);
    }

    // Check reputation threshold
    if reputation < MIN_REPUTATION {
        log_event(ctx, EventType::Drop, src_ip, dst_ip, zone_id, reputation);
        increment_stat(|s| s.dropped += 1);
        return Ok(xdp_action::XDP_DROP);
    }

    // Packet passed all checks
    log_event(ctx, EventType::Pass, src_ip, dst_ip, zone_id, reputation);
    increment_stat(|s| s.passed += 1);
    
    // Log high-reputation traffic for monitoring
    if reputation > 9000 {
        info!(ctx, "High reputation packet from zone {} (rep={})", zone_id, reputation);
    }

    Ok(xdp_action::XDP_PASS)
}

/// Log event to ring buffer
fn log_event(
    ctx: &XdpContext,
    event_type: EventType,
    src_ip: u32,
    dst_ip: u32,
    zone_id: u32,
    reputation: u32,
) {
    if let Some(mut entry) = EVENTS.reserve::<FirewallEvent>(0) {
        let timestamp_ns = unsafe { bpf_ktime_get_ns() };
        
        entry.write(FirewallEvent {
            event_type: event_type as u8,
            src_ip,
            dst_ip,
            zone_id,
            reputation,
            timestamp_ns,
        });
        
        entry.submit(0);
    }
}

/// Increment per-CPU statistics
fn increment_stat<F>(f: F)
where
    F: FnOnce(&mut PacketStats),
{
    let cpu_id = unsafe { bpf_get_smp_processor_id() };
    if let Some(stats) = unsafe { CPU_STATS.get_ptr_mut(0) } {
        unsafe {
            f(&mut *stats);
        }
    }
}

/// Panic handler for no_std environment
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // In eBPF, we cannot unwind - loop forever
    // The verifier should prevent this from being reached
    unsafe {
        core::arch::asm!("unreachable", options(noreturn));
    }
}
