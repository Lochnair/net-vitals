#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{BPF_ANY, BPF_NOEXIST, TC_ACT_PIPE},
    helpers::generated::bpf_ktime_get_ns,
    macros::{classifier, map},
    maps::{LruHashMap, RingBuf},
    programs::TcContext,
};
use net_vitals_common::{FlowEvent, FlowKey, FlowState, RttSample, TsEntry};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

// ── Maps ──────────────────────────────────────────────────────────────────────

/// Per-flow state (ECN / retransmit counters, sequence tracking).
#[map]
static FLOW_STATE: LruHashMap<FlowKey, FlowState> = LruHashMap::with_max_entries(4096, 0);

/// Ring buffer for new-flow (SYN) events delivered to userspace.
#[map]
static NEW_FLOWS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Stores the TSval + ktime we sent on egress so the ingress path can compute RTTs.
#[map]
static TS_STORE: LruHashMap<FlowKey, TsEntry> = LruHashMap::with_max_entries(4096, 0);

/// Ring buffer for RTT samples delivered to userspace.
#[map]
static RTT_SAMPLES: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// ── Classifier entry points ───────────────────────────────────────────────────

/// Egress classifier: tracks flows, emits SYN events, stores TSval for RTT.
#[classifier]
pub fn net_vitals(ctx: TcContext) -> i32 {
    match try_classify_egress(&ctx) {
        Ok(ret) | Err(ret) => ret,
    }
}

/// Ingress classifier: computes RTT when TSecr echoes a stored TSval.
#[classifier]
pub fn net_vitals_ingress(ctx: TcContext) -> i32 {
    match try_classify_ingress(&ctx) {
        Ok(ret) | Err(ret) => ret,
    }
}

// ── Packet offsets ────────────────────────────────────────────────────────────

const IP_OFFSET: usize = EthHdr::LEN;
const TCP_OFFSET: usize = EthHdr::LEN + Ipv4Hdr::LEN;
/// Byte offset within the full frame where TCP options start (after the fixed
/// 20-byte TCP header).
const TCP_OPTS_OFFSET: usize = TCP_OFFSET + 20;

// ── TCP option constants ──────────────────────────────────────────────────────

const TCPOPT_EOL: u8 = 0;
const TCPOPT_NOP: u8 = 1;
const TCPOPT_TIMESTAMP: u8 = 8;

// ── TCP option parser ─────────────────────────────────────────────────────────

/// Scans TCP options (up to `opts_len` bytes starting at `TCP_OPTS_OFFSET`)
/// looking for the RFC 1323 timestamp option (kind=8, length=10).
///
/// Returns `(tsval, tsecr)` in network byte order if found, `None` otherwise.
///
/// The outer loop is bounded at 40 (maximum TCP options length in bytes), which
/// satisfies the eBPF verifier's requirement for bounded loops.
#[inline(always)]
fn find_tcp_timestamp(ctx: &TcContext, opts_len: usize) -> Option<(u32, u32)> {
    // Clamp to the RFC-maximum of 40 bytes of options.
    let max = if opts_len > 40 { 40 } else { opts_len };

    let mut i = 0usize;
    // Fixed upper bound keeps the eBPF verifier happy.
    for _ in 0..40 {
        if i >= max {
            return None;
        }

        let kind: u8 = ctx.load(TCP_OPTS_OFFSET + i).ok()?;

        match kind {
            TCPOPT_EOL => return None,
            TCPOPT_NOP => {
                i += 1;
            }
            TCPOPT_TIMESTAMP => {
                // kind(1) + len(1) + tsval(4) + tsecr(4) = 10 bytes total.
                if i + 9 >= max {
                    return None;
                }
                let tsval: u32 = ctx.load(TCP_OPTS_OFFSET + i + 2).ok()?;
                let tsecr: u32 = ctx.load(TCP_OPTS_OFFSET + i + 6).ok()?;
                return Some((tsval, tsecr));
            }
            _ => {
                // Variable-length option: read the length byte.
                if i + 1 >= max {
                    return None;
                }
                let len: u8 = ctx.load(TCP_OPTS_OFFSET + i + 1).ok()?;
                if len < 2 {
                    return None; // Malformed option — abort parsing.
                }
                i += len as usize;
            }
        }
    }

    None
}

// ── Egress path ───────────────────────────────────────────────────────────────

#[inline(always)]
fn try_classify_egress(ctx: &TcContext) -> Result<i32, i32> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| TC_ACT_PIPE)?;
    if ethhdr.ether_type != EtherType::Ipv4 {
        return Ok(TC_ACT_PIPE);
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(IP_OFFSET).map_err(|_| TC_ACT_PIPE)?;
    if ipv4hdr.proto != IpProto::Tcp {
        return Ok(TC_ACT_PIPE);
    }

    let tcphdr: TcpHdr = ctx.load(TCP_OFFSET).map_err(|_| TC_ACT_PIPE)?;

    let key = FlowKey {
        src_ip: ipv4hdr.src_addr,
        dst_ip: ipv4hdr.dst_addr,
        src_port: tcphdr.source,
        dst_port: tcphdr.dest,
    };

    // ── Flow state tracking ──

    // Insert initial state only for new flows; no-op if the entry already exists.
    let _ = FLOW_STATE.insert(
        &key,
        &FlowState {
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            tracked_seq: tcphdr.seq,
            highest_seq: tcphdr.seq,
            ecn_packets: 0,
            retransmits: 0,
        },
        BPF_NOEXIST as u64,
    );

    // Operate through the raw pointer to update the map entry in-place.
    if let Some(state) = FLOW_STATE.get_ptr_mut(&key) {
        unsafe {
            (*state).timestamp_ns = bpf_ktime_get_ns();
            (*state).tracked_seq = tcphdr.seq;
            if tcphdr.seq > (*state).highest_seq {
                (*state).highest_seq = tcphdr.seq;
            } else {
                (*state).retransmits = (*state).retransmits.saturating_add(1);
            }
            if tcphdr.ece() != 0 {
                (*state).ecn_packets = (*state).ecn_packets.saturating_add(1);
            }
        }
    }

    // ── SYN event emission ──

    if tcphdr.syn() == 1 {
        if let Some(mut entry) = NEW_FLOWS.reserve::<FlowEvent>(0) {
            entry.write(FlowEvent {
                src_ip: key.src_ip,
                dst_ip: key.dst_ip,
                src_port: key.src_port,
                dst_port: key.dst_port,
                ece: tcphdr.ece(),
                cwr: tcphdr.cwr(),
            });
            entry.submit(0);
        }
    }

    // ── TCP timestamp storage for RTT measurement ──

    let opts_len = (tcphdr.doff() as usize) * 4;
    if opts_len > 20 {
        if let Some((tsval, _tsecr)) = find_tcp_timestamp(ctx, opts_len - 20) {
            let _ = TS_STORE.insert(
                &key,
                &TsEntry {
                    ktime_ns: unsafe { bpf_ktime_get_ns() },
                    tsval,
                    _pad: 0,
                },
                BPF_ANY as u64, // overwrite so we always have the latest TSval
            );
        }
    }

    Ok(TC_ACT_PIPE)
}

// ── Ingress path ──────────────────────────────────────────────────────────────

#[inline(always)]
fn try_classify_ingress(ctx: &TcContext) -> Result<i32, i32> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| TC_ACT_PIPE)?;
    if ethhdr.ether_type != EtherType::Ipv4 {
        return Ok(TC_ACT_PIPE);
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(IP_OFFSET).map_err(|_| TC_ACT_PIPE)?;
    if ipv4hdr.proto != IpProto::Tcp {
        return Ok(TC_ACT_PIPE);
    }

    let tcphdr: TcpHdr = ctx.load(TCP_OFFSET).map_err(|_| TC_ACT_PIPE)?;

    let opts_len = (tcphdr.doff() as usize) * 4;
    if opts_len <= 20 {
        return Ok(TC_ACT_PIPE); // No TCP options — nothing to do.
    }

    let (_tsval, tsecr) = match find_tcp_timestamp(ctx, opts_len - 20) {
        Some(ts) => ts,
        None => return Ok(TC_ACT_PIPE),
    };

    // The egress entry was stored with src=local, dst=remote.
    // The incoming reply has src=remote, dst=local, so we reverse the key.
    let egress_key = FlowKey {
        src_ip: ipv4hdr.dst_addr,
        dst_ip: ipv4hdr.src_addr,
        src_port: tcphdr.dest,
        dst_port: tcphdr.source,
    };

    if let Some(stored) = TS_STORE.get_ptr(&egress_key) {
        let ts = unsafe { &*stored };
        // TSecr in the reply must match the TSval we stored.
        if ts.tsval == tsecr {
            let now = unsafe { bpf_ktime_get_ns() };
            if now >= ts.ktime_ns {
                let rtt_ns = now - ts.ktime_ns;
                if let Some(mut entry) = RTT_SAMPLES.reserve::<RttSample>(0) {
                    entry.write(RttSample {
                        src_ip: egress_key.src_ip,
                        dst_ip: egress_key.dst_ip,
                        src_port: egress_key.src_port,
                        dst_port: egress_key.dst_port,
                        rtt_ns,
                    });
                    entry.submit(0);
                }
            }
        }
    }

    Ok(TC_ACT_PIPE)
}

// ── Panic / license ───────────────────────────────────────────────────────────

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
