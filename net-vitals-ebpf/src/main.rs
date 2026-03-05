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

    FLOW_STATE.insert(
        key,
        FlowState {
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            tracked_seq: tcphdr.seq,
            highest_seq: tcphdr.seq,
            ecn_packets: 0,
            retransmits: 0,
        },
        BPF_NOEXIST as u64,
    );

    let state = unsafe { *FLOW_STATE.get_ptr_mut(key).unwrap() };
    state.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    state.tracked_seq = tcphdr.seq;
    state.highest_seq = tcphdr.seq;
    state.ecn_packets = 0;
    state.retransmits = 0;

    if tcphdr.syn() != 1 {
        return Ok(TC_ACT_PIPE);
    }

    if let Some(mut entry) = NEW_FLOWS.reserve::<FlowEvent>(0) {
        entry.write(FlowEvent {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            ece: tcphdr.ece(),
            cwr: tcphdr.cwr(),
        });
        entry.submit(0);
    }

    Ok(TC_ACT_PIPE)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
