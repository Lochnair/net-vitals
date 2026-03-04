#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{BPF_ANY, BPF_NOEXIST, TC_ACT_PIPE},
    helpers::generated::bpf_ktime_get_ns,
    macros::{classifier, map},
    maps::{LruHashMap, RingBuf},
    programs::TcContext,
};
use net_vitals_common::{FlowEvent, FlowKey, FlowState};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

#[map]
static FLOW_STATE: LruHashMap<FlowKey, FlowState> = LruHashMap::with_max_entries(4096, 0);

#[map]
static NEW_FLOWS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[classifier]
pub fn net_vitals(ctx: TcContext) -> i32 {
    match try_classify(&ctx) {
        Ok(ret) | Err(ret) => ret,
    }
}

#[classifier]
pub fn net_vitals_ingress(ctx: TcContext) -> i32 {
    match try_classify(&ctx) {
        Ok(ret) | Err(ret) => ret,
    }
}

#[inline(always)]
fn try_classify(ctx: &TcContext) -> Result<i32, i32> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| TC_ACT_PIPE)?;
    let ether_type = ethhdr.ether_type;
    if ether_type != EtherType::Ipv4 {
        return Ok(TC_ACT_PIPE);
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| TC_ACT_PIPE)?;
    let proto = ipv4hdr.proto;
    if proto != IpProto::Tcp {
        return Ok(TC_ACT_PIPE);
    }

    let tcphdr: TcpHdr = ctx
        .load(EthHdr::LEN + Ipv4Hdr::LEN)
        .map_err(|_| TC_ACT_PIPE)?;

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
