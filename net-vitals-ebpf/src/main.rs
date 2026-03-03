#![no_std]
#![no_main]

mod ct;

use aya_ebpf::{
    bindings::{
        TC_ACT_PIPE, bpf_sock_tuple, bpf_sock_tuple__bindgen_ty_1,
        bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1,
    },
    macros::{classifier, map},
    maps::RingBuf,
    programs::TcContext,
};
use net_vitals_common::FlowEvent;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

use ct::{bpf_ct_opts, bpf_ct_release, bpf_skb_ct_lookup};

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
    let src_ip = ipv4hdr.src_addr;
    let dst_ip = ipv4hdr.dst_addr;

    let tcphdr: TcpHdr = ctx
        .load(EthHdr::LEN + Ipv4Hdr::LEN)
        .map_err(|_| TC_ACT_PIPE)?;
    if tcphdr.syn() != 1 {
        return Ok(TC_ACT_PIPE);
    }
    let src_port = tcphdr.source;
    let dst_port = tcphdr.dest;

    if let Some(mut entry) = NEW_FLOWS.reserve::<FlowEvent>(0) {
        entry.write(FlowEvent {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
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
