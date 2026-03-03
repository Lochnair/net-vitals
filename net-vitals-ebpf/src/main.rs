#![no_std]
#![no_main]

use aya_ebpf::{bindings::TC_ACT_PIPE, macros::classifier, programs::TcContext};
use aya_log_ebpf::info;

#[classifier]
pub fn net_vitals(ctx: TcContext) -> i32 {
    match try_net_vitals(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_net_vitals(ctx: TcContext) -> Result<i32, i32> {
    info!(&ctx, "received a packet");
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
