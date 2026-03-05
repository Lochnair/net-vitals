use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};

use clap::Parser;
use net_vitals::{FlowEvent, NetVitals, RttSample};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

static RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn handle_sigint(_: libc::c_int) {
    RUNNING.store(false, Ordering::Relaxed);
}

fn main() -> anyhow::Result<()> {
    let Opt { iface } = Opt::parse();

    unsafe {
        libc::signal(
            libc::SIGINT,
            handle_sigint as *const () as libc::sighandler_t,
        )
    };

    let mut nv = NetVitals::load(&iface)?;
    println!("Listening on {iface}... (Ctrl-C to exit)");

    nv.run(
        &RUNNING,
        |event: FlowEvent| {
            let src = Ipv4Addr::from(u32::from_be(event.src_ip));
            let dst = Ipv4Addr::from(u32::from_be(event.dst_ip));
            let sp = u16::from_be(event.src_port);
            let dp = u16::from_be(event.dst_port);
            println!(
                "New flow: {src}:{sp} -> {dst}:{dp} [ECN: {0} CWR: {1}]",
                event.ece, event.cwr
            );
        },
        |sample: RttSample| {
            let src = Ipv4Addr::from(u32::from_be(sample.src_ip));
            let dst = Ipv4Addr::from(u32::from_be(sample.dst_ip));
            let sp = u16::from_be(sample.src_port);
            let dp = u16::from_be(sample.dst_port);
            let rtt_us = sample.rtt_ns / 1_000;
            println!("RTT sample: {src}:{sp} -> {dst}:{dp} rtt={rtt_us}µs");
        },
    );

    println!("Exiting...");
    Ok(())
}
