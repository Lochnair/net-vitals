use std::net::Ipv4Addr;

use aya::maps::RingBuf;
use aya::programs::{SchedClassifier, TcAttachType, tc};
use clap::Parser;
#[rustfmt::skip]
use log::debug;
use net_vitals_common::FlowEvent;
use tokio::io::{Interest, unix::AsyncFd};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/net-vitals"
    )))?;

    let Opt { iface } = opt;
    let _ = tc::qdisc_add_clsact(&iface);

    let program: &mut SchedClassifier = ebpf.program_mut("net_vitals").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, TcAttachType::Egress)?;

    let program: &mut SchedClassifier =
        ebpf.program_mut("net_vitals_ingress").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, TcAttachType::Ingress)?;

    let ring_buf = RingBuf::try_from(ebpf.take_map("NEW_FLOWS").unwrap())?;
    let mut async_fd = AsyncFd::with_interest(ring_buf, Interest::READABLE)?;

    println!("Listening for new TCP connections... (Ctrl-C to exit)");

    let ctrl_c = signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            _ = &mut ctrl_c => {
                println!("Exiting...");
                break;
            }
            guard = async_fd.readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    // SAFETY: eBPF wrote a fully-initialized FlowEvent into this slot
                    // via MaybeUninit::write; ring buffer guarantees 8-byte alignment
                    // which satisfies FlowEvent's alignment of 4.
                    let event = unsafe { &*(item.as_ptr() as *const FlowEvent) };
                    let src = Ipv4Addr::from(u32::from_be(event.src_ip));
                    let dst = Ipv4Addr::from(u32::from_be(event.dst_ip));
                    let sp  = u16::from_be(event.src_port);
                    let dp  = u16::from_be(event.dst_port);
                    println!("New flow detected: {src}:{sp} -> {dst}:{dp}");
                }
                guard.clear_ready();
            }
        }
    }

    Ok(())
}
