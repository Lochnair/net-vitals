use std::os::fd::AsFd as _;
use std::os::fd::AsRawFd as _;
use std::sync::atomic::{AtomicBool, Ordering};

use aya::maps::{MapData, RingBuf};
use aya::programs::{SchedClassifier, TcAttachType, tc};
pub use net_vitals_common::FlowEvent;

pub struct NetVitals {
    _ebpf: aya::Ebpf, // must outlive ring_buf; dropping unloads the eBPF program
    ring_buf: RingBuf<MapData>,
}

impl NetVitals {
    pub fn load(iface: &str) -> anyhow::Result<Self> {
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };

        let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/net-vitals"
        )))?;

        let _ = tc::qdisc_add_clsact(iface);

        let prog: &mut SchedClassifier = ebpf.program_mut("net_vitals").unwrap().try_into()?;
        prog.load()?;
        prog.attach(iface, TcAttachType::Egress)?;

        let prog: &mut SchedClassifier =
            ebpf.program_mut("net_vitals_ingress").unwrap().try_into()?;
        prog.load()?;
        prog.attach(iface, TcAttachType::Ingress)?;

        let ring_buf = RingBuf::try_from(ebpf.take_map("NEW_FLOWS").unwrap())?;

        Ok(Self {
            _ebpf: ebpf,
            ring_buf,
        })
    }

    /// Block-polls the ring buffer, calling `on_event` for each `FlowEvent`,
    /// until `running` is set to `false` (e.g. from a SIGINT handler).
    pub fn run(&mut self, running: &AtomicBool, mut on_event: impl FnMut(FlowEvent)) {
        let fd = self.ring_buf.as_fd().as_raw_fd();
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };

        while running.load(Ordering::Relaxed) {
            let ret = unsafe { libc::poll(&mut pfd, 1, 100) }; // 100 ms timeout
            if ret > 0 {
                while let Some(item) = self.ring_buf.next() {
                    // SAFETY: eBPF wrote a fully-initialized FlowEvent via
                    // MaybeUninit::write; ring buf guarantees ≥4-byte alignment.
                    let event = unsafe { *(item.as_ptr() as *const FlowEvent) };
                    on_event(event);
                }
            }
        }
    }
}
