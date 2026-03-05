use std::os::fd::AsFd as _;
use std::os::fd::AsRawFd as _;
use std::sync::atomic::{AtomicBool, Ordering};

use aya::maps::{MapData, RingBuf};
use aya::programs::{SchedClassifier, TcAttachType, tc};
pub use net_vitals_common::{FlowEvent, RttSample};

pub struct NetVitals {
    _ebpf: aya::Ebpf, // must outlive ring bufs; dropping unloads the eBPF programs
    flow_buf: RingBuf<MapData>,
    rtt_buf: RingBuf<MapData>,
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

        let flow_buf = RingBuf::try_from(ebpf.take_map("NEW_FLOWS").unwrap())?;
        let rtt_buf = RingBuf::try_from(ebpf.take_map("RTT_SAMPLES").unwrap())?;

        Ok(Self {
            _ebpf: ebpf,
            flow_buf,
            rtt_buf,
        })
    }

    /// Block-polls both ring buffers, dispatching events to the provided
    /// callbacks, until `running` is set to `false`.
    pub fn run(
        &mut self,
        running: &AtomicBool,
        mut on_flow: impl FnMut(FlowEvent),
        mut on_rtt: impl FnMut(RttSample),
    ) {
        let flow_fd = self.flow_buf.as_fd().as_raw_fd();
        let rtt_fd = self.rtt_buf.as_fd().as_raw_fd();

        let mut pfds = [
            libc::pollfd { fd: flow_fd, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: rtt_fd, events: libc::POLLIN, revents: 0 },
        ];

        while running.load(Ordering::Relaxed) {
            let ret = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, 100) };
            if ret > 0 {
                // Drain new-flow events.
                if pfds[0].revents & libc::POLLIN != 0 {
                    while let Some(item) = self.flow_buf.next() {
                        // SAFETY: eBPF wrote a fully-initialised FlowEvent via
                        // MaybeUninit::write; ring buf guarantees ≥4-byte alignment.
                        let event = unsafe { *(item.as_ptr() as *const FlowEvent) };
                        on_flow(event);
                    }
                }
                // Drain RTT samples.
                if pfds[1].revents & libc::POLLIN != 0 {
                    while let Some(item) = self.rtt_buf.next() {
                        let sample = unsafe { *(item.as_ptr() as *const RttSample) };
                        on_rtt(sample);
                    }
                }
            }
        }
    }
}
