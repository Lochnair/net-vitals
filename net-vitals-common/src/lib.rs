#![no_std]

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FlowEvent {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub ece: u16,
    pub cwr: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FlowKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FlowState {
    pub timestamp_ns: u64,
    pub tracked_seq: u32,
    pub highest_seq: u32,
    pub ecn_packets: u32,
    pub retransmits: u32,
}

/// Egress-side entry stored in `TS_STORE` when we send a TCP segment with a
/// TCP timestamp option.  Keyed by the egress `FlowKey`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct TsEntry {
    /// Kernel monotonic time when the segment was transmitted (nanoseconds).
    pub ktime_ns: u64,
    /// The TSval value we sent (network byte order; kept as-is for comparison).
    pub tsval: u32,
    pub _pad: u32,
}

/// Emitted to the `RTT_SAMPLES` ring buffer when a complete RTT measurement is
/// available (egress TSval echoed back as TSecr in an ingress TCP reply).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RttSample {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    /// Measured round-trip time in nanoseconds.
    pub rtt_ns: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowState {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TsEntry {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RttSample {}
