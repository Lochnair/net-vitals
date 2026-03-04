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

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowEvent {}
