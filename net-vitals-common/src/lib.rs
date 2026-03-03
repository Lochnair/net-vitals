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

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowEvent {}
