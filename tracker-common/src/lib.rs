#![no_std]

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Connection {
    pub source_ip: u32,
    pub dest_ip: u32,
    pub source_port: u16,
    pub dest_port: u16,
}

// have to do packed here, otherwise bpf verifier complains
// about invalid indirect read due to padding
#[derive(Clone, Copy)]
#[repr(packed)]
pub struct ConnectionV6 {
    pub source_ip: u128,
    pub dest_ip: u128,
    pub source_port: u16,
    pub dest_port: u16,
}
