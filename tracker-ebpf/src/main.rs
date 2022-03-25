#![no_std]
#![no_main]

mod bindings;
use aya_bpf::{
    bindings::xdp_action::{self, XDP_PASS},
    macros::{map, xdp},
    maps::{HashMap, PerfEventArray},
    programs::XdpContext,
};

use bindings::{ethhdr, iphdr, ipv6hdr, tcphdr};
use core::mem;
use memoffset::offset_of;
use tracker_common::{Connection, ConnectionV6};

const TCP: u8 = 0x0006;
const PORT: u16 = 0x0050;
const IP4_HDR_LEN: usize = mem::size_of::<iphdr>();
const IP6_HDR_LEN: usize = mem::size_of::<ipv6hdr>();
const ETH_P_IPV4: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const MAX_ENTRIES: u32 = 65536;

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<Connection> =
    PerfEventArray::<Connection>::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "EVENTSV6")]
static mut EVENTSV6: PerfEventArray<ConnectionV6> =
    PerfEventArray::<ConnectionV6>::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "BLOCKLIST")]
static mut BLOCKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "BLOCKLISTV6")]
static mut BLOCKLISTV6: HashMap<u128, u32> = HashMap::<u128, u32>::with_max_entries(MAX_ENTRIES, 0);

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let h_proto = u16::from_be(unsafe { *ptr_at(&ctx, offset_of!(ethhdr, h_proto))? });
    if h_proto != ETH_P_IPV4 && h_proto != ETH_P_IPV6 {
        return Ok(xdp_action::XDP_PASS);
    }

    // now that we know we have IPv4 or IPv6, next thing to check is if we should block
    if block_ip(&ctx, h_proto)? {
        return Ok(xdp_action::XDP_DROP);
    }

    // now get and check if protocol is TCP since blocking decisions are based on syn packets
    // return early if get something that is not TCP
    let ip_proto: u8 = get_ip_proto(&ctx, h_proto)?;
    if ip_proto != TCP {
        return Ok(xdp_action::XDP_PASS);
    }

    let bitfield = get_tcp_bitfield(&ctx, h_proto)?;

    // ignore when ack flag is set and if the syn flag isn't set
    if (bitfield & (1 << 12) != 0) {
        return Ok(xdp_action::XDP_PASS);
    }
    if !(bitfield & (1 << 5) != 0) {
        return Ok(xdp_action::XDP_PASS);
    }

    if h_proto == ETH_P_IPV4 {
        return Ok(try_ipv4(&ctx)?);
    }

    Ok(try_ipv6(&ctx)?)
}

fn get_ip_proto(ctx: &XdpContext, h_proto: u16) -> Result<u8, ()> {
    if h_proto == ETH_P_IPV4 {
        return Ok(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, protocol))? });
    }
    // this is not the best way to do ipv6 since nexthdr could point
    // to extension headers which we would need to iterate over to eventually get tcphdr. 
    // For now we will just assume there aren't any extension headers
    Ok(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(ipv6hdr, nexthdr))? })
}

fn get_tcp_bitfield(ctx: &XdpContext, h_proto: u16) -> Result<u16, ()> {
    if h_proto == ETH_P_IPV4 {
        return Ok(unsafe {
            *ptr_at(
                ctx,
                ETH_HDR_LEN + IP4_HDR_LEN + offset_of!(tcphdr, _bitfield_1),
            )?
        });
    }
    Ok(unsafe {
        *ptr_at(
            ctx,
            ETH_HDR_LEN + IP6_HDR_LEN + offset_of!(tcphdr, _bitfield_1),
        )?
    })
}

fn try_ipv4(ctx: &XdpContext) -> Result<u32, ()> {
    let dest_ip = u32::from_be(unsafe { *ptr_at(ctx, ETH_HDR_LEN + offset_of!(iphdr, daddr))? });
    let source_ip = u32::from_be(unsafe { *ptr_at(ctx, ETH_HDR_LEN + offset_of!(iphdr, saddr))? });
    let dest_port = u16::from_be(unsafe {
        *ptr_at(ctx, ETH_HDR_LEN + IP4_HDR_LEN + offset_of!(tcphdr, dest))?
    });
    let source_port = u16::from_be(unsafe {
        *ptr_at(ctx, ETH_HDR_LEN + IP4_HDR_LEN + offset_of!(tcphdr, source))?
    });

    let log_entry = Connection {
        source_ip,
        dest_ip,
        source_port,
        dest_port,
    };

    unsafe {
        EVENTS.output(ctx, &log_entry, 0);
    }

    Ok(xdp_action::XDP_PASS)
}

fn try_ipv6(ctx: &XdpContext) -> Result<u32, ()> {
    let dest_ip = u128::from_be(unsafe { *ptr_at(ctx, ETH_HDR_LEN + offset_of!(ipv6hdr, daddr))? });
    let source_ip =
        u128::from_be(unsafe { *ptr_at(ctx, ETH_HDR_LEN + offset_of!(ipv6hdr, saddr))? });
    let dest_port = u16::from_be(unsafe {
        *ptr_at(ctx, ETH_HDR_LEN + IP6_HDR_LEN + offset_of!(tcphdr, dest))?
    });
    let source_port = u16::from_be(unsafe {
        *ptr_at(ctx, ETH_HDR_LEN + IP6_HDR_LEN + offset_of!(tcphdr, source))?
    });

    let log_entry = ConnectionV6 {
        source_ip,
        dest_ip,
        source_port,
        dest_port,
    };

    unsafe {
        EVENTSV6.output(ctx, &log_entry, 0);
    }
    Ok(xdp_action::XDP_PASS)
}

fn block_ip(ctx: &XdpContext, h_proto: u16) -> Result<bool, ()> {
    if h_proto == ETH_P_IPV4 {
        let source_ip =
            u32::from_be(unsafe { *ptr_at(ctx, ETH_HDR_LEN + offset_of!(iphdr, saddr))? });
        return Ok(block_ipv4(source_ip));
    }
    let source_ip =
        u128::from_be(unsafe { *ptr_at(ctx, ETH_HDR_LEN + offset_of!(ipv6hdr, saddr))? });
    Ok(block_ipv6(source_ip))
}

fn block_ipv4(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}

fn block_ipv6(address: u128) -> bool {
    unsafe { BLOCKLISTV6.get(&address).is_some() }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unreachable!()
}
