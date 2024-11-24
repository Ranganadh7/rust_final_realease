

#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
    tcp::TcpHdr,
    udp::UdpHdr,
};
/// Panic handler to ensure the program does not crash unexpectedly.
/// This function will be invoked when a panic occurs, but in this case,
/// it will simply halt the program execution.

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}


/// IP blocklist map.
///
/// This map is used to store the blocked IP addresses. The key is the IP address (in `u32` format),
/// and the value is a placeholder (`u32`) to enable key-value pairs for easier map handling. 
/// It can hold up to 1024 entries.

#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

// Port blocklist map
/// Port blocklist map.
///
/// This map is used to store the blocked port numbers. The key is the port number (in `u16` format),
/// and the value is a placeholder (`u16`) to enable key-value pairs for easier map handling. 
/// It can hold up to 1024 entries.
#[map]
static PORT_BLOCKLIST: HashMap<u16, u16> = HashMap::<u16, u16>::with_max_entries(1024, 0);

/// XDP firewall program entry point.
///
/// This is the main eBPF program function that is executed when a packet is processed. 
/// It attempts to block the packet based on the source IP and destination port 
/// and returns the corresponding action (DROP or PASS).
#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}
/// Helper function to safely read a pointer at a specific offset within the packet data.
///
/// This function attempts to retrieve a pointer to a specific data structure (e.g., TCP, UDP header)
/// from the packet, ensuring that the pointer is within bounds.
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    // Ensure the access is within bounds
    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(ptr)
}

/// Block an IP address if it is in the blocklist.
///
/// This function checks if the given IP address is in the `BLOCKLIST`. If the IP is found, the packet 
/// is dropped by returning `XDP_DROP`; otherwise, the packet is passed.
// IP blocking function
fn block_ip_fn(ctx: &XdpContext, source: u32) -> u32 {
    if block_ip(source) {
        info!(ctx, "Blocking IP: {:i}", source);
        return xdp_action::XDP_DROP;
    }
    xdp_action::XDP_PASS
}

/// Block a port if it is in the blocklist.
///
/// This function checks if the destination port of the packet is in the `PORT_BLOCKLIST`. It first 
/// inspects the protocol type (TCP or UDP) and then checks if the port is blocked. If the port is 
/// blocked, the packet is dropped by returning `XDP_DROP`.
// Port blocking function
fn block_port_fn(ctx: &XdpContext, protocol: u8, ctx_offset: usize) -> u32 {
    match protocol {
        6 => {  // TCP protocol number
            if let Ok(tcphdr) = unsafe { ptr_at::<TcpHdr>(ctx, ctx_offset) } {
                let dest_port = u16::from_be(unsafe { (*tcphdr).dest });
                if block_port(dest_port) {
                    info!(ctx, "Blocking TCP port: {}", dest_port);
                    return xdp_action::XDP_DROP;
                }
            } else {
                return xdp_action::XDP_PASS; // Invalid access, pass the packet
            }
        },
        17 => { // UDP protocol number
            if let Ok(udphdr) = unsafe { ptr_at::<UdpHdr>(ctx, ctx_offset) } {
                let dest_port = u16::from_be(unsafe { (*udphdr).dest });
                if block_port(dest_port) {
                    info!(ctx, "Blocking UDP port: {}", dest_port);
                    return xdp_action::XDP_DROP;
                }
            } else {
                return xdp_action::XDP_PASS; // Invalid access, pass the packet
            }
        },
        _ => return xdp_action::XDP_PASS, // Allow other protocols
    }
    xdp_action::XDP_PASS
}
/// Check if an IP address is in the blocklist.
///
/// This function checks if the given IP address is present in the `BLOCKLIST` map. It returns `true`
/// if the IP is blocked, and `false` otherwise.
// Check if an IP is in the blocklist
fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}
/// Check if a port is in the blocklist.
///
/// This function checks if the given port is present in the `PORT_BLOCKLIST` map. It returns `true`
/// if the port is blocked, and `false` otherwise.
// Check if a port is in the blocklist
fn block_port(port: u16) -> bool {
    unsafe { PORT_BLOCKLIST.get(&port).is_some() }
}
/// Main eBPF firewall logic.
///
/// This function processes each incoming packet by first parsing the Ethernet header and checking
/// if it is an IPv4 packet. It then parses the IPv4 header, extracts the source IP address, and 
/// checks if the IP address is blocked. If the IP address is not blocked, it checks the destination 
/// port to see if it is blocked. It returns the appropriate action: `XDP_DROP` to block, or 
/// `XDP_PASS` to allow the packet.
// ebpf port and ipblock logic
fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    // Parse the Ethernet header
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}, // Continue processing if IPv4
        _ => return Ok(xdp_action::XDP_PASS), // Pass non-IPv4 packets
    }

    // Parse the IPv4 header
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let source = u32::from_be(unsafe { (*ipv4hdr).src_addr });

    // Ensure packet contains the protocol information
    let protocol: u8 = unsafe { *((ipv4hdr as *const u8).add(9)) };

    // Check if IP should be blocked
    let action = block_ip_fn(&ctx, source);
    if action == xdp_action::XDP_DROP {
        return Ok(action);
    }

    // If IP is not blocked, check port blocking logic
    let action = block_port_fn(&ctx, protocol, EthHdr::LEN + Ipv4Hdr::LEN);
    Ok(action)
}


