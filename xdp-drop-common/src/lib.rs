#![no_std]
#![allow(warnings)]
/// A structure representing a log entry for network packets.
///
/// The `PacketLog` struct is designed to log information about network packets,
/// including the IPv4 address and the action performed on the packet.
///
/// # Fields
/// - `ipv4_address`: A `u32` representing the IPv4 address of the packet.
/// - `action`: A `u32` indicating the action performed on the packet. The meaning of
///   this field depends on the context in which the `PacketLog` is used.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub ipv4_address: u32,
    pub action: u32,
}

#[cfg(feature = "user")]
/// A marker implementation to indicate that the `PacketLog` struct can be safely
/// interpreted as a plain data structure (POD - Plain Old Data).
///
/// This implementation ensures that the `PacketLog` struct is compatible with 
/// environments requiring `no_std` and facilitates its use in memory-mapped
/// contexts or shared memory buffers.
///
/// # Safety
/// This implementation of `aya::Pod` is marked as `unsafe` because it assumes that
/// the `PacketLog` struct has no invalid memory layouts and is compatible with
/// the `Pod` trait requirements.
unsafe impl aya::Pod for PacketLog {}
