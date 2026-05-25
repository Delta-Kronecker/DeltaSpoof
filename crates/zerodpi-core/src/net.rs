//! Network helpers shared by core and platform crates.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

/// Discover the local IPv4 address the kernel would use to reach `target`.
///
/// Mirrors upstream's `get_default_interface_ipv4`: we open an unconnected
/// UDP socket and call `connect()` to a well-known address so the kernel
/// fills in the source address; no packets are actually sent.
pub fn default_interface_ipv4(target: Ipv4Addr) -> anyhow::Result<Ipv4Addr> {
    let sock = UdpSocket::bind(SocketAddr::from(([0u8, 0, 0, 0], 0)))?;
    sock.connect(SocketAddr::from((target, 53)))?;
    match sock.local_addr()?.ip() {
        IpAddr::V4(v4) => Ok(v4),
        IpAddr::V6(_) => anyhow::bail!("unexpected IPv6 local address"),
    }
}
