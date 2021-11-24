#![no_std]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
extern crate pal_nrf as pal;

#[cfg(target_os = "linux")]
extern crate pal_pc as pal;

#[macro_use]
extern crate log;

use smoltcp::iface::{EthernetInterfaceBuilder, Neighbor, NeighborCache};
use smoltcp::socket::{SocketSet, UdpPacketMetadata, UdpSocket, UdpSocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address};

#[cfg_attr(target_os = "none", pal::cortex_m_rt::entry)]
fn main() -> ! {
    pal::init();

    let mut neighbor_cache_storage: [Option<(IpAddress, Neighbor)>; 16] = [None; 16];
    let neighbor_cache = NeighborCache::new(&mut neighbor_cache_storage[..]);

    let mut ip_addrs = [IpCidr::new(IpAddress::v4(169, 254, 0, 1), 16)];
    let eth_phy = pal::ethernet::Phy::new(pal::ethernet::get_backend());
    let mut iface = EthernetInterfaceBuilder::new(eth_phy)
        .ethernet_addr(EthernetAddress([0x10, 0x20, 0x30, 0x40, 0x50, 0x60]))
        .neighbor_cache(neighbor_cache)
        .ip_addrs(&mut ip_addrs[..])
        .finalize();

    let mut udp_rx_metadata = [UdpPacketMetadata::EMPTY; 16];
    let mut udp_rx_payload = [0u8; 512];
    let mut udp_tx_metadata = [UdpPacketMetadata::EMPTY; 16];
    let mut udp_tx_payload = [0u8; 512];

    let udp_rx = UdpSocketBuffer::new(&mut udp_rx_metadata[..], &mut udp_rx_payload[..]);
    let udp_tx = UdpSocketBuffer::new(&mut udp_tx_metadata[..], &mut udp_tx_payload[..]);
    let mut socket = UdpSocket::new(udp_rx, udp_tx);
    socket
        .bind((Ipv4Address::UNSPECIFIED, 9400))
        .expect("UDP bind failed");

    debug!("UDP socket initialized");

    let mut socket_set_buf = [None; 1];
    let mut socket_set = SocketSet::new(&mut socket_set_buf[..]);
    let socket_handle = socket_set.add(socket);

    let mut echo_buf = [0u8; 128];

    loop {
        match iface.poll(&mut socket_set, Instant { millis: 0 }) {
            Ok(true) => {}
            Ok(false) => {}
            Err(e) => {
                error!("smoltcp error: {}", e)
            }
        };

        let mut socket = socket_set.get::<UdpSocket>(socket_handle);

        match socket.recv_slice(&mut echo_buf) {
            Ok((n, ep)) => match socket.send_slice(&echo_buf[..n], ep) {
                Ok(()) => info!("Sent echo back to {}", ep),
                Err(e) => error!("UDP send error (to {}): {}", ep, e),
            },
            Err(smoltcp::Error::Exhausted) => {
                // No packets incoming
            }
            Err(e) => error!("UDP recv error: {}", e),
        }

        //cortex_m::asm::wfi();
    }
}
