#![no_std]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
extern crate pal_nrf as pal;

#[cfg(target_os = "linux")]
extern crate pal_pc as pal;

#[macro_use]
extern crate log;

use smoltcp::iface::{EthernetInterfaceBuilder, Neighbor, NeighborCache};
use smoltcp::socket::{SocketRef, SocketSet, UdpPacketMetadata, UdpSocket, UdpSocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpCidr, Ipv4Address};

use coap_lite::{CoapRequest, RequestType};

struct CoapClient {}
impl CoapClient {
    pub fn poll(&mut self, socket: SocketRef<'_, UdpSocket>) {
        info!("Testing CoAP");

        let mut request: CoapRequest<u32> = CoapRequest::new();
        request.set_path("/Test");
        request.set_method(RequestType::Get);
        let _packet = request.message.to_bytes().unwrap();
    }
}

// TODO: should check how much we actually need here and decrease (or increase)
// these if needed
const UDP_META_DEFAULT_BUF_LEN: usize = 16;
const UDP_DEFAULT_BUF_LEN: usize = 512;

#[cfg_attr(target_os = "none", pal::cortex_m_rt::entry)]
fn main() -> ! {
    pal::init();

    // We are going to use 2 sockets:
    // one for echo service
    // and one for CoAP client
    let mut socket_set_buf = [None, None];
    let mut socket_set = SocketSet::new(&mut socket_set_buf[..]);

    // Initialize network interface
    let mut neighbor_cache_storage: [Option<(IpAddress, Neighbor)>; 16] = [None; 16];
    let neighbor_cache = NeighborCache::new(&mut neighbor_cache_storage[..]);

    let mut ip_addrs = [IpCidr::new(IpAddress::v4(169, 254, 0, 1), 16)];
    let eth_phy = pal::ethernet::create_phy();
    let mut iface = EthernetInterfaceBuilder::new(eth_phy)
        .ethernet_addr(pal::ethernet::get_ethernet_address())
        .neighbor_cache(neighbor_cache)
        .ip_addrs(&mut ip_addrs[..])
        .finalize();

    // Create UDP socket for echo service
    let mut udp_rx_metadata = [UdpPacketMetadata::EMPTY; UDP_META_DEFAULT_BUF_LEN];
    let mut udp_rx_payload = [0u8; UDP_DEFAULT_BUF_LEN];
    let mut udp_tx_metadata = [UdpPacketMetadata::EMPTY; UDP_META_DEFAULT_BUF_LEN];
    let mut udp_tx_payload = [0u8; UDP_DEFAULT_BUF_LEN];

    let udp_rx = UdpSocketBuffer::new(&mut udp_rx_metadata[..], &mut udp_rx_payload[..]);
    let udp_tx = UdpSocketBuffer::new(&mut udp_tx_metadata[..], &mut udp_tx_payload[..]);
    let mut socket = UdpSocket::new(udp_rx, udp_tx);
    socket
        .bind((Ipv4Address::UNSPECIFIED, 9400))
        .expect("UDP bind failed");

    debug!("UDP socket initialized");

    // Create UDP socket for CoAP client
    let mut udp_coap_rx_metadata = [UdpPacketMetadata::EMPTY; UDP_META_DEFAULT_BUF_LEN];
    let mut udp_coap_rx_payload = [0u8; UDP_DEFAULT_BUF_LEN];
    let mut udp_coap_tx_metadata = [UdpPacketMetadata::EMPTY; UDP_META_DEFAULT_BUF_LEN];
    let mut udp_coap_tx_payload = [0u8; UDP_DEFAULT_BUF_LEN];

    let udp_coap_rx =
        UdpSocketBuffer::new(&mut udp_coap_rx_metadata[..], &mut udp_coap_rx_payload[..]);
    let udp_coap_tx =
        UdpSocketBuffer::new(&mut udp_coap_tx_metadata[..], &mut udp_coap_tx_payload[..]);

    let mut coap_socket = UdpSocket::new(udp_coap_rx, udp_coap_tx);
    // TODO: which port should we use for CoAP?
    coap_socket
        .bind((Ipv4Address::UNSPECIFIED, 9944))
        .expect("UDP bind failed (CoAP)");

    debug!("COAP socket initialized");

    // Add sockets into socket set
    let echo_socket_handle = socket_set.add(socket);
    let coap_socket_handle = socket_set.add(coap_socket);

    let mut echo_buf = [0u8; 128];

    let mut coap_client = CoapClient {};

    loop {
        match iface.poll(
            &mut socket_set,
            Instant {
                millis: pal::timer::get_time_ms(),
            },
        ) {
            Ok(true) => {}
            Ok(false) => {}
            Err(_) => {}
        };

        {
            let mut echo_socket = socket_set.get::<UdpSocket>(echo_socket_handle);

            match echo_socket.recv_slice(&mut echo_buf) {
                Ok((n, ep)) => match echo_socket.send_slice(&echo_buf[..n], ep) {
                    Ok(()) => info!("Sent echo back to {}", ep),
                    Err(e) => error!("UDP send error (to {}): {}", ep, e),
                },
                Err(smoltcp::Error::Exhausted) => {
                    // No packets incoming
                }
                Err(e) => error!("UDP recv error: {}", e),
            }
        }

        // CoAP poll
        coap_client.poll(socket_set.get::<UdpSocket>(echo_socket_handle));

        pal::cpu_relax();
    }
}
