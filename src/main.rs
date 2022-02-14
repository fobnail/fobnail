#![no_std]
#![cfg_attr(target_os = "none", no_main)]
// Used by CoAP client, refer to coap/mod.rs for more information.
#![feature(int_log)]

#[cfg(target_os = "none")]
extern crate pal_nrf as pal;

#[cfg(target_os = "linux")]
extern crate pal_pc as pal;

#[macro_use]
extern crate log;

#[macro_use]
extern crate alloc;

use client::FobnailClient;
use smoltcp::iface::{EthernetInterfaceBuilder, Neighbor, NeighborCache};
use smoltcp::socket::{SocketSet, UdpPacketMetadata, UdpSocket, UdpSocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpCidr, Ipv4Address};

use coap::CoapClient;

mod client;
mod coap;

// TODO: should check how much we actually need here and decrease (or increase)
// these if needed
const UDP_META_DEFAULT_BUF_LEN: usize = 16;
const ECHO_SERVER_BUF_LEN: usize = 512;
// Set at Ethernet MTU
// Actually we can transfer less than that in UDP packet since Ethernet frame +
// IP frame already takes some space. Should compute exatly how much bytes do we
// need.
const COAP_CLIENT_BUF_LEN: usize = 1500;

// FIXME: should not use hardcoded server addresses, instead server should be
// discovered
const SERVER_IP_ADDRESS: IpAddress = IpAddress::Ipv4(Ipv4Address::new(169, 254, 0, 8));

// Client also needs a port to be able to communicate with server. Usually local
// port is dynamically assigned from 49152-65535 pool. Here we statically assign
// the first port from dynamic range.
// See https://en.wikipedia.org/wiki/Ephemeral_port
const COAP_LOCAL_PORT: u16 = 49152;

fn make_udp_socket(max_packet: usize, port: u16) -> UdpSocket<'static> {
    let udp_rx = UdpSocketBuffer::new(
        vec![UdpPacketMetadata::EMPTY; UDP_META_DEFAULT_BUF_LEN],
        vec![0u8; max_packet],
    );
    let udp_tx = UdpSocketBuffer::new(
        vec![UdpPacketMetadata::EMPTY; UDP_META_DEFAULT_BUF_LEN],
        vec![0u8; max_packet],
    );
    let mut socket = UdpSocket::new(udp_rx, udp_tx);
    socket
        .bind((Ipv4Address::UNSPECIFIED, port))
        .expect("UDP bind failed");
    socket
}

#[cfg_attr(target_os = "none", pal::cortex_m_rt::entry)]
fn main() -> ! {
    pal::init();
    let mut trussed_clients = pal::trussed::init(&["fobnail_client"]);
    let trussed_fobnail_client = trussed_clients.pop().unwrap();

    let mut neighbor_cache_storage: [Option<(IpAddress, Neighbor)>; 16] = [None; 16];
    let neighbor_cache = NeighborCache::new(&mut neighbor_cache_storage[..]);

    let mut socket_set = SocketSet::new(vec![]);

    // Set Fobnail's IP address to 169.254.0.1
    let mut ip_addrs = [IpCidr::new(IpAddress::v4(169, 254, 0, 1), 16)];
    let eth_phy = pal::ethernet::create_phy();
    let mut iface = EthernetInterfaceBuilder::new(eth_phy)
        .ethernet_addr(pal::ethernet::get_ethernet_address())
        .neighbor_cache(neighbor_cache)
        .ip_addrs(&mut ip_addrs[..])
        .finalize();

    let socket = make_udp_socket(ECHO_SERVER_BUF_LEN, 9400);
    let mut echo_buf = [0u8; 512];
    debug!("UDP socket initialized");

    let coap_socket = make_udp_socket(COAP_CLIENT_BUF_LEN, COAP_LOCAL_PORT);
    debug!("COAP socket initialized");

    // Add sockets into socket set
    let echo_socket_handle = socket_set.add(socket);
    let coap_socket_handle = socket_set.add(coap_socket);

    let coap_client = CoapClient::new(SERVER_IP_ADDRESS, CoapClient::COAP_DEFAULT_PORT);
    let mut fobnail_client = FobnailClient::new(coap_client, trussed_fobnail_client);

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
        fobnail_client.poll(socket_set.get::<UdpSocket>(coap_socket_handle));

        pal::cpu_relax();
    }
}
