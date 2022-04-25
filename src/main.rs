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

use client::{attestation, provisioning, token_provisioning};
use pal::led::{self, Led};
use smoltcp::iface::{EthernetInterfaceBuilder, Neighbor, NeighborCache};
use smoltcp::socket::{SocketSet, UdpPacketMetadata, UdpSocket, UdpSocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpCidr, Ipv4Address};

use coap::CoapClient;
use trussed::types::{Location, PathBuf};
use trussed::ClientImplementation;

mod certmgr;
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

// FIXME: server should have IP address assigned by using DHCP server located in
// Fobnail token
const SERVER_IP_ADDRESS: IpAddress = IpAddress::Ipv4(Ipv4Address::new(169, 254, 0, 8));

// Client also needs a port to be able to communicate with server. Usually local
// port is dynamically assigned from 49152-65535 pool. Here we statically assign
// the first port from dynamic range.
// See https://en.wikipedia.org/wiki/Ephemeral_port
const COAP_LOCAL_PORT: u16 = 49152;

/// Checks whether we have some RIMs saved in persistent memory. Used to detect
/// whether we have already provisioned some platform (attester) and select
/// default operation mode - if no platform is provisioned enter provisioning
/// mode, otherwise enter attestation mode.
fn have_rims<T>(trussed: &mut T) -> bool
where
    T: trussed::client::FilesystemClient,
{
    let meta_dir = PathBuf::from(b"/meta/");
    let result = trussed::syscall!(trussed.read_dir_first(Location::Internal, meta_dir, None));
    result.entry.is_some()
}

/// Checks whether we have any certificates installed in certstore. This is used
/// to detect whether Fobnail has been provisioned.
fn have_certchain<T>(trussed: &mut T) -> bool
where
    T: trussed::client::FilesystemClient,
{
    let cert_dir = PathBuf::from(b"/cert/");
    let result = trussed::syscall!(trussed.read_dir_first(Location::Internal, cert_dir, None));
    result.entry.is_some()
}

enum OperationMode<'a> {
    Idle {
        trussed: &'a mut ClientImplementation<pal::trussed::Syscall>,
    },
    TokenProvisioning(token_provisioning::FobnailClient<'a>),
    Provisioning(provisioning::FobnailClient<'a>),
    Attestation(attestation::FobnailClient<'a>),
}

impl<'a> OperationMode<'a> {
    pub fn new(trussed: &'a mut ClientImplementation<pal::trussed::Syscall>) -> Self {
        Self::Idle { trussed }
    }

    fn reclaim_trussed(
        self,
    ) -> &'a mut trussed::client::ClientImplementation<pal::trussed::Syscall> {
        match self {
            Self::Idle { trussed } => trussed,
            Self::TokenProvisioning(c) => c.into_trussed(),
            Self::Provisioning(c) => c.into_trussed(),
            Self::Attestation(c) => c.into_trussed(),
        }
    }

    /// Enter Fobnail token provisioning mode.
    pub fn token_provisioning(self) -> Self {
        // FIXME: reinitializing CoapClient resets its message ID which is used
        // for deduplication
        Self::TokenProvisioning(token_provisioning::FobnailClient::new(
            CoapClient::new(SERVER_IP_ADDRESS, CoapClient::COAP_DEFAULT_PORT),
            self.reclaim_trussed(),
        ))
    }

    /// Enter platform provisioning mode.
    pub fn provisioning(self) -> Self {
        // FIXME: reinitializing CoapClient resets its message ID which is used
        // for deduplication
        Self::Provisioning(provisioning::FobnailClient::new(
            CoapClient::new(SERVER_IP_ADDRESS, CoapClient::COAP_DEFAULT_PORT),
            self.reclaim_trussed(),
        ))
    }

    /// Enter attestation mode.
    pub fn attestation(self) -> Self {
        // FIXME: reinitializing CoapClient resets its message ID which is used
        // for deduplication
        Self::Attestation(attestation::FobnailClient::new(
            CoapClient::new(SERVER_IP_ADDRESS, CoapClient::COAP_DEFAULT_PORT),
            self.reclaim_trussed(),
        ))
    }
}

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
    let mut trussed_fobnail_client = trussed_clients.pop().unwrap();

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

    let have_certchain = have_certchain(&mut trussed_fobnail_client);
    let have_rims = have_rims(&mut trussed_fobnail_client);
    let mut operation_mode = OperationMode::new(&mut trussed_fobnail_client);

    operation_mode = if !have_certchain {
        operation_mode.token_provisioning()
    } else if !have_rims {
        operation_mode.provisioning()
    } else {
        operation_mode.attestation()
    };

    let mut last_button_state = false;
    let mut button_press_time = 0;
    loop {
        let now = pal::timer::get_time_ms() as u64;
        // Pressing button for 10 s triggers Fobnail Token provisioning.
        if now - button_press_time > 10000
            && !matches!(operation_mode, OperationMode::TokenProvisioning(_))
        {
            for _ in 0..3 {
                let t = pal::timer::get_time_ms() as u64;
                led::control(Led::Green, true);
                while pal::timer::get_time_ms() as u64 - t < 100 {}
                let t = pal::timer::get_time_ms() as u64;
                led::control(Led::Green, false);
                while pal::timer::get_time_ms() as u64 - t < 100 {}
            }

            // Clear persistent storage and reboot. After reboot Fobnail
            // enters provisioning mode.
            pal::trussed::reset_device(operation_mode.reclaim_trussed());
        }

        let button_pressed = pal::button::is_pressed();
        if button_pressed != last_button_state {
            last_button_state = button_pressed;
            button_press_time = now;
        }

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
        let coap_socket = socket_set.get::<UdpSocket>(coap_socket_handle);
        match operation_mode {
            OperationMode::TokenProvisioning(ref mut p) => {
                p.poll(coap_socket);
                if p.done() {
                    operation_mode = operation_mode.provisioning();
                }
            }
            OperationMode::Provisioning(ref mut p) => {
                p.poll(coap_socket);
                if p.done() {
                    operation_mode = operation_mode.attestation();
                }
            }
            OperationMode::Attestation(ref mut a) => a.poll(coap_socket),
            OperationMode::Idle { .. } => unreachable!(),
        }

        pal::cpu_relax();
    }
}
