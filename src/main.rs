#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]
#![feature(btree_drain_filter)]

#[cfg(target_os = "none")]
extern crate pal_nrf as pal;

#[cfg(target_os = "linux")]
extern crate pal_pc as pal;

#[macro_use]
extern crate alloc;

#[macro_use]
extern crate log;

#[macro_use]
extern crate async_trait;

#[macro_use]
extern crate pin_project;

extern crate x509_cert as x509;

use alloc::collections::BTreeMap;
use pal::embassy::time::{Duration, Instant, Ticker};
use pal::embassy_net::{udp::UdpSocket, PacketMetadata};

use coap_server::app::Request;
use coap_server::{app, CoapServer};
use futures_util::StreamExt;
use pal::embassy_util::blocking_mutex::raw::CriticalSectionRawMutex;
use pal::embassy_util::mutex::Mutex;
use pal::embassy_util::{select, Either, Forever};
use trussed::ClientImplementation;
use udp::Endpoint;

mod certmgr;
mod server;
mod udp;
mod util;

/// How often to check for old clients to disconnect.
const CLIENT_PURGE_INTERVAL: Duration = Duration::from_secs(1);
/// Inactivity period after which client gets disconnected.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(3);

type TrussedClient = ClientImplementation<pal::trussed::Syscall>;

struct Client {
    last_activity: Instant,
}

pub struct ServerState {
    trussed: &'static Mutex<CriticalSectionRawMutex, TrussedClient>,
    clients: Mutex<CriticalSectionRawMutex, BTreeMap<Endpoint, Client>>,
}

#[pal::main]
async fn main() {
    info!("Hello from main");
    let mut clients = pal::trussed::init(&["fobnail"]);

    static TRUSSED: Forever<Mutex<CriticalSectionRawMutex, TrussedClient>> = Forever::new();
    let trussed = TRUSSED.put(Mutex::new(clients.pop().unwrap()));

    let stack = pal::net::stack();

    static RX_META: Forever<[PacketMetadata; 16]> = Forever::new();
    let rx_meta = RX_META.put([PacketMetadata::EMPTY; 16]);
    static RX_BUFFER: Forever<[u8; 4096]> = Forever::new();
    let rx_buffer = RX_BUFFER.put([0; 4096]);
    static TX_META: Forever<[PacketMetadata; 16]> = Forever::new();
    let tx_meta = TX_META.put([PacketMetadata::EMPTY; 16]);
    static TX_BUFFER: Forever<[u8; 4096]> = Forever::new();
    let tx_buffer = TX_BUFFER.put([0; 4096]);

    let server = CoapServer::bind(udp::UdpTransport::new(
        UdpSocket::new(stack, rx_meta, rx_buffer, tx_meta, tx_buffer),
        5683,
    ))
    .await
    .unwrap();

    static STATE: Forever<ServerState> = Forever::new();
    let state = STATE.put(ServerState {
        trussed,
        // TODO: Default could be implemented for embassy Mutex
        clients: Mutex::new(Default::default()),
    });

    macro_rules! handle {
        ($handler:expr) => {
            |req: Request<Endpoint>| async {
                handle_client(req.original.source.unwrap(), state).await;
                ($handler)(req, state).await
            }
        };
    }

    let mut purger = Ticker::every(CLIENT_PURGE_INTERVAL);
    let server = server.serve(
        app::new()
            .ping_handler(|ep| info!("PING from {:?}", ep))
            .not_discoverable()
            .block_transfer()
            .resources(vec![
                app::resource("/admin/token_provision").post(handle!(
                    server::token_provisioning::token_provision_certchain
                )),
                app::resource("/admin/provision_complete").post(handle!(
                    server::token_provisioning::token_provision_complete
                )),
            ]),
        util::rng::TrussedRng::new(trussed),
    );
    futures_util::pin_mut!(server);
    loop {
        match select(&mut server, purger.next()).await {
            Either::First(_) => {
                panic!("CoAP server died")
            }
            Either::Second(x) => {
                // Timer should never stop ticking
                let _ = x.unwrap();
                remove_clients(state).await;
            }
        }
    }
}

// TODO: actually, this could be easily spawned onto executor
async fn remove_clients(state: &ServerState) {
    let mut clients = state.clients.lock().await;
    clients.drain_filter(|k, v| {
        if Instant::now().duration_since(v.last_activity) > CLIENT_TIMEOUT {
            info!("disconnect client: {:?}", k);
            true
        } else {
            false
        }
    });
}

async fn handle_client(ep: Endpoint, state: &ServerState) {
    let mut clients = state.clients.lock().await;
    if let Some(client) = clients.get_mut(&ep) {
        client.last_activity = Instant::now();
    } else {
        info!("new client: {:?}", ep);
        clients.insert(
            ep,
            Client {
                last_activity: Instant::now(),
            },
        );
    }
}
