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

use core::sync::atomic::AtomicBool;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use certmgr::CertMgr;
use pal::embassy::time::{Duration, Instant, Ticker};
use pal::embassy_net::{udp::UdpSocket, PacketMetadata};

use coap_server::app::Request;
use coap_server::{app, CoapServer};
use futures_util::StreamExt;
use pal::embassy_util::blocking_mutex::raw::CriticalSectionRawMutex;
use pal::embassy_util::mutex::Mutex;
use pal::embassy_util::{select, Either, Forever};
use pal::led;
use trussed::ClientImplementation;
use udp::Endpoint;
use util::provisioning::is_token_provisioned;
use util::rng::TrussedRng;
use util::signing::Nonce;

mod certmgr;
mod server;
mod udp;
mod util;

/// How often to check for old clients to disconnect.
const CLIENT_PURGE_INTERVAL: Duration = Duration::from_secs(1);
/// Inactivity period after which client gets disconnected.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(3);

type TrussedClient = ClientImplementation<pal::trussed::Syscall>;

#[derive(Default)]
pub struct Client {
    nonce: Option<Nonce>,
    provisioning: server::provisioning::Data,
    attestation: server::attestation::Data,
}

pub struct ServerState {
    // FIXME: should avoid using CriticalSectionRawMutex as it disables USB
    // interrupts. ThreadModeRawMutex may be a possible alternative.
    trussed: &'static Mutex<CriticalSectionRawMutex, TrussedClient>,
    clients: Mutex<
        CriticalSectionRawMutex,
        BTreeMap<Endpoint, (Instant, Arc<Mutex<CriticalSectionRawMutex, Client>>)>,
    >,
    certmgr: Mutex<CriticalSectionRawMutex, CertMgr>,
    token_provisioned: AtomicBool,
    rng: TrussedRng<CriticalSectionRawMutex, TrussedClient>,
    /// Number of connected clients who passed attestation and have access to
    /// Fobnail Token Services.
    clients_with_fts_access: Mutex<CriticalSectionRawMutex, u32>,
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

    let token_provisioned = is_token_provisioned(&mut *trussed.lock().await).into();
    if token_provisioned {
        led::control(led::LedState::TokenWaiting);
    } else {
        led::control(led::LedState::TokenNotProvisioned);
    }

    static STATE: Forever<ServerState> = Forever::new();
    let state: &'static ServerState = STATE.put(ServerState {
        trussed,
        // TODO: Default could be implemented for embassy Mutex
        clients: Mutex::new(Default::default()),
        certmgr: Mutex::new(CertMgr::new()),
        token_provisioned: token_provisioned.into(),
        rng: util::rng::TrussedRng::new(trussed),
        clients_with_fts_access: Mutex::new(0),
    });

    macro_rules! handle {
        ($handler:expr) => {
            |req: Request<Endpoint>| async {
                let endpoint = req.original.source.unwrap();
                let client = handle_client(endpoint, state).await;
                ($handler)(req, state, client).await
            }
        };
    }

    let mut purger = Ticker::every(CLIENT_PURGE_INTERVAL);
    let server = server.serve(
        app::new()
            .ping_handler(move |ep| {
                let state = state;
                async move {
                    handle_client(ep, state).await;
                }
            })
            .not_discoverable()
            .block_transfer()
            .resources(vec![
                app::resource("/api/version").get(handle!(server::get_api_version)),
                app::resource("/api/v1/admin/token_provision").post(handle!(
                    server::token_provisioning::token_provision_certchain
                )),
                app::resource("/api/v1/admin/provision_complete").post(handle!(
                    server::token_provisioning::token_provision_complete
                )),
                app::resource("/api/v1/nonce").get(handle!(server::generate_nonce)),
                app::resource("/api/v1/admin/provision/ek")
                    .post(handle!(server::provisioning::process_ek)),
                app::resource("/api/v1/admin/provision/aik")
                    .post(handle!(server::provisioning::process_aik)),
                app::resource("/api/v1/admin/provision")
                    .post(handle!(server::provisioning::main_handler)),
                app::resource("/api/v1/attest").post(handle!(server::attestation::attest)),
                app::resource("/api/v1/storage/fs")
                    .default_handler(handle!(server::fts::storage::handler)),
            ]),
        state.rng.clone(),
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
    let mut clients_with_fts_access = state.clients_with_fts_access.lock().await;

    let np = *clients_with_fts_access;
    let mut n = *clients_with_fts_access;

    // drain_filter requires sync closure so we can't lock mutex from there.
    for (_k, v) in clients.iter() {
        if Instant::now().duration_since(v.0) > CLIENT_TIMEOUT {
            let c = v.1.lock().await;
            if c.attestation.platform().is_some() {
                n -= 1;
            }
        }
    }

    clients.drain_filter(|k, v| {
        if Instant::now().duration_since(v.0) > CLIENT_TIMEOUT {
            info!("disconnect client: {:?}", k);
            true
        } else {
            false
        }
    });

    *clients_with_fts_access = n;
    if n == 0 && np > 0 {
        led::control(led::LedState::TokenWaiting);
    }
}

async fn handle_client(
    ep: Endpoint,
    state: &ServerState,
) -> Arc<Mutex<CriticalSectionRawMutex, Client>> {
    let mut clients = state.clients.lock().await;
    if let Some(client) = clients.get_mut(&ep) {
        client.0 = Instant::now();
        Arc::clone(&client.1)
    } else {
        info!("new client: {:?}", ep);
        let client = Arc::new(Mutex::new(Client::default()));
        let client_2 = Arc::clone(&client);
        clients.insert(ep, (Instant::now(), client));
        client_2
    }
}
