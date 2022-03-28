use core::cell::RefCell;

use alloc::rc::Rc;
use coap_lite::{MessageClass, Packet, RequestType, ResponseType};
use pal::timer::get_time_ms;
use smoltcp::socket::{SocketRef, UdpSocket};
use trussed::{
    api::reply::ReadFile,
    types::{Location, PathBuf},
};

use super::{
    crypto, proto, signing,
    util::{format_hex, handle_server_error_response},
};
use crate::coap::{CoapClient, Error};
use state::State;

mod state;

/// Client which speaks to attester in order to perform platform attestation.
pub struct FobnailClient<'a> {
    state: Rc<RefCell<State>>,
    coap_client: CoapClient<'a>,
    trussed: RefCell<&'a mut trussed::ClientImplementation<pal::trussed::Syscall>>,
}

impl<'a> FobnailClient<'a> {
    pub fn new(
        coap_client: CoapClient<'a>,
        trussed: &'a mut trussed::ClientImplementation<pal::trussed::Syscall>,
    ) -> Self {
        Self {
            state: Rc::new(RefCell::new(State::default())),
            coap_client,
            trussed: RefCell::new(trussed),
        }
    }

    /// Reclaim ownership of Trussed client.
    pub fn into_trussed(self) -> &'a mut trussed::ClientImplementation<pal::trussed::Syscall> {
        let Self { trussed, .. } = self;
        trussed.into_inner()
    }

    pub fn poll(&mut self, socket: SocketRef<'_, UdpSocket>) {
        self.coap_client.poll(socket);

        let state = &mut *(*self.state).borrow_mut();
        match state {
            State::Idle { timeout } => {
                if let Some(timeout) = timeout {
                    if get_time_ms() as u64 > *timeout {
                        *state = State::default();
                    }
                }
            }
            State::RequestMetadata { request_pending } => {
                if !*request_pending {
                    *request_pending = true;
                    let mut request = coap_lite::CoapRequest::new();
                    request.set_path("/metadata");
                    request.set_method(RequestType::Fetch);
                    let state = Rc::clone(&self.state);
                    self.coap_client
                        .queue_request(request, move |result| Self::handle_response(result, state));
                }
            }
            State::LoadAik { metadata } => {
                let mut trussed = self.trussed.borrow_mut();
                match signing::hash_signed_object(*trussed, metadata.as_slice()) {
                    Ok(hash) => match Self::load_aik(*trussed, hash.as_slice()) {
                        Ok(_aik) => todo!(),
                        Err(()) => {
                            error!("Could not load AIK");
                            state.error()
                        }
                    },
                    Err(()) => {
                        error!("Invalid metadata");
                        state.error();
                    }
                }
            }
        }
    }

    fn handle_response(result: Result<Packet, Error>, state: Rc<RefCell<State>>) {
        let state = &mut *(*state).borrow_mut();

        match state {
            State::RequestMetadata { .. } => match result {
                Ok(resp) => {
                    Self::handle_server_response(resp, state);
                }
                Err(e) => {
                    error!(
                        "Communication with attester failed (state {}): {:#?}, retrying after 5s",
                        state, e
                    );
                    state.error();
                }
            },
            State::Idle { .. } | State::LoadAik { .. } => {
                // We don't send any requests during these states so we shouldn't
                // get responses.
                unreachable!(
                    "We shouldn't receive receive any response during this state ({})",
                    state
                )
            }
        }
    }

    fn handle_server_response(result: Packet, state: &mut State) {
        if handle_server_error_response(&result).is_err() {
            error!(
                "Failed to {}, server returned error {}, retrying in 5s",
                state, result.header.code
            );
            state.error();
            return;
        }

        match state {
            State::RequestMetadata { .. } => {
                if result.header.code == MessageClass::Response(ResponseType::Content) {
                    *state = State::LoadAik {
                        metadata: result.payload,
                    }
                } else {
                    error!("Server gave invalid response to metadata request");
                    state.error();
                }
            }
            _ => unimplemented!(),
        }
    }

    /// Load AIK from internal storage.
    fn load_aik<T>(trussed: &mut T, metadata_hash: &[u8]) -> Result<crypto::Key<'static>, ()>
    where
        T: trussed::client::FilesystemClient,
    {
        let metadata_hash = format_hex(metadata_hash);
        let path_str = format!("/meta/{}_aik", metadata_hash);
        let path = PathBuf::from(path_str.as_bytes());

        debug!("Loading AIK from {}", path_str);

        let ReadFile { data } = trussed::try_syscall!(trussed.read_file(Location::Internal, path))
            .map_err(|_| error!("Failed to load AIK (is the platform provisioned?)"))?;
        let proto::PersistentRsaKey { n, e } = trussed::cbor_deserialize(&data).map_err(|e| {
            error!("Failed to deserialize persistent key: {}", e);
            error!("AIK is corrupted, please re-provision your platform");
        })?;

        crypto::RsaKey::load2(n, e)
            .map(crypto::Key::Rsa)
            .map_err(|_| {
                error!("AIK is corrupted, please re-provision your platform");
            })
    }
}
