use core::cell::RefCell;

use alloc::{rc::Rc, vec::Vec};
use coap_lite::{ContentFormat, MessageClass, Packet, RequestType, ResponseType};
use pal::timer::get_time_ms;
use smoltcp::socket::{SocketRef, UdpSocket};
use trussed::{
    api::reply::ReadFile,
    types::{Location, PathBuf},
};

use super::{
    crypto,
    policy::Policy,
    proto,
    signing::{self, generate_nonce},
    util::{handle_server_error_response, HexFormatter},
};
use crate::{
    client::util::format_hex,
    coap::{CoapClient, Error},
};
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

        macro_rules! coap_request {
            ($method:expr, $ep:expr) => {{
                let mut request = coap_lite::CoapRequest::new();
                request.set_path($ep);
                request.set_method($method);
                let state = Rc::clone(&self.state);
                self.coap_client
                    .queue_request(request, move |result| Self::handle_response(result, state));
            }};

            ($method:expr, $ep:expr, $data:expr) => {{
                let mut request = coap_lite::CoapRequest::new();
                request.set_path($ep);
                request.set_method($method);

                let encoded = trussed::cbor_serialize_bytes::<_, 512>(&$data).unwrap();
                request.message.payload = encoded.to_vec();
                request
                    .message
                    .set_content_format(ContentFormat::ApplicationCBOR);

                let state = Rc::clone(&self.state);
                self.coap_client
                    .queue_request(request, move |result| Self::handle_response(result, state));
            }};
        }

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

                    coap_request!(RequestType::Fetch, "/metadata");
                }
            }
            State::LoadAik { metadata } => {
                let mut trussed = self.trussed.borrow_mut();
                match signing::hash_signed_object(*trussed, metadata.as_slice()) {
                    Ok(hash) => match Self::load_aik(*trussed, hash.as_slice()) {
                        Ok(aik_pubkey) => match Self::load_rim(*trussed, &hash) {
                            Ok(rim) => {
                                *state = State::RequestEvidence {
                                    aik_pubkey: Rc::new(aik_pubkey),
                                    nonce: generate_nonce(*trussed),
                                    rim,
                                    request_pending: false,
                                    // TODO: policy should be loaded from
                                    // internal storage
                                    policy: Policy::default(),
                                }
                            }
                            Err(()) => state.error(),
                        },
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
            State::RequestEvidence {
                request_pending,
                nonce,
                ..
            } => {
                if !*request_pending {
                    *request_pending = true;

                    coap_request!(RequestType::Fetch, "/rim", &proto::Nonce::new(&nonce[..]));
                }
            }
            State::VerifyEvidence {
                nonce,
                evidence,
                rim,
                aik_pubkey,
                policy,
            } => {
                let mut trussed = self.trussed.borrow_mut();
                match Self::verify_evidence(*trussed, nonce, rim, evidence, aik_pubkey, policy) {
                    Ok(()) => {
                        info!("Attestation complete");
                        // TODO: should clearly notify user that attestation is
                        // successful
                        // On real hardware this will be a green LED
                    }
                    Err(()) => {
                        // TODO: should clearly notify user that attestation has
                        // failed (red LED)
                        state.error()
                    }
                }
            }
        }
    }

    fn handle_response(result: Result<Packet, Error>, state: Rc<RefCell<State>>) {
        let state = &mut *(*state).borrow_mut();

        match state {
            State::RequestMetadata { .. } | State::RequestEvidence { .. } => match result {
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
            State::Idle { .. } | State::LoadAik { .. } | State::VerifyEvidence { .. } => {
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
            State::RequestEvidence {
                aik_pubkey,
                rim,
                nonce,
                policy,
                ..
            } => {
                if result.header.code == MessageClass::Response(ResponseType::Content) {
                    // Trick to move data without copying.
                    // Rust won't allow us just move out data because doing
                    // so would make state invalid.
                    let mut rim_moved = vec![];
                    core::mem::swap(rim, &mut rim_moved);

                    *state = State::VerifyEvidence {
                        aik_pubkey: Rc::clone(aik_pubkey),
                        rim: rim_moved,
                        evidence: result.payload,
                        nonce: *nonce,
                        policy: *policy,
                    }
                } else {
                    error!("Server gave invalid response to evidence request");
                    state.error()
                }
            }
            _ => {
                // We already matched all possible states in handle_response()
                // and we should never reach here
                unreachable!()
            }
        }
    }

    fn load_rim<T>(trussed: &mut T, metadata_hash: &[u8]) -> Result<Vec<u8>, ()>
    where
        T: trussed::client::FilesystemClient,
    {
        let path_str = format!("/meta/{}", HexFormatter(metadata_hash));
        let path = PathBuf::from(path_str.as_str());
        match trussed::try_syscall!(trussed.read_file(Location::Internal, path)) {
            Ok(ReadFile { data }) => {
                let mut data_copy = Vec::new();
                data_copy.extend_from_slice(&data);
                Ok(data_copy)
            }
            Err(trussed::Error::FilesystemReadFailure) => {
                error!("Failed to read {} (is the platform provisioned?)", path_str);
                Err(())
            }
            Err(e) => {
                error!("Unknown file system error: {:?}", e);
                Err(())
            }
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

    fn verify_evidence<T>(
        trussed: &mut T,
        nonce: &[u8],
        rim: &[u8],
        evidence: &[u8],
        aik: &Rc<crypto::Key>,
        _policy: &Policy,
    ) -> Result<(), ()>
    where
        T: trussed::client::CryptoClient,
    {
        // Load and verify integrity of RIM stored in internal memory.
        let rim = trussed::cbor_deserialize::<proto::Rim>(rim).map_err(|e| {
            error!("Failed to deserialize RIM from internal storage: {}", e);
            error!("RIM is corrupted, please re-provision your platform");
        })?;
        rim.verify().map_err(|_| {
            error!("RIM is corrupted, please re-provision your platform");
        })?;

        // Verify integrity of evidence
        let (evidence, _) =
            signing::decode_signed_object::<_, proto::Rim>(trussed, evidence, aik, nonce)
                .map_err(|_| error!("Evidence has invalid signature"))?;
        evidence.verify().map_err(|_| {
            error!("Evidence contains invalid data");
        })?;

        // Do an actual evidence verification (appraisal) against RIMs and
        // policy

        info!("Commencing evidence verification");

        // very simple test
        // TODO: update_ctr?
        /*for (idx, pcr) in &rim.sha1 {
            if let Some(pcr_from_evidence) = evidence.sha1.pcr(idx) {
                if pcr_from_evidence == pcr {
                    debug!("pcr{:02}: match", idx);
                } else {
                    error!("pcr{:02}: mismatch", idx);
                }
            } else {
                error!("pcr{:02}: missing", idx);
            }
        }*/

        Err(())
    }
}
