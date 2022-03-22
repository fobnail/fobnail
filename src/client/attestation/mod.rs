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
    crypto, proto, signing, tpm,
    util::{handle_server_error_response, HexFormatter},
};
use crate::{
    certmgr::CertMgr,
    coap::{CoapClient, Error},
};
use state::State;

mod state;

/// Client which speaks to attester in order to perform platform attestation.
pub struct FobnailClient<'a> {
    state: Rc<RefCell<State<'a>>>,
    coap_client: CoapClient<'a>,
    trussed: RefCell<&'a mut trussed::ClientImplementation<pal::trussed::Syscall>>,
    certmgr: CertMgr,
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
            certmgr: CertMgr {},
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
            State::RequestEkCert { request_pending } => {
                if !*request_pending {
                    *request_pending = true;
                    let mut request = coap_lite::CoapRequest::new();
                    request.set_path("/ek");
                    request.set_method(RequestType::Fetch);
                    let state = Rc::clone(&self.state);
                    self.coap_client
                        .queue_request(request, move |result| Self::handle_response(result, state));
                }
            }
            State::VerifyEkCertificate { data } => {
                let mut trussed = self.trussed.borrow_mut();

                match tpm::ek::load(*trussed, &self.certmgr, data) {
                    Ok(cert) => {
                        *state = State::RequestAik {
                            request_pending: false,
                            ek_cert: Some(cert),
                        };
                    }
                    Err(e) => {
                        error!("Failed to load EK certificate: {}", e);
                        state.error()
                    }
                }
            }
            State::RequestAik {
                ref mut request_pending,
                ..
            } => {
                if !*request_pending {
                    *request_pending = true;
                    let mut request = coap_lite::CoapRequest::new();
                    request.set_path("/aik");
                    request.set_method(RequestType::Fetch);
                    let state = Rc::clone(&self.state);
                    self.coap_client
                        .queue_request(request, move |result| Self::handle_response(result, state));
                }
            }
            State::VerifyAikStage1 { data, ek_cert } => {
                let mut trussed = self.trussed.borrow_mut();

                match tpm::aik::decode(*trussed, data).and_then(|(_tpm_public, loaded_key_name)| {
                    tpm::prepare_aik_challenge(
                        *trussed,
                        tpm::mu::LoadedKeyName::decode(&loaded_key_name).unwrap(),
                        ek_cert,
                    )
                }) {
                    Ok((secret, id_object, encrypted_secret)) => {
                        // Trick to move data without copying.
                        // Rust won't allow us just move out data because doing
                        // so would make state invalid.
                        let mut aik = vec![];
                        core::mem::swap(data, &mut aik);

                        *state = State::VerifyAikStage2 {
                            request_pending: false,
                            secret,
                            id_object,
                            encrypted_secret,
                            aik,
                        }
                    }
                    Err(()) => {
                        error!("AIK verification failed");
                        state.error();
                    }
                }
            }
            State::VerifyAikStage2 {
                request_pending,
                id_object,
                encrypted_secret,
                ..
            } => {
                if !*request_pending {
                    let encoded = trussed::cbor_serialize_bytes::<_, 512>(&proto::Challenge {
                        id_object,
                        encrypted_secret,
                    })
                    .unwrap();

                    let mut request = coap_lite::CoapRequest::new();
                    request.set_path("/challenge");
                    request.set_method(RequestType::Post);
                    request.message.payload = encoded.to_vec();
                    request
                        .message
                        .set_content_format(ContentFormat::ApplicationCBOR);

                    let state = Rc::clone(&self.state);
                    self.coap_client
                        .queue_request(request, move |result| Self::handle_response(result, state));

                    *request_pending = true;
                }
            }
            State::LoadAik { raw_aik } => match tpm::aik::load(raw_aik) {
                Ok(aik) => {
                    *state = State::RequestMetadata {
                        aik_pubkey: aik,
                        request_pending: false,
                    }
                }
                Err(()) => {
                    error!("Failed to load AIK");
                    state.error();
                }
            },
            State::RequestMetadata {
                request_pending, ..
            } => {
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
            State::VerifyMetadata {
                aik_pubkey,
                metadata,
            } => {
                let mut trussed = self.trussed.borrow_mut();

                match signing::decode_signed_object::<_, proto::Metadata>(
                    *trussed, metadata, aik_pubkey,
                )
                .map(|(meta, _, hash)| (meta, hash))
                {
                    Ok((metadata, hash)) => {
                        info!("Attesting platform:");
                        info!("  Manufacturer : {}", metadata.manufacturer);
                        info!("  Product      : {}", metadata.product_name);
                        info!("  Serial       : {}", metadata.serial_number);
                        info!("  MAC          : {}", metadata.mac);

                        match Self::load_rim(*trussed, &hash) {
                            Ok(_rim) => {
                                error!("Attestation is not implemented");
                                state.error();
                            }
                            Err(()) => state.error(),
                        }
                    }
                    Err(()) => {
                        error!("Metadata invalid");
                        state.error();
                    }
                }
            }
        }
    }

    fn handle_response(result: Result<Packet, Error>, state: Rc<RefCell<State>>) {
        let state = &mut *(*state).borrow_mut();

        match state {
            State::RequestEkCert { .. }
            | State::RequestAik { .. }
            | State::VerifyAikStage2 { .. }
            | State::RequestMetadata { .. } => match result {
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
            State::VerifyEkCertificate { .. }
            | State::VerifyAikStage1 { .. }
            | State::Idle { .. }
            | State::LoadAik { .. }
            | State::VerifyMetadata { .. } => {
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
            State::RequestEkCert { .. } => {
                info!("Received EK certificate");

                if result.header.code == MessageClass::Response(ResponseType::Content) {
                    *state = State::VerifyEkCertificate {
                        data: result.payload,
                    }
                } else {
                    error!("Server gave invalid response to EK request");
                    state.error();
                }
            }
            State::RequestAik { ek_cert, .. } => {
                if result.header.code == MessageClass::Response(ResponseType::Content) {
                    *state = State::VerifyAikStage1 {
                        data: result.payload,
                        ek_cert: ek_cert.take().unwrap(),
                    };
                } else {
                    error!("Server gave invalid response to AIK request");
                    state.error();
                }
            }
            State::VerifyAikStage2 { secret, aik, .. } => {
                if result.header.code == MessageClass::Response(ResponseType::Created) {
                    if result.payload.as_slice() == secret.as_slice() {
                        // Trick to move data without copying.
                        // Rust won't allow us just move out data because doing
                        // so would make state invalid.
                        let mut raw_aik = vec![];
                        core::mem::swap(aik, &mut raw_aik);
                        *state = State::LoadAik { raw_aik };
                    } else {
                        error!("Attester has failed challenge");
                        state.error();
                    }
                } else {
                    error!("Invalid response during AIK stage 1 verification");
                    state.error();
                }
            }
            State::RequestMetadata { aik_pubkey, .. } => {
                if result.header.code == MessageClass::Response(ResponseType::Content) {
                    *state = State::VerifyMetadata {
                        metadata: result.payload,
                        aik_pubkey: Rc::clone(aik_pubkey),
                    }
                } else {
                    error!("Server gave invalid response to metadata request");
                    state.error();
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
}
