use core::cell::RefCell;

use crate::{
    certmgr::{CertMgr, Key},
    coap::{CoapClient, Error},
};
use alloc::{boxed::Box, rc::Rc};
use coap_lite::{MessageClass, Packet, RequestType, ResponseType};
use pal::timer::get_time_ms;
use rsa::PublicKeyParts;
use smoltcp::socket::{SocketRef, UdpSocket};
use state::State;

use super::{crypto, proto, util::handle_server_error_response};

mod csr;
mod state;

/// Client which speaks to the Platform Owner in order to perform Fobnail Token
/// provisioning.
pub struct FobnailClient<'a> {
    state: Rc<RefCell<State>>,
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
            certmgr: CertMgr::new(),
        }
    }

    /// Reclaim ownership of Trussed client.
    pub fn into_trussed(self) -> &'a mut trussed::ClientImplementation<pal::trussed::Syscall> {
        let Self { trussed, .. } = self;
        trussed.into_inner()
    }

    /// Checks whether provisioning is done.
    pub fn done(&self) -> bool {
        let state = &mut *(*self.state).borrow_mut();

        matches!(state, State::Done)
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

            // Like above, but without encoding
            ($method:expr, $ep:expr, raw $data:expr) => {{
                let mut request = coap_lite::CoapRequest::new();
                request.set_path($ep);
                request.set_method($method);
                request.message.payload = $data;

                let state = Rc::clone(&self.state);
                self.coap_client
                    .queue_request(request, move |result| Self::handle_response(result, state));
            }};
        }

        let state = &mut *(*self.state).borrow_mut();
        match state {
            State::Done => {
                unreachable!("Should not be polled in this state");
            }
            State::RequestPoCertChain { request_pending } => {
                if !*request_pending {
                    *request_pending = true;

                    coap_request!(RequestType::Fetch, "/cert_chain")
                }
            }
            State::SignalStatus { success } => {
                // Volatile certs are not removed in verify_certchain because
                // are needed to complete provisioning. Remove them here before
                // retrying provisioning.
                self.certmgr.clear_volatile_certs();

                // TODO: signal status, probably should use different signaling
                // than when provisioning platform
                if *success {
                    *state = State::Done;
                } else {
                    *state = State::Idle {
                        timeout: Some(get_time_ms() as u64 + 5000),
                    };
                }
            }
            State::Idle { timeout } => {
                if let Some(timeout) = timeout {
                    if get_time_ms() as u64 > *timeout {
                        *state = State::default();
                    }
                }
            }
            State::VerifyPoCertChain { chain } => {
                let mut trussed = self.trussed.borrow_mut();
                if Self::verify_certchain(*trussed, &mut self.certmgr, chain).is_err() {
                    error!("PO chain verification failed");
                    state.error();
                } else {
                    info!("PO chain verification OK");
                    *state = State::GenerateKeys;
                }
            }
            State::GenerateKeys => {
                let mut trussed = self.trussed.borrow_mut();
                let keypair = Box::new(crypto::generate_rsa_key(*trussed, 2048));

                *state = State::SendCsr {
                    request_pending: false,
                    keypair: Some(keypair),
                }
            }
            State::SendCsr {
                request_pending,
                keypair,
            } => {
                if !*request_pending {
                    *request_pending = true;

                    let keypair = keypair.as_ref().unwrap();

                    let req = csr::make_csr(&keypair.0, &keypair.1, pal::device_id()).unwrap();
                    coap_request!(RequestType::Post, "csr", raw req);
                }
            }
            State::VerifyCertificate {
                certificate,
                keypair,
            } => {
                let mut trussed = self.trussed.borrow_mut();
                match Self::verify_certificate(
                    *trussed,
                    &mut self.certmgr,
                    &certificate,
                    &keypair.1,
                ) {
                    Ok(()) => {
                        info!("Fobnail provisioning complete");
                        state.done();
                    }
                    Err(()) => state.error(),
                }
            }
        }
    }

    fn handle_response(result: Result<Packet, Error>, state: Rc<RefCell<State>>) {
        let state = &mut *(*state).borrow_mut();

        match state {
            State::RequestPoCertChain { .. } | State::SendCsr { .. } => match result {
                Ok(resp) => {
                    Self::handle_server_response(resp, state);
                }
                Err(e) => {
                    error!(
                        "Communication with platform owner failed (state {}): {:#?}",
                        state, e
                    );
                    state.error();
                }
            },
            State::Done
            | State::Idle { .. }
            | State::SignalStatus { .. }
            | State::VerifyPoCertChain { .. }
            | State::GenerateKeys
            | State::VerifyCertificate { .. } => {
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
            State::RequestPoCertChain { .. } => {
                if result.header.code == MessageClass::Response(ResponseType::Content) {
                    *state = State::VerifyPoCertChain {
                        chain: result.payload,
                    }
                } else {
                    error!("Server gave invalid response to certificate chain request");
                    state.error();
                }
            }
            State::SendCsr { keypair, .. } => {
                if result.header.code == MessageClass::Response(ResponseType::Created) {
                    *state = State::VerifyCertificate {
                        keypair: keypair.take().unwrap(),
                        certificate: result.payload,
                    }
                } else {
                    error!("Server gave invalid response to certification request");
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

    /// Verify certchain. On success certificates are loaded into certstore as
    /// volatile certificates so that they can be used later.
    fn verify_certchain<T>(trussed: &mut T, certmgr: &mut CertMgr, chain: &[u8]) -> Result<(), ()>
    where
        T: trussed::client::FilesystemClient + trussed::client::Sha256,
    {
        /// Minimal number of certificates required in a chain (including root).
        const MIN_CERTS: usize = 2;
        /// Max number of certificates allowed in a chain (including root).
        const MAX_CERTS: usize = 3;

        let chain = trussed::cbor_deserialize::<proto::CertChain>(chain)
            .map_err(|e| error!("Failed to deserialize PO certchain: {}", e))?;

        let num_certs = chain.certs.len();
        if !matches!(num_certs, MIN_CERTS..=MAX_CERTS) {
            error!(
                "Expected between {} and {} certificates but got {}",
                MIN_CERTS, MAX_CERTS, num_certs
            );
            return Err(());
        }

        let mut it = chain.certs.iter();
        let root_raw = it.next().unwrap();
        // Attester sends full chain, including root ca. Check only whether received
        // root CA matches embedded CA.
        if &root_raw[..] != CertMgr::po_root_raw() {
            error!("Received root CA doesn't match with CA stored in firmware");
            return Err(());
        }

        for cert in it {
            match certmgr.load_cert_owned(cert) {
                Ok(cert) => match certmgr.verify(trussed, &cert, crate::certmgr::VerifyMode::Po) {
                    Ok(()) => {
                        // Inject as volatile certificate, we will save
                        // certificates to persistent storage only after entire
                        // chain has been verified.
                        certmgr.inject_volatile_cert(cert);
                    }
                    Err(e) => {
                        error!("Cert verification failed: {}", e);
                        return Err(());
                    }
                },
                Err(e) => {
                    error!("Invalid certificate: {}", e);
                    return Err(());
                }
            }
        }

        Ok(())
    }

    /// Verify generated Identity/Encryption certificate. If verification is
    /// successful save it to persistent storage, completing Fobnail token
    /// provisioning.
    fn verify_certificate<T>(
        trussed: &mut T,
        certmgr: &mut CertMgr,
        cert_raw: &[u8],
        public_key: &rsa::RsaPublicKey,
    ) -> Result<(), ()>
    where
        T: trussed::client::FilesystemClient + trussed::client::Sha256,
    {
        let cert = certmgr.load_cert(cert_raw).map_err(|e| error!("{}", e))?;
        certmgr
            .verify(trussed, &cert, crate::certmgr::VerifyMode::TokenCert)
            .map_err(|e| error!("{}", e))?;

        let cert_key = cert.key().map_err(|e| error!("{}", e))?;

        let mut exponent_bytes = [0u8; 4];
        let e = public_key.e().to_bytes_be();
        if e.is_empty() || e.len() > 4 {
            return Err(());
        }
        let l = e.len();
        exponent_bytes[4 - l..].copy_from_slice(&e);
        let expected_exponent = exponent_bytes;

        match cert_key {
            Key::Rsa { n, e } => {
                if n != public_key.n().to_bytes_be() || e.to_be_bytes() != expected_exponent {
                    error!("Generated certificate public key mismatch");

                    return Err(());
                }
            }
        }

        certmgr
            .save_certificate(trussed, &cert, "token_cert")
            .map_err(|()| error!("Could not save certificate in persistent storage"))?;

        Ok(())
    }
}
