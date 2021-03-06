use core::cell::RefCell;

use alloc::{rc::Rc, vec::Vec};
use coap_lite::{ContentFormat, MessageClass, Packet, RequestType, ResponseType};
use pal::{
    led::{self, Led},
    timer::get_time_ms,
};
use sha2::Digest;
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
    tpm,
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
            State::Completion {
                attestation_success,
                timeout,
            } => {
                let l = if *attestation_success {
                    Led::Green
                } else {
                    Led::Red
                };

                if *timeout == 0 {
                    led::control(l, true);
                    // Wait for ten seconds before turning LED off
                    *timeout = get_time_ms() as u64 + 10000;
                } else if get_time_ms() as u64 > *timeout {
                    led::control(l, false);
                    *state = State::Idle { timeout: None };
                }
            }
            State::Init => {
                let mut trussed = self.trussed.borrow_mut();
                *state = State::RequestMetadata {
                    request_pending: false,
                    nonce: signing::generate_nonce(*trussed),
                }
            }
            State::RequestMetadata {
                request_pending,
                nonce,
            } => {
                if !*request_pending {
                    *request_pending = true;

                    coap_request!(RequestType::Fetch, "/metadata", proto::Nonce::new(nonce));
                }
            }
            State::LoadAik { metadata, nonce } => {
                let mut trussed = self.trussed.borrow_mut();
                match signing::hash_signed_object(*trussed, metadata.as_slice()) {
                    Ok(hash) => match Self::load_aik(*trussed, hash.as_slice()) {
                        Ok(aik) => {
                            match signing::decode_signed_object::<_, proto::Metadata>(
                                *trussed,
                                metadata.as_slice(),
                                &aik,
                                nonce,
                            ) {
                                Ok((meta, _)) => {
                                    info!("Attesting platform:");
                                    info!("  MAC          : {}", meta.mac);
                                    info!("  Manufacturer : {}", meta.manufacturer);
                                    info!("  Product      : {}", meta.product_name);
                                    info!("  Serial       : {}", meta.serial_number);
                                    match Self::load_rim(*trussed, &hash) {
                                        Ok(rim) => {
                                            *state = State::RequestEvidence {
                                                aik_pubkey: Rc::new(aik),
                                                nonce: generate_nonce(*trussed),
                                                rim,
                                                request_pending: false,
                                                // TODO: policy should be loaded from
                                                // internal storage
                                                policy: Policy::default(),
                                            }
                                        }
                                        Err(()) => state.error(),
                                    }
                                }
                                Err(()) => {
                                    error!("Metadata was not signed with proper AIK, did the AIK change?");
                                    state.error();
                                }
                            }
                        }
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
                policy,
                ..
            } => {
                if !*request_pending {
                    *request_pending = true;

                    coap_request!(
                        RequestType::Post,
                        "/quote",
                        &proto::QuoteRequest {
                            nonce: proto::Nonce::new(&nonce[..]),
                            banks: policy.banks
                        }
                    );
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
                        info!("Attestation successful");
                        // TODO: should clearly notify user that attestation is
                        // successful
                        // On real hardware this will be a green LED

                        // Currently attestation is run only once when Fobnail
                        // is plugged into USB.
                        *state = State::Completion {
                            attestation_success: true,
                            timeout: 0,
                        }
                    }
                    Err(()) => {
                        error!("Attestation failed");
                        // TODO: should clearly notify user that attestation has
                        // failed (red LED)

                        // Currently attestation is run only once when Fobnail
                        // is plugged into USB.
                        state.error();
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
                        "Communication with attester failed (state {}): {:#?}",
                        state, e
                    );
                    state.error();
                }
            },
            State::Init
            | State::Idle { .. }
            | State::LoadAik { .. }
            | State::VerifyEvidence { .. }
            | State::Completion { .. } => {
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
            State::RequestMetadata { nonce, .. } => {
                if result.header.code == MessageClass::Response(ResponseType::Content) {
                    *state = State::LoadAik {
                        metadata: result.payload,
                        nonce: *nonce,
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
                if result.header.code == MessageClass::Response(ResponseType::Created) {
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

        crypto::RsaKey::load(n, e)
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
        policy: &Policy,
    ) -> Result<(), ()>
    where
        T: trussed::client::CryptoClient,
    {
        // Load and verify integrity of RIM stored in internal memory.
        // TODO: ideally we would do all verification during deserialize stage
        // but serde doesn't allow this currently (at least not easily), also
        // validity of one field may depend on another field which brings more
        // problems.
        // https://github.com/serde-rs/serde/issues/939
        let rim = trussed::cbor_deserialize::<proto::Rim>(rim).map_err(|e| {
            error!("Failed to deserialize RIM from internal storage: {}", e);
            error!("RIM is corrupted, please re-provision your platform");
        })?;
        rim.verify().map_err(|_| {
            error!("RIM is corrupted, please re-provision your platform");
        })?;

        // Nonce is inside TPMS_ATTEST structure, not here
        let evidence = signing::verify_signed_object(trussed, evidence, aik, &[])
            .map_err(|_| {
                error!("Evidence has invalid signature");
            })
            .and_then(tpm::mu::Quote::decode)?;

        let tpm::mu::Quote {
            extra_data,
            safe,
            banks,
            digest,
        } = evidence;

        if extra_data != nonce {
            error!("Evidence nonce is invalid");
            return Err(());
        }

        if safe == 0 {
            error!("TPM clock is not safe");
            return Err(());
        }

        // Step 1: check if evidence contains bank that we did not request
        for bank in &banks {
            policy
                .banks
                .iter()
                .find(|x| bank.algo_id == x.algo_id)
                .ok_or_else(|| error!("Evidence contains bank we didn't request"))?;
        }

        // Step 2: check if evidence contains all banks we are interested in.
        // Check whether selected PCRs match policy's PCR selection.
        for bank in policy.banks {
            banks
                .iter()
                .find(|x| x.algo_id == bank.algo_id)
                .ok_or_else(|| {
                    error!(
                        "Required PCR bank ({}) not provided in evidence",
                        bank.algo_id
                    )
                })
                .and_then(|x| {
                    if bank.pcrs == x.pcrs {
                        Ok(())
                    } else {
                        error!("Attester provided evidence with wrong PCR select");
                        error!("expected 0x{:08x} got 0x{:08x}", bank.pcrs, x.pcrs);
                        Err(())
                    }
                })?;
        }

        // Don't use Trussed here. Trussed doesn't provide update() method so we
        // would have to merge all PCRs into continuous memory region
        // TODO: move to Trussed when it gains required APIs
        let mut hasher = if digest.len() == 32 {
            // assume SHA-256
            sha2::Sha256::new()
        } else {
            error!("Unsupported hash algorithm for TPM quote");
            return Err(());
        };

        // Step 3: Hash PCRs required by policy.
        //
        // Attester must hash PCR banks in the order defined by policy. PCRs
        // itself are always hashed starting with the lowest selected PCR.
        for bank in policy.banks {
            // Policy contains information about what we want to verify, actual
            // PCRs we need to load from RIM
            let bank_rim = rim
                .banks
                .inner
                .iter()
                .find(|x| x.algo_id == bank.algo_id)
                .ok_or_else(|| {
                    error!("RIM is missing required bank {}", bank.algo_id);
                    error!("This may be caused by platform's TPM lacking PCR bank required by the current policy");
                })?;

            let mut hashed_pcrs = 0u32;
            for (i, pcr) in bank_rim {
                if bank.pcrs & (1 << i) == 0 {
                    continue;
                }

                hasher.update(pcr);
                hashed_pcrs |= 1 << i;
            }

            // Check whether all PCRs required by policy are present.
            if hashed_pcrs != bank.pcrs {
                error!(
                    "RIM is missing required set of PCRs from bank {}",
                    bank.algo_id
                );
                return Err(());
            }
        }

        // Step 4: compare hashes
        let pcr_digest_from_rim = hasher.finalize();
        if &pcr_digest_from_rim[..] == digest {
            Ok(())
        } else {
            error!("PCRs don't match");
            Err(())
        }
    }
}
