use core::cell::RefCell;

use alloc::{rc::Rc, vec::Vec};
use coap_lite::{ContentFormat, MessageClass, Packet, RequestType, ResponseType};
use rsa::PublicKeyParts;
use smoltcp::socket::{SocketRef, UdpSocket};
use trussed::{
    client::CryptoClient,
    config::MAX_MESSAGE_LENGTH,
    types::{Location, Mechanism, Message, PathBuf},
};

use crate::{
    certmgr::CertMgr,
    coap::{CoapClient, Error},
    pal::timer::get_time_ms,
};
use state::State;

use super::{
    crypto, proto, signing, tpm,
    util::{format_hex, handle_server_error_response, HexFormatter},
};

mod state;

/// Client which speaks to attester in order to perform platform provisioning.
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

    /// Checks whether provisioning is done.
    pub fn done(&self) -> bool {
        let state = &mut *(*self.state).borrow_mut();

        matches!(state, State::Done)
    }

    pub fn poll(&mut self, socket: SocketRef<'_, UdpSocket>) {
        self.coap_client.poll(socket);

        let state = &mut *(*self.state).borrow_mut();

        match state {
            State::Done => {
                unreachable!("Should not be polled in this state");
            }
            State::Idle { timeout } => {
                if let Some(timeout) = timeout {
                    if get_time_ms() as u64 > *timeout {
                        *state = State::default();
                    }
                }
            }
            State::Init {
                ref mut request_pending,
            } => {
                if !*request_pending {
                    *request_pending = true;
                    let mut request = coap_lite::CoapRequest::new();
                    request.set_path("/attest");
                    request.set_method(RequestType::Fetch);
                    let state = Rc::clone(&self.state);
                    self.coap_client
                        .queue_request(request, move |result| Self::handle_response(result, state));
                }
            }
            State::InitDataReceived { data } => {
                match ::core::str::from_utf8(&data[..]) {
                    Ok(s) => {
                        info!("Received response from server: {}", s);
                    }
                    Err(e) => {
                        error!(
                            "Received response from server but it's not a valid UTF-8 string: {}",
                            e
                        );
                    }
                }

                *state = State::RequestEkCert {
                    request_pending: false,
                }
            }
            State::RequestEkCert {
                ref mut request_pending,
            } => {
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
                    };
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
                metadata,
                aik_pubkey,
            } => {
                let mut trussed = self.trussed.borrow_mut();

                match signing::decode_signed_object::<_, proto::Metadata>(
                    *trussed,
                    metadata,
                    aik_pubkey,
                    &[],
                ) {
                    Ok((metadata, raw_metadata)) => {
                        let h = trussed::syscall!(trussed.hash(
                            Mechanism::Sha256,
                            trussed::Bytes::from_slice(raw_metadata).unwrap()
                        ));

                        info!("Received attester metadata:");
                        info!("  Version      : {}", metadata.version);
                        info!("  MAC          : {}", metadata.mac);
                        info!("  Manufacturer : {}", metadata.manufacturer);
                        info!("  Product      : {}", metadata.product_name);
                        info!("  Serial       : {}", metadata.serial_number);

                        // For now we are unable to completely avoid copying
                        // data around because metadata hash goes through a few
                        // states. Move data now to heap so we have to move only
                        // pointer to that data.
                        let mut hash_copy = Vec::new();
                        hash_copy.extend_from_slice(h.hash.as_slice());

                        if Self::do_verify_metadata(&metadata) {
                            *state = State::RequestRim {
                                metadata_hash: hash_copy,
                                aik_pubkey: Rc::clone(aik_pubkey),
                                request_pending: false,
                            }
                        } else {
                            state.error();
                        }
                    }
                    Err(_e) => {
                        error!("Metadata invalid");
                        state.error();
                    }
                }
            }
            State::RequestRim {
                request_pending, ..
            } => {
                if !*request_pending {
                    let mut request = coap_lite::CoapRequest::new();
                    request.set_path("/rim");
                    request.set_method(RequestType::Fetch);
                    let state = Rc::clone(&self.state);
                    self.coap_client
                        .queue_request(request, move |result| Self::handle_response(result, state));
                    *request_pending = true;
                }
            }
            State::VerifyStoreRimAik {
                rim,
                aik_pubkey,
                metadata_hash,
            } => {
                let mut trussed = self.trussed.borrow_mut();
                match Self::do_verify_rim(*trussed, rim, aik_pubkey) {
                    Ok((_, raw_rim)) => {
                        // Save raw RIM as encoded by attester, RIM contents are
                        // already verified by checking signature and verifying
                        // sanity of the RIM itself.
                        // Avoid re-encoding and save it as-is but with stripped
                        // signature which we don't need anymore.
                        let meta = metadata_hash
                            .as_slice()
                            .try_into()
                            .expect("invalid length of metadata hash");
                        match Self::store_rim(*trussed, meta, raw_rim) {
                            Ok(()) => match Self::store_aik(*trussed, meta, aik_pubkey) {
                                Ok(()) => {
                                    info!("Provisioning complete");
                                    state.done();
                                }
                                Err(()) => {
                                    error!("Failed to save AIK in persistent storage");
                                    state.error();
                                }
                            },
                            Err(()) => {
                                error!("Failed to save RIM in persistent storage");
                                state.error();
                            }
                        }
                    }
                    Err(()) => {
                        error!("RIM verification failed");
                        state.error();
                    }
                }
            }
        }
    }

    fn handle_response(result: Result<Packet, Error>, state: Rc<RefCell<State>>) {
        let state = &mut *(*state).borrow_mut();

        match state {
            State::Init { .. }
            | State::RequestMetadata { .. }
            | State::RequestAik { .. }
            | State::RequestEkCert { .. }
            | State::VerifyAikStage2 { .. }
            | State::RequestRim { .. } => match result {
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
            State::InitDataReceived { .. }
            | State::Idle { .. }
            | State::Done
            | State::VerifyEkCertificate { .. }
            | State::VerifyMetadata { .. }
            | State::VerifyAikStage1 { .. }
            | State::LoadAik { .. }
            | State::VerifyStoreRimAik { .. } => {
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
            State::Init { .. } => {
                if result.header.code == MessageClass::Response(ResponseType::Content) {
                    *state = State::InitDataReceived {
                        data: result.payload,
                    };
                } else {
                    error!("Server gave invalid response to init request");
                    state.error();
                }
            }
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
            State::RequestRim {
                aik_pubkey,
                metadata_hash,
                ..
            } => {
                if result.header.code == MessageClass::Response(ResponseType::Content) {
                    // Trick to move data without copying.
                    // Rust won't allow us just move out data because doing
                    // so would make state invalid.
                    let mut hash = vec![];
                    core::mem::swap(metadata_hash, &mut hash);

                    *state = State::VerifyStoreRimAik {
                        rim: result.payload,
                        aik_pubkey: Rc::clone(aik_pubkey),
                        metadata_hash: hash,
                    }
                } else {
                    error!("Server gave invalid response to RIM request");
                    state.error();
                }
            }
            // We don't send any requests during these states so we shouldn't
            // get responses.
            State::InitDataReceived { .. }
            | State::Idle { .. }
            | State::VerifyEkCertificate { .. }
            | State::VerifyMetadata { .. }
            | State::VerifyAikStage1 { .. }
            | State::LoadAik { .. }
            | State::VerifyStoreRimAik { .. }
            | State::Done => {
                unreachable!()
            }
        }
    }

    /// Verify correctness of the metadata itself.
    fn do_verify_metadata(metadata: &proto::Metadata) -> bool {
        if metadata.version != proto::CURRENT_VERSION {
            error!(
                "Unsupported metadata version {}, expected version {}",
                metadata.version,
                proto::CURRENT_VERSION
            );
            return false;
        }

        // TODO: maybe should verify that strings aren't empty

        true
    }

    /// Store SHA-256 hash into non-volatile memory.
    fn store_rim<T>(trussed: &mut T, metadata_hash: &[u8; 32], rim: &[u8]) -> Result<(), ()>
    where
        T: trussed::client::FilesystemClient,
    {
        // Use filesystem as a database:
        // RIM is stored by creating a file with a name like this:
        // /meta/8784060ad4fd3d48a494e4db8051b8e56fbdd30b16f9a8c040e5ed1943d06edd
        // Hash is created by hashing platform metadata.

        let metadata_hash = format_hex(metadata_hash);
        let meta_dir = PathBuf::from(b"/meta/");
        let path_str = format!("/meta/{}", metadata_hash);

        let mut locate = trussed::syscall!(trussed.locate_file(
            Location::Internal,
            Some(meta_dir),
            PathBuf::from(metadata_hash.as_str())
        ));
        if let Some(path) = locate.path.take() {
            // File already exists, compare contents of the old RIM and current
            // RIM, if these are the same avoid writing to flash.
            let r = trussed::syscall!(trussed.read_file(Location::Internal, path));
            if r.data == rim {
                debug!("{} didn't change since last write", path_str);
                return Ok(());
            }
        }

        let path = PathBuf::from(path_str.as_str());
        if rim.len() > trussed::config::MAX_MESSAGE_LENGTH {
            error!(
                "RIM is too big: size exceeds MAX_MESSAGE_LENGTH ({} vs {})",
                rim.len(),
                trussed::config::MAX_MESSAGE_LENGTH
            );
            Err(())
        } else {
            let rim = Message::from_slice(rim).unwrap();
            trussed::try_syscall!(trussed.write_file(Location::Internal, path, rim, None))
                .map_err(|e| {
                    error!("Failed to save RIM: {:?}", e);
                })?;

            info!("Wrote {}", path_str);
            Ok(())
        }
    }

    fn store_aik<T>(
        trussed: &mut T,
        metadata_hash: &[u8; 32],
        aik_pubkey: &Rc<crypto::Key>,
    ) -> Result<(), ()>
    where
        T: trussed::client::FilesystemClient,
    {
        let metadata_hash = format_hex(metadata_hash);
        let meta_dir = PathBuf::from(b"/meta/");
        let path_str = format!("/meta/{}_aik", metadata_hash);

        let serialized = match aik_pubkey.as_ref() {
            crypto::Key::Rsa(rsa) => {
                let key = proto::PersistentRsaKey {
                    n: &rsa.inner.n().to_bytes_be()[..],
                    e: &rsa.inner.e().to_bytes_be()[..],
                };
                trussed::cbor_serialize_bytes::<_, MAX_MESSAGE_LENGTH>(&key).unwrap()
            }
        };

        let mut locate = trussed::syscall!(trussed.locate_file(
            Location::Internal,
            Some(meta_dir),
            PathBuf::from(metadata_hash.as_str())
        ));
        if let Some(path) = locate.path.take() {
            // File already exists, compare contents of with the old AIK and
            // current AIK, if these are the same avoid writing to flash.
            let r = trussed::syscall!(trussed.read_file(Location::Internal, path));
            if r.data == serialized {
                debug!("{} didn't change since last write", path_str);
                return Ok(());
            }
        }

        let path = PathBuf::from(path_str.as_str());
        if serialized.len() > trussed::config::MAX_MESSAGE_LENGTH {
            error!(
                "AIK is too big: size exceeds MAX_MESSAGE_LENGTH ({} vs {})",
                serialized.len(),
                trussed::config::MAX_MESSAGE_LENGTH
            );
            Err(())
        } else {
            trussed::try_syscall!(trussed.write_file(Location::Internal, path, serialized, None))
                .map_err(|e| {
                error!("Failed to save AIK: {:?}", e);
            })?;

            info!("Wrote {}", path_str);
            Ok(())
        }
    }

    fn do_verify_rim<'r, T>(
        trussed: &mut T,
        rim_with_sig: &'r [u8],
        aik: &Rc<crypto::Key>,
    ) -> Result<(proto::Rim<'r>, &'r [u8]), ()>
    where
        T: trussed::client::CryptoClient,
    {
        let (rim, raw_rim) =
            signing::decode_signed_object::<_, proto::Rim>(trussed, rim_with_sig, aik, &[])?;

        rim.verify().map_err(|_| error!("RIM is invalid"))?;

        for bank in rim.banks.iter() {
            info!("{}:", bank.algo_name);
            for (i, pcr) in bank {
                info!("  pcr{:02}: {}", i, HexFormatter(pcr));
            }
        }

        Ok((rim, raw_rim))
    }
}
