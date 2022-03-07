use core::cell::RefCell;

use alloc::{rc::Rc, string::String, vec::Vec};
use coap_lite::{ContentFormat, MessageClass, Packet, RequestType, ResponseType};
use smoltcp::socket::{SocketRef, UdpSocket};
use trussed::{
    api::reply::RandomBytes,
    types::{Location, Message, PathBuf},
};

use crate::{
    certmgr::{CertMgr, X509Certificate},
    coap::{CoapClient, Error},
    pal::timer::get_time_ms,
};
use state::State;

use self::crypto::RsaKey;

mod crypto;
mod proto;
mod signing;
mod state;
mod tpm;

/// Client which speaks to Fobnail server located on attester
pub struct FobnailClient<'a> {
    state: Rc<RefCell<State<'a>>>,
    coap_client: CoapClient<'a>,
    trussed_platform: Rc<RefCell<trussed::ClientImplementation<pal::trussed::Syscall>>>,
    certmgr: CertMgr,
}

impl<'a> FobnailClient<'a> {
    pub fn new(
        coap_client: CoapClient<'a>,
        trussed_platform: trussed::ClientImplementation<pal::trussed::Syscall>,
    ) -> Self {
        Self {
            state: Rc::new(RefCell::new(State::default())),
            coap_client,
            trussed_platform: Rc::new(RefCell::new(trussed_platform)),
            certmgr: CertMgr {},
        }
    }

    pub fn poll(&mut self, socket: SocketRef<'_, UdpSocket>) {
        self.coap_client.poll(socket);

        let state = &*self.state;
        let state = &mut *state.borrow_mut();

        match state {
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
                let mut trussed = self.trussed_platform.borrow_mut();

                let cert = match self.certmgr.load_cert_owned(&data) {
                    Ok(cert) => {
                        match Self::verify_ek_certificate(&self.certmgr, &cert, &mut *trussed) {
                            Ok(()) => Some(cert),
                            Err(e) => {
                                error!("Failed to verify EK certificate: {}", e);
                                None
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to load EK certificate: {}", e);
                        None
                    }
                };

                if let Some(cert) = cert {
                    *state = State::RequestAik {
                        request_pending: false,
                        ek_cert: Some(cert),
                    };
                } else {
                    *state = State::Idle {
                        timeout: Some(get_time_ms() as u64 + 5000),
                    };
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
                let mut trussed = self.trussed_platform.borrow_mut();

                match Self::decode_aik(&mut *trussed, &data).and_then(
                    |(_tpm_public, loaded_key_name)| {
                        Self::prepare_aik_challenge(
                            &mut *trussed,
                            tpm::mu::LoadedKeyName::decode(&loaded_key_name).unwrap(),
                            ek_cert,
                        )
                    },
                ) {
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
                        *state = State::Idle {
                            timeout: Some(get_time_ms() as u64 + 5000),
                        };
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
                        id_object: &id_object,
                        encrypted_secret: &encrypted_secret,
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
            State::LoadAik { raw_aik } => match Self::load_aik(&raw_aik) {
                Ok(aik) => {
                    *state = State::RequestMetadata {
                        aik_pubkey: aik,
                        request_pending: false,
                    };
                }
                Err(()) => {
                    error!("Failed to load AIK");
                    *state = State::Idle {
                        timeout: Some(get_time_ms() as u64 + 5000),
                    }
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
                let mut trussed = self.trussed_platform.borrow_mut();

                match Self::do_verify_metadata_signature(&mut *trussed, metadata, aik_pubkey) {
                    Ok((metadata, hash)) => {
                        info!("Received attester metadata:");
                        info!("  Version      : {}", metadata.version);
                        info!("  MAC          : {}", metadata.mac);
                        info!("  Manufacturer : {}", metadata.manufacturer);
                        info!("  Product      : {}", metadata.product_name);
                        info!("  Serial       : {}", metadata.serial_number);
                        // Changing state will trigger destructor of AIK key,
                        // removing it from Trussed keystore. Destructor calls
                        // a closure which borrows trussed client, so we need to
                        // release current borrow to avoid panic.
                        drop(trussed);

                        if Self::do_verify_metadata(&metadata) {
                            *state = State::StoreMetadata { metadata, hash }
                        } else {
                            *state = State::Idle {
                                timeout: Some(get_time_ms() as u64 + 5000),
                            }
                        }
                    }
                    Err(_e) => {
                        error!("Metadata invalid");
                        *state = State::Idle {
                            timeout: Some(get_time_ms() as u64 + 5000),
                        }
                    }
                }
            }
            State::StoreMetadata { hash, .. } => {
                let mut trussed = self.trussed_platform.borrow_mut();
                let hash = hash.as_slice().try_into().expect("Invalid hash length");
                if !Self::have_metadata_hash(&mut *trussed, hash) {
                    Self::store_metadata_hash(&mut *trussed, hash);
                } else {
                    debug!("/meta/{} already in DB", Self::format_hash(hash));
                }

                *state = State::RequestRim {
                    request_pending: false,
                    metadata_hash: trussed::types::Bytes::from_slice(hash).unwrap(),
                };
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
        }
    }

    fn handle_response(result: Result<Packet, Error>, state: Rc<RefCell<State>>) {
        match result {
            Ok(resp) => Self::handle_server_response(resp, state),
            Err(e) => Self::handle_coap_error(e, state),
        }
    }

    /// Handles communication errors like timeouts or malformed response packets
    fn handle_coap_error(error: Error, state: Rc<RefCell<State>>) {
        let state = &*state;
        let state = &mut *state.borrow_mut();
        match state {
            State::Init { .. }
            | State::RequestMetadata { .. }
            | State::RequestAik { .. }
            | State::RequestEkCert { .. }
            | State::VerifyAikStage2 { .. }
            | State::RequestRim { .. } => {
                error!(
                    "Communication with attester failed (state {}): {:#?}, retrying after 1s",
                    state, error
                );
                *state = State::Idle {
                    timeout: Some(get_time_ms() as u64 + 1000),
                };
            }
            // We don't send any requests during these states so we shouldn't
            // get responses.
            State::InitDataReceived { .. }
            | State::Idle { .. }
            | State::VerifyEkCertificate { .. }
            | State::VerifyMetadata { .. }
            | State::StoreMetadata { .. }
            | State::VerifyAikStage1 { .. }
            | State::LoadAik { .. } => {
                unreachable!()
            }
        }
    }

    /// Handles server error responses - communication with server works and we
    /// received a valid response, but that response contains an error.
    fn handle_server_error_response(result: &Packet, state: &Rc<RefCell<State>>) -> bool {
        match result.header.code {
            #[rustfmt::skip]
            MessageClass::Response(r) => match r {
                // 200 (success codes)
                ResponseType::Created => return false,
                ResponseType::Deleted => return false,
                ResponseType::Valid => return false,
                ResponseType::Changed => return false,
                ResponseType::Content => return false,
                ResponseType::Continue => return false,

                // 400 codes
                ResponseType::BadRequest => error!("server error: Bad request"),
                ResponseType::Unauthorized => error!("server error: Unauthorized"),
                ResponseType::BadOption => error!("server error: Bad option"),
                ResponseType::Forbidden => error!("server error: Forbidden"),
                ResponseType::NotFound => error!("server error: Not found"),
                ResponseType::MethodNotAllowed => error!("server error: Method not allowed"),
                ResponseType::NotAcceptable => error!("server error: Not acceptable"),
                ResponseType::Conflict => error!("server error: Conflict"),
                ResponseType::PreconditionFailed => error!("server error: Precondition failed"),
                ResponseType::RequestEntityTooLarge => error!("server error: RequestEntityTooLarge"),
                ResponseType::UnsupportedContentFormat => error!("server error: Unsupported content format"),
                ResponseType::RequestEntityIncomplete => error!("server error: Request entity incomplete"),
                ResponseType::UnprocessableEntity => error!("server error: Unprocessable entity"),
                ResponseType::TooManyRequests => error!("server error: Too many requests"),
                // 500 codes
                ResponseType::InternalServerError => error!("server error: Internal server error"),
                ResponseType::NotImplemented => error!("server error: Not implemented"),
                ResponseType::BadGateway => error!("server error: Bad gateway"),
                ResponseType::ServiceUnavailable => error!("server error: Service unavailable"),
                ResponseType::GatewayTimeout => error!("server error: Gateway timeout"),
                ResponseType::ProxyingNotSupported => error!("server error: Proxying not supported"),
                ResponseType::HopLimitReached => error!("server error: Hop limit Reached"),

                ResponseType::UnKnown => error!("unknown server error"),
            },
            // CoapClient revokes any packets that are not response packet
            _ => unreachable!("This packet type should be handled by CoapClient"),
        }

        let state = &*state;
        let state = &mut *state.borrow_mut();
        match state {
            State::Init { .. } => {
                error!("Retrying in 5s ...");
                *state = State::Idle {
                    timeout: Some(get_time_ms() as u64 + 5000),
                };
            }
            State::RequestEkCert { .. } => {
                error!("Failed to request EK certificate, retrying in 5s");
                *state = State::Idle {
                    timeout: Some(get_time_ms() as u64 + 5000),
                }
            }
            State::RequestAik { .. } => {
                error!("Failed to request AIK key, retrying in 5s");
                *state = State::Idle {
                    timeout: Some(get_time_ms() as u64 + 5000),
                }
            }
            State::VerifyAikStage2 { .. } => {
                error!("Failed to send challenge, retrying in 5s");
                *state = State::Idle {
                    timeout: Some(get_time_ms() as u64 + 5000),
                }
            }
            State::RequestMetadata { .. } => {
                error!("Failed to request metadata, retrying in 5s");
                *state = State::Idle {
                    timeout: Some(get_time_ms() as u64 + 5000),
                };
            }
            State::RequestRim { .. } => {
                error!("Failed to request RIM, retrying in 5s");
                *state = State::Idle {
                    timeout: Some(get_time_ms() as u64 + 5000),
                };
            }
            // We don't send any requests during these states so we shouldn't
            // get responses.
            State::InitDataReceived { .. }
            | State::Idle { .. }
            | State::VerifyEkCertificate { .. }
            | State::VerifyMetadata { .. }
            | State::StoreMetadata { .. }
            | State::VerifyAikStage1 { .. }
            | State::LoadAik { .. } => {
                unreachable!()
            }
        }

        true
    }

    fn handle_server_response(result: Packet, state: Rc<RefCell<State>>) {
        if Self::handle_server_error_response(&result, &state) {
            return;
        }

        let state = &*state;
        let state = &mut *state.borrow_mut();

        match state {
            State::Init { .. } => {
                if result.header.code == MessageClass::Response(ResponseType::Content) {
                    *state = State::InitDataReceived {
                        data: result.payload,
                    };
                } else {
                    error!("Server gave invalid response to init request");
                    *state = State::Idle {
                        timeout: Some(get_time_ms() as u64 + 5000),
                    };
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
                    *state = State::Idle {
                        timeout: Some(get_time_ms() as u64 + 5000),
                    };
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
                    *state = State::Idle {
                        timeout: Some(get_time_ms() as u64 + 5000),
                    };
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
                        *state = State::Idle {
                            timeout: Some(get_time_ms() as u64 + 5000),
                        };
                    }
                } else {
                    error!("Invalid response during AIK stage 1 verification");
                    *state = State::Idle {
                        timeout: Some(get_time_ms() as u64 + 5000),
                    };
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
                    *state = State::Idle {
                        timeout: Some(get_time_ms() as u64 + 5000),
                    };
                }
            }
            State::RequestRim { .. } => {
                if result.header.code == MessageClass::Response(ResponseType::Content) {
                    *state = State::Idle {
                        timeout: Some(get_time_ms() as u64 + 5000),
                    }
                } else {
                    error!("Server gave invalid response to RIM request");
                    *state = State::Idle {
                        timeout: Some(get_time_ms() as u64 + 5000),
                    };
                }
            }
            // We don't send any requests during these states so we shouldn't
            // get responses.
            State::InitDataReceived { .. }
            | State::Idle { .. }
            | State::VerifyEkCertificate { .. }
            | State::VerifyMetadata { .. }
            | State::StoreMetadata { .. }
            | State::VerifyAikStage1 { .. }
            | State::LoadAik { .. } => {
                unreachable!()
            }
        }
    }

    /// Verify cryptographic signature of metadata.
    fn do_verify_metadata_signature<T>(
        trussed: &mut T,
        metadata: &[u8],
        key: &crypto::Key,
    ) -> Result<(proto::Metadata, trussed::Bytes<128>), ()>
    where
        T: trussed::client::CryptoClient,
    {
        signing::decode_signed_object::<_, proto::Metadata>(trussed, metadata, key)
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

    fn format_hash(hash: &[u8]) -> String {
        use core::fmt;

        struct Writer<'a>(&'a [u8]);
        impl fmt::Display for Writer<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for &x in self.0 {
                    write!(f, "{:02x}", x)?;
                }
                Ok(())
            }
        }
        format!("{}", Writer(hash))
    }

    /// Checks whether metadata hash is already stored
    fn have_metadata_hash<T>(trussed: &mut T, hash: &[u8; 32]) -> bool
    where
        T: trussed::client::FilesystemClient,
    {
        let hash = Self::format_hash(hash);
        let dir = PathBuf::from(b"/meta/");
        let r = trussed::syscall!(trussed.locate_file(
            Location::Internal,
            Some(dir),
            PathBuf::from(hash.as_str())
        ));
        r.path.is_some()
    }

    /// Store SHA-256 hash into non-volatile memory.
    fn store_metadata_hash<T>(trussed: &mut T, hash: &[u8; 32])
    where
        T: trussed::client::FilesystemClient,
    {
        // Use filesystem as a database:
        // Hash is stored by creating an empty file with a name like this:
        // /meta/8784060ad4fd3d48a494e4db8051b8e56fbdd30b16f9a8c040e5ed1943d06edd

        let data = Message::new();
        let hash = Self::format_hash(hash);
        let path = format!("/meta/{}", hash);
        debug!("Writing {}", path);

        let path = PathBuf::from(path.as_str());
        trussed::syscall!(trussed.write_file(Location::Internal, path, data, None));
    }

    fn verify_ek_certificate<T>(
        certmgr: &CertMgr,
        cert: &X509Certificate,
        trussed: &mut T,
    ) -> crate::certmgr::Result<()>
    where
        T: trussed::client::FilesystemClient + trussed::client::Sha256,
    {
        info!("X.509 version {}", cert.version());
        let issuer = cert.issuer()?;
        info!("Issuer: {}", issuer);
        let subject = cert.subject()?;
        info!("Subject: {}", subject);
        let key = cert.key()?;
        info!("Key: {}", key);

        certmgr.verify(trussed, cert)?;

        Ok(())
    }

    fn prepare_aik_challenge<T>(
        trussed: &mut T,
        loaded_key_name: tpm::mu::LoadedKeyName,
        ek_cert: &X509Certificate,
    ) -> Result<
        (
            trussed::types::Bytes<{ trussed::config::MAX_MESSAGE_LENGTH }>,
            Vec<u8>,
            Vec<u8>,
        ),
        (),
    >
    where
        T: trussed::client::CryptoClient + trussed::client::Sha256 + trussed::client::Aes256Cbc,
    {
        let RandomBytes { bytes: secret } = trussed::try_syscall!(trussed.random_bytes(32))
            .map_err(|e| {
                error!("Failed to generate secret: {:?}", e);
                ()
            })?;

        match ek_cert.key().map_err(|e| {
            error!("Failed to extract EK public key: {}", e);
            ()
        })? {
            crate::certmgr::Key::Rsa { n, e } => {
                let ek_key = RsaKey::load(n, e)?;

                let (id_object, encrypted_secret) = Self::make_credential_rsa(
                    trussed,
                    loaded_key_name,
                    &ek_key,
                    16,
                    secret.as_slice(),
                )
                .unwrap();

                Ok((secret, id_object, encrypted_secret))
            }
        }
    }

    /// Decode TPM2B_PUBLIC structure containing AIK key, AIK name, attributes.
    /// Verify key attributes and compute key name.
    fn decode_aik<'r, T>(
        trussed: &mut T,
        data: &'r [u8],
    ) -> Result<(tpm::mu::Public<'r>, Vec<u8>), ()>
    where
        T: trussed::client::Sha256,
    {
        const TPMA_OBJECT_FIXEDTPM: u32 = 0x00000002;
        const TPMA_OBJECT_FIXEDPARENT: u32 = 0x00000010;
        const TPMA_OBJECT_SENSITIVEDATAORIGIN: u32 = 0x00000020;
        const TPMA_OBJECT_USERWITHAUTH: u32 = 0x00000040;
        const TPMA_OBJECT_NODA: u32 = 0x00000400;
        const TPMA_OBJECT_DECRYPT: u32 = 0x00020000;
        const TPMA_OBJECT_SIGN_ENCRYPT: u32 = 0x00040000;

        const EXPECTED_AIK_ATTRIBUTES: u32 = TPMA_OBJECT_USERWITHAUTH
            | TPMA_OBJECT_SIGN_ENCRYPT
            | TPMA_OBJECT_DECRYPT
            | TPMA_OBJECT_FIXEDTPM
            | TPMA_OBJECT_FIXEDPARENT
            | TPMA_OBJECT_SENSITIVEDATAORIGIN
            | TPMA_OBJECT_NODA;

        let public = tpm::mu::Public::decode(data)?;
        if public.object_attributes != EXPECTED_AIK_ATTRIBUTES {
            error!(
                "Key attributes are not valid for AIK, expected {} got {}",
                EXPECTED_AIK_ATTRIBUTES, public.object_attributes
            );
            return Err(());
        }

        let name = match public.hash_algorithm {
            tpm::mu::Algorithm::Sha256 => {
                // We hash all bytes except first two which are size of
                // TPM2B_PUBLIC structure.

                let trussed::api::reply::Hash { hash } =
                    trussed::syscall!(trussed.hash_sha256(&public.raw_data[2..]));

                // Prepend algorithm ID to turn hash into name.
                let mut name = Vec::with_capacity(2 + hash.len());
                name.extend_from_slice(&public.hash_algorithm.as_raw().to_be_bytes());
                name.extend_from_slice(&hash);
                name
            }
            _ => {
                // TODO: to avoid matching hash algorithms in multiple places
                // we should create a universal helper method/class which takes
                // algorithm as parameter (instead of generics) and then calls
                // proper APIs.
                error!("Unsupported hash algorithm");
                error!("Cannot compute LKN");
                return Err(());
            }
        };

        Ok((public, name))
    }

    fn load_aik(raw_aik: &[u8]) -> Result<Rc<crypto::Key<'static>>, ()> {
        let key = tpm::mu::Public::decode(&raw_aik)?;

        match key.key {
            tpm::mu::PublicKey::Rsa { exponent, modulus } => match modulus.len() * 8 {
                1024 | 2048 | 4096 | 8192 => {
                    let key = RsaKey::load(&modulus, exponent)?;
                    Ok(Rc::new(crypto::Key::Rsa(key)))
                }

                n => {
                    error!("Unsupported RSA key size {}", n * 8);
                    Err(())
                }
            },
        }
    }
}
