use core::cell::RefCell;

use alloc::{rc::Rc, string::String};
use coap_lite::{MessageClass, Packet, RequestType, ResponseType};
use rsa::PublicKey as _;
use smoltcp::socket::{SocketRef, UdpSocket};
use trussed::{
    config::MAX_SIGNATURE_LENGTH,
    types::{Location, Mechanism, Message, PathBuf},
};

use crate::{
    coap::{CoapClient, Error},
    pal::timer::get_time_ms,
};
use state::State;

use self::{
    crypto::{Ed25519Key, RsaKey},
    proto::AikKey,
};

mod crypto;
mod proto;
mod state;

/// Client which speaks to Fobnail server located on attester
pub struct FobnailClient<'a> {
    state: Rc<RefCell<State<'a>>>,
    coap_client: CoapClient<'a>,
    trussed_platform: Rc<RefCell<trussed::ClientImplementation<pal::trussed::Syscall>>>,
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
            State::RequestAik {
                ref mut request_pending,
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
                        info!("  Version : {}", metadata.version);
                        info!("  MAC     : {}", metadata.mac);
                        info!("  Serial  : {}", metadata.sn);
                        info!("  EK hash : {}", metadata.ek_hash.id);
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

                *state = State::Idle {
                    timeout: Some(get_time_ms() as u64 + 5000),
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
            | State::RequestEkCert { .. } => {
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
            | State::VerifyMetadata { .. }
            | State::StoreMetadata { .. } => {
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
            State::RequestMetadata { .. } => {
                error!("Failed to request metadata, retrying in 5s");
                *state = State::Idle {
                    timeout: Some(get_time_ms() as u64 + 5000),
                };
            }
            // We don't send any requests during these states so we shouldn't
            // get responses.
            State::InitDataReceived { .. }
            | State::Idle { .. }
            | State::VerifyMetadata { .. }
            | State::StoreMetadata { .. } => {
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
                *state = State::RequestAik {
                    request_pending: false,
                }
            }
            State::RequestAik { .. } => {
                if result.header.code == MessageClass::Response(ResponseType::Content) {
                    let key = trussed::cbor_deserialize::<proto::AikKey>(&result.payload).unwrap();
                    match key.key_type {
                        proto::KeyType::Rsa => match key.key.n.len() * 8 {
                            1024 | 2048 | 4096 | 8192 => match Self::verify_aik(&key) {
                                Ok(()) => match RsaKey::load(&key.key.n, key.key.e) {
                                    Ok(key) => {
                                        *state = State::RequestMetadata {
                                            request_pending: false,
                                            aik_pubkey: Rc::new(crypto::Key::Rsa(key)),
                                        }
                                    }
                                    Err(_) => {
                                        *state = State::Idle {
                                            timeout: Some(get_time_ms() as u64 + 5000),
                                        };
                                    }
                                },
                                Err(()) => {
                                    error!("AIK verification failed");
                                    *state = State::Idle {
                                        timeout: Some(get_time_ms() as u64 + 5000),
                                    };
                                }
                            },
                            n => {
                                error!("Unsupported RSA key size {}", n);
                                *state = State::Idle {
                                    timeout: Some(get_time_ms() as u64 + 5000),
                                };
                            }
                        },
                        t => {
                            error!("Unsupported key type {:?}", t);
                            *state = State::Idle {
                                timeout: Some(get_time_ms() as u64 + 5000),
                            };
                        }
                    }
                } else {
                    error!("Server gave invalid response to AIK request");
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
            // We don't send any requests during these states so we shouldn't
            // get responses.
            State::InitDataReceived { .. }
            | State::Idle { .. }
            | State::VerifyMetadata { .. }
            | State::StoreMetadata { .. } => {
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
        T: trussed::client::Ed255 + trussed::client::Sha256,
    {
        let metadata_with_sig = trussed::cbor_deserialize::<proto::MetadataWithSignature>(metadata)
            .map_err(|_| {
                error!("Metadata deserialization failed");
                ()
            })?;

        if metadata_with_sig.signature.len() > MAX_SIGNATURE_LENGTH {
            // If verify_ed255() is called with to big signature then Trussed
            // will panic, so we need to handle that case ourselves.
            error!("Signature size exceeds MAX_SIGNATURE_LENGTH");
            return Err(());
        }

        // We expect SHA256 for RSA and SHA512 for Ed25519
        match key {
            crypto::Key::Ed25519(key) => {
                match trussed::try_syscall!(trussed.verify_ed255(
                    key.key_id().clone(),
                    metadata_with_sig.encoded_metadata,
                    metadata_with_sig.signature,
                )) {
                    Ok(v) if v.valid => {
                        let sha = trussed::try_syscall!(
                            trussed.hash_sha256(metadata_with_sig.encoded_metadata)
                        )
                        .map_err(|e| {
                            error!("Failed to compute SHA-256: {:?}", e);
                        })?;

                        let meta = trussed::cbor_deserialize::<proto::Metadata>(
                            metadata_with_sig.encoded_metadata,
                        )
                        .map_err(|_| error!("Metadata deserialization failed"))?;
                        Ok((meta, sha.hash))
                    }
                    Ok(_) => {
                        error!("Metadata signature is invalid");
                        Err(())
                    }
                    Err(e) => {
                        error!("verify_ed255() failed: {:?}", e);
                        Err(())
                    }
                }
            }
            crypto::Key::Rsa(key) => {
                let sha = trussed::try_syscall!(trussed.hash(
                    Mechanism::Sha256,
                    trussed::Bytes::from_slice(metadata_with_sig.encoded_metadata).unwrap(),
                ))
                .map_err(|e| {
                    error!("Failed to compute SHA-256: {:?}", e);
                })?;
                // Currently, Trussed does not provide RSA support so we use
                // rsa crate directly.
                match key.inner.verify(
                    rsa::PaddingScheme::PKCS1v15Sign {
                        hash: Some(rsa::Hash::SHA2_256),
                    },
                    &sha.hash,
                    metadata_with_sig.signature,
                ) {
                    Ok(_) => {
                        let meta = trussed::cbor_deserialize::<proto::Metadata>(
                            metadata_with_sig.encoded_metadata,
                        )
                        .map_err(|_| error!("Metadata deserialization failed"))?;
                        Ok((meta, sha.hash))
                    }
                    Err(e) => {
                        error!("Metadata signature verification failed: {}", e);
                        Err(())
                    }
                }
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

        let expected_hash_len = match metadata.ek_hash.id {
            proto::HashType::SHA1 => 20,
            proto::HashType::SHA256 => 32,
            proto::HashType::SHA512 => 64,
        };
        if metadata.ek_hash.hash.len() != expected_hash_len {
            error!(
                "Invalid EK cert hash, expected hash with length of {} bytes (type {}) but got {}.",
                expected_hash_len,
                metadata.ek_hash.id,
                metadata.ek_hash.hash.len()
            );
            return false;
        }

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

    fn verify_aik(aik: &AikKey) -> Result<(), ()> {
        Ok(())
    }
}
