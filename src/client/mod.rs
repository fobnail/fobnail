use core::cell::RefCell;

use alloc::{rc::Rc, string::String};
use coap_lite::{MessageClass, Packet, RequestType, ResponseType};
use smoltcp::socket::{SocketRef, UdpSocket};
use trussed::{
    config::MAX_SIGNATURE_LENGTH,
    types::{Location, Message, PathBuf},
};

use crate::{
    coap::{CoapClient, Error},
    pal::timer::get_time_ms,
};
use state::State;

use self::crypto::Ed25519Key;

mod crypto;
mod metadata;
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

                *state = State::RequestMetadata {
                    request_pending: false,
                    aik_pubkey: {
                        // For now let's use hardcoded key.
                        // This will be removed soon and key will be received
                        // from attester.
                        static KEY: &'static [u8] = &[
                            0x4a, 0xd9, 0xd7, 0xfe, 0xba, 0x04, 0xb3, 0x83, 0xa1, 0x9d, 0x54, 0xd0,
                            0x66, 0x1c, 0x97, 0x69, 0x58, 0x13, 0xb7, 0xdc, 0x24, 0x29, 0x09, 0x94,
                            0xc7, 0xc7, 0xf9, 0x92, 0x39, 0x6e, 0x79, 0x24,
                        ];
                        let trussed_ref = Rc::clone(&self.trussed_platform);
                        Rc::new(Ed25519Key::load(
                            &mut *self.trussed_platform.borrow_mut(),
                            KEY,
                            Location::Volatile,
                            move |id| {
                                debug!("Dropping key id {:?}", id);
                                let mut trussed = trussed_ref
                                    .try_borrow_mut()
                                    .expect("Failed to borrow Trussed client while freeing key");
                                let trussed = &mut *trussed;
                                trussed::syscall!(trussed::client::CryptoClient::delete(
                                    trussed,
                                    id.clone()
                                ));
                            },
                        ))
                    },
                };
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
            State::Init { .. } | State::RequestMetadata { .. } => {
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
        key: &Ed25519Key,
    ) -> Result<(metadata::Metadata, trussed::Bytes<128>), ()>
    where
        T: trussed::client::Ed255 + trussed::client::Sha256,
    {
        let metadata_with_sig = trussed::cbor_deserialize::<metadata::MetadataWithSignature>(
            metadata,
        )
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

        match trussed::try_syscall!(trussed.verify_ed255(
            key.key_id().clone(),
            metadata_with_sig.encoded_metadata,
            metadata_with_sig.signature,
        )) {
            Ok(v) if v.valid => {
                let sha =
                    trussed::try_syscall!(trussed.hash_sha256(metadata_with_sig.encoded_metadata))
                        .map_err(|e| {
                            error!("Failed to compute SHA-256: {:?}", e);
                        })?;

                let meta = trussed::cbor_deserialize::<metadata::Metadata>(
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

    /// Verify correctness of the metadata itself.
    fn do_verify_metadata(metadata: &metadata::Metadata) -> bool {
        if metadata.version != metadata::CURRENT_VERSION {
            error!(
                "Unsupported metadata version {}, expected version {}",
                metadata.version,
                metadata::CURRENT_VERSION
            );
            return false;
        }

        let expected_hash_len = match metadata.ek_hash.id {
            metadata::HashType::SHA1 => 20,
            metadata::HashType::SHA256 => 32,
            metadata::HashType::SHA512 => 64,
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
}
