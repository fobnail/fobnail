use alloc::rc::Rc;
use alloc::vec::Vec;
use core::fmt;

use super::crypto::Ed25519Key;
use super::metadata::Metadata;

pub enum State<'a> {
    /// Repeat hello request until server responds.
    Init { request_pending: bool },

    /// State after receiving init data.
    InitDataReceived { data: Vec<u8> },

    // TODO: before requesting metadata we must request AIK (Attestation
    // Identity Key) key, receive it and verify.
    // This adds two new states: RequestAik and VerifyAik inserted between
    // InitDataReceived and RequestMetadata
    /// Send metadata request and wait for response.
    RequestMetadata {
        aik_pubkey: Rc<Ed25519Key<'a>>,
        request_pending: bool,
    },

    /// Verify whether metadata has been properly with the Attestation Identity
    /// Key.
    VerifyMetadata {
        aik_pubkey: Rc<Ed25519Key<'a>>,
        metadata: Vec<u8>,
    },

    // TODO: implement this, must store metadata in persistent storage.
    StoreMetadata {
        metadata: Metadata,
        /// Hash of metadata
        hash: trussed::Bytes<128>,
    },

    /// Idle state with optional timeout. After timeout resets into Init state.
    Idle { timeout: Option<u64> },
}

impl Default for State<'_> {
    fn default() -> Self {
        Self::Init {
            request_pending: false,
        }
    }
}

impl fmt::Display for State<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Init { .. } => write!(f, "init"),
            Self::InitDataReceived { .. } => write!(f, "init data received"),
            Self::RequestMetadata { .. } => write!(f, "request metadata"),
            Self::VerifyMetadata { .. } => write!(f, "verify metadata"),
            Self::StoreMetadata { .. } => write!(f, "store metadata"),
            Self::Idle { .. } => write!(f, "idle"),
        }
    }
}
