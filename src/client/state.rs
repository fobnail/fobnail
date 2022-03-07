use alloc::rc::Rc;
use alloc::vec::Vec;
use core::fmt;

use crate::certmgr::X509Certificate;

use super::crypto::Key;
use super::proto::Metadata;

pub enum State<'a> {
    /// Repeat hello request until server responds.
    Init { request_pending: bool },

    /// State after receiving init data.
    InitDataReceived { data: Vec<u8> },

    /// Send request to obtain EK certificate
    RequestEkCert { request_pending: bool },

    /// Verify EK certificate chain
    VerifyEkCertificate { data: Vec<u8> },

    RequestAik {
        // FIXME:
        // This field is wrapped in option to allow moving inner value into next
        // state. This is a hack we are using because Rust won't allow us to
        // move object. Should work on improving state machine patterns so that
        // we can update state atomically or get replace state machine with some
        // other approach.
        ek_cert: Option<X509Certificate<'static>>,
        request_pending: bool,
    },

    /// Do basic parsing and verification of received AIK. Prepare challenge
    /// that attester has to pass (credential activation) to confirm that AIK
    /// comes from TPM (AIK is bound to EK).
    VerifyAikStage1 {
        ek_cert: X509Certificate<'static>,
        data: Vec<u8>,
    },

    /// Send AIK challenge. Attester decrypts secret which is part of challenge
    /// and returns secret as plaintext. If decrypted secret matches with secret
    /// stored in memory then verification succeeds.
    VerifyAikStage2 {
        request_pending: bool,
        secret: trussed::types::Bytes<{ trussed::config::MAX_MESSAGE_LENGTH }>,
        id_object: Vec<u8>,
        encrypted_secret: Vec<u8>,
        aik: Vec<u8>,
    },

    /// Parse and load AIK key.
    LoadAik { raw_aik: Vec<u8> },

    /// Send metadata request and wait for response.
    RequestMetadata {
        aik_pubkey: Rc<Key<'a>>,
        request_pending: bool,
    },

    /// Verify whether metadata has been properly with the Attestation Identity
    /// Key.
    VerifyMetadata {
        aik_pubkey: Rc<Key<'a>>,
        metadata: Vec<u8>,
    },

    // TODO: implement this, must store metadata in persistent storage.
    StoreMetadata {
        metadata: Metadata,
        /// Hash of metadata
        hash: trussed::Bytes<128>,
        aik_pubkey: Rc<Key<'a>>,
    },

    /// Request Reference Integrity Manifests from attester.
    RequestRim {
        /// RIMs are bound to a specific device. We use metadata hashes to
        /// distinguish these devices.
        metadata_hash: trussed::Bytes<128>,
        aik_pubkey: Rc<Key<'a>>,
        request_pending: bool,
    },

    /// Verify Reference Integrity Manifest
    VerifyRim {
        rim: Vec<u8>,
        aik_pubkey: Rc<Key<'a>>,
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
            Self::RequestEkCert { .. } => write!(f, "request EK cert"),
            Self::VerifyEkCertificate { .. } => write!(f, "verify EK cert"),
            Self::RequestAik { .. } => write!(f, "request AIK"),
            Self::VerifyAikStage1 { .. } => write!(f, "verify AIK (stage 1)"),
            Self::VerifyAikStage2 { .. } => write!(f, "verify AIK (stage 2)"),
            Self::LoadAik { .. } => write!(f, "load AIK"),
            Self::RequestMetadata { .. } => write!(f, "request metadata"),
            Self::VerifyMetadata { .. } => write!(f, "verify metadata"),
            Self::StoreMetadata { .. } => write!(f, "store metadata"),
            Self::RequestRim { .. } => write!(f, "request RIM"),
            Self::VerifyRim { .. } => write!(f, "verify RIM"),
            Self::Idle { .. } => write!(f, "idle"),
        }
    }
}
