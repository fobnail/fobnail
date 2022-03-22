use alloc::{rc::Rc, vec::Vec};
use core::fmt;

use super::crypto::Key;
use crate::certmgr::X509Certificate;
use pal::timer::get_time_ms;

pub enum State<'a> {
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
        secret: Vec<u8>,
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

    /// Verify whether metadata has been properly signed with the Attestation
    /// Identity Key. Check if attester is provisioned and load its RIMs.
    VerifyMetadata {
        aik_pubkey: Rc<Key<'a>>,
        metadata: Vec<u8>,
    },

    /// Idle state with optional timeout. After timeout resets into Init state.
    Idle { timeout: Option<u64> },
}

impl State<'_> {
    /// Transition into error state.
    pub fn error(&mut self) {
        *self = Self::Idle {
            timeout: Some(get_time_ms() as u64 + 5000),
        }
    }
}

impl Default for State<'_> {
    fn default() -> Self {
        Self::RequestEkCert {
            request_pending: false,
        }
    }
}

impl fmt::Display for State<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestEkCert { .. } => write!(f, "request EK certificate"),
            Self::VerifyEkCertificate { .. } => write!(f, "verify EK certificate"),
            Self::RequestAik { .. } => write!(f, "request AIK"),
            Self::VerifyAikStage1 { .. } => write!(f, "verify AIK (stage 1)"),
            Self::VerifyAikStage2 { .. } => write!(f, "verify AIK (stage 2)"),
            Self::LoadAik { .. } => write!(f, "load AIK"),
            Self::RequestMetadata { .. } => write!(f, "request metadata"),
            Self::VerifyMetadata { .. } => write!(f, "verify metadata"),
            Self::Idle { .. } => write!(f, "idle"),
        }
    }
}
