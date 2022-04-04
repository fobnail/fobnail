use alloc::{rc::Rc, vec::Vec};
use core::fmt;

use super::{crypto::Key, signing::Nonce, Policy};

pub enum State {
    /// Generate nonce and transition to RequestMetadata. We need this state
    /// because we can't access Trussed from State::default()
    Init,

    /// We need metadata to determine which AIK we should load.
    RequestMetadata { request_pending: bool, nonce: Nonce },

    /// Parse and load AIK key.
    LoadAik { metadata: Vec<u8>, nonce: Nonce },

    RequestEvidence {
        aik_pubkey: Rc<Key<'static>>,
        /// RIM from Fobnail's internal storage. Evidence will be verified
        /// against this.
        rim: Vec<u8>,
        request_pending: bool,
        nonce: Nonce,
        policy: Policy,
    },

    VerifyEvidence {
        aik_pubkey: Rc<Key<'static>>,
        rim: Vec<u8>,
        evidence: Vec<u8>,
        nonce: Nonce,
        policy: Policy,
    },

    /// Idle state with optional timeout. After timeout resets into Init state.
    Idle { timeout: Option<u64> },

    /// Triggered when attestation is completed, either successfully or with
    /// failure. This state is responsible for signalling attestation result
    /// using LED.
    Completion {
        attestation_success: bool,
        timeout: u64,
    },
}

impl State {
    /// Transition into error state.
    pub fn error(&mut self) {
        *self = Self::Completion {
            attestation_success: false,
            timeout: 0,
        }
    }
}

impl Default for State {
    fn default() -> Self {
        Self::Init
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Init { .. } => write!(f, "init"),
            Self::RequestMetadata { .. } => write!(f, "request metadata"),
            Self::LoadAik { .. } => write!(f, "load AIK"),
            Self::RequestEvidence { .. } => write!(f, "request evidence"),
            Self::VerifyEvidence { .. } => write!(f, "verify evidence"),
            Self::Idle { .. } => write!(f, "idle"),
            Self::Completion { .. } => write!(f, "completion"),
        }
    }
}
