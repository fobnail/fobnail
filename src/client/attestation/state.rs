use alloc::{rc::Rc, vec::Vec};
use core::fmt;

use super::{crypto::Key, signing::Nonce, Policy};
use pal::timer::get_time_ms;

pub enum State {
    /// We need metadata to determine which AIK we should load.
    RequestMetadata { request_pending: bool },

    /// Parse and load AIK key.
    LoadAik { metadata: Vec<u8> },

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
}

impl State {
    /// Transition into error state.
    pub fn error(&mut self) {
        *self = Self::Idle {
            timeout: Some(get_time_ms() as u64 + 5000),
        }
    }
}

impl Default for State {
    fn default() -> Self {
        Self::RequestMetadata {
            request_pending: false,
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestMetadata { .. } => write!(f, "request metadata"),
            Self::LoadAik { .. } => write!(f, "load AIK"),
            Self::RequestEvidence { .. } => write!(f, "request evidence"),
            Self::VerifyEvidence { .. } => write!(f, "verify evidence"),
            Self::Idle { .. } => write!(f, "idle"),
        }
    }
}
