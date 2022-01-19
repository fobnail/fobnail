use alloc::vec::Vec;
use core::fmt;

pub enum State {
    /// Repeat hello request until server responds.
    Init { request_pending: bool },

    /// State after receiving init data.
    InitDataReceived { data: Vec<u8> },

    /// Send metadata request and wait for response.
    RequestMetadata { request_pending: bool },

    /// Verify whether metadata has been properly with the Attestation Identity
    /// Key.
    VerifyMetadata { metadata: Vec<u8> },

    /// Idle state with optional timeout. After timeout resets into Init state.
    Idle { timeout: Option<u64> },
}

impl Default for State {
    fn default() -> Self {
        Self::Init {
            request_pending: false,
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Init { .. } => write!(f, "init"),
            Self::InitDataReceived { .. } => write!(f, "init data received"),
            Self::RequestMetadata { .. } => write!(f, "request metadata"),
            Self::VerifyMetadata { .. } => write!(f, "verify metadata"),
            Self::Idle { .. } => write!(f, "idle"),
        }
    }
}
