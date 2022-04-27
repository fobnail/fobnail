use core::fmt;

use alloc::vec::Vec;

pub enum State {
    /// Request platform owner certificate chain.
    RequestPoCertChain {
        request_pending: bool,
    },

    /// Idle state with optional timeout. After timeout resets into Init state.
    Idle {
        timeout: Option<u64>,
    },

    /// Signal either success or error by blinking with LED.
    SignalStatus {
        success: bool,
    },

    VerifyPoCertChain {
        chain: Vec<u8>,
    },

    /// Provisioning is complete. Main loop is responsible for switching mode
    /// into platform provisioning mode.
    Done,
}

impl Default for State {
    fn default() -> Self {
        Self::RequestPoCertChain {
            request_pending: false,
        }
    }
}

impl State {
    /// Signal status and transition into error state.
    pub fn error(&mut self) {
        *self = Self::SignalStatus { success: false };
    }

    /// Signal status and transition into done state.
    pub fn done(&mut self) {
        *self = Self::SignalStatus { success: true };
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestPoCertChain { .. } => write!(f, "request po cert chain"),
            Self::SignalStatus { .. } => write!(f, "signal status"),
            Self::VerifyPoCertChain { .. } => write!(f, "verify po cert chain"),
            Self::Done => write!(f, "done"),
            Self::Idle { .. } => write!(f, "idle"),
        }
    }
}
