use core::fmt;

pub enum State {
    /// Request platform owner certificate chain.
    RequestPoCertChain {
        request_pending: bool,
    },

    Error,
}

impl Default for State {
    fn default() -> Self {
        Self::RequestPoCertChain {
            request_pending: false,
        }
    }
}

impl State {
    /// Transition into error state.
    pub fn error(&mut self) {
        *self = Self::Error;
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestPoCertChain { .. } => write!(f, "request po cert chain"),
            Self::Error => write!(f, "error"),
        }
    }
}
