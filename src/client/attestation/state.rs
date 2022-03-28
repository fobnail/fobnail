use alloc::vec::Vec;
use core::fmt;

use pal::timer::get_time_ms;

pub enum State {
    /// We need metadata to determine which AIK we should load.
    RequestMetadata { request_pending: bool },

    /// Parse and load AIK key.
    LoadAik { metadata: Vec<u8> },

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
            Self::Idle { .. } => write!(f, "idle"),
        }
    }
}
