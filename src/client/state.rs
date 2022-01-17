use alloc::vec::Vec;

pub enum State {
    /// Repeat hello request until server responds
    Init { request_pending: bool },

    /// State after receiving init data
    InitDataReceived { data: Vec<u8> },

    /// Idle state
    Idle,
}

impl Default for State {
    fn default() -> Self {
        Self::Init {
            request_pending: false,
        }
    }
}
