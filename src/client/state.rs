pub enum State {
    /// Repeat hello request until server responds
    Init { request_pending: bool },
}

impl Default for State {
    fn default() -> Self {
        Self::Init {
            request_pending: false,
        }
    }
}
