pub type Result<T> = ::core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    /// Failed to process response.
    ProtocolError,

    /// Timeout while waiting for response.
    Timeout,
}
