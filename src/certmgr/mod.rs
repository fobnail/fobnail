pub use self::error::*;
pub use self::key::*;
pub use self::signature::*;
pub use self::x509::*;

mod error;
mod key;
mod signature;
mod store;
mod verify;
mod x509;

pub struct CertMgr;

impl CertMgr {
    /// Parses DER-encoded certificate without copying data. The main advantage
    /// of this method over `load_cert_owned` is that it does not copy nor
    /// dynamically allocate data. However it borrows data for lifetime of
    /// X509Certificate object, this affects state machine in
    /// src/client/state.rs and we cannot move certificate between states
    /// without unsafe code (at least I am not aware of any way to do that).
    #[allow(dead_code)]
    pub fn load_cert<'r>(&self, data: &'r [u8]) -> Result<X509Certificate<'r>> {
        X509Certificate::parse(data)
    }

    pub fn load_cert_owned(&self, data: &[u8]) -> Result<X509Certificate<'static>> {
        X509Certificate::parse_owned(data.to_vec())
    }
}
