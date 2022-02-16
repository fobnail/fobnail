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
    pub fn load_cert<'r>(&self, data: &'r [u8]) -> Result<X509Certificate<'r>> {
        X509Certificate::parse(data)
    }
}
