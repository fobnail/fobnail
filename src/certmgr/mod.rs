pub use self::error::*;
pub use self::x509::*;

mod error;
mod x509;

pub struct CertMgr;

impl CertMgr {
    pub fn load_cert<'r>(&self, data: &'r [u8]) -> Result<X509Certificate<'r>> {
        X509Certificate::parse(data)
    }
}
