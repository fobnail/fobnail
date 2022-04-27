use alloc::vec::Vec;

pub use self::error::*;
pub use self::key::*;
pub use self::signature::*;
pub use self::verify::*;
pub use self::x509::*;

mod error;
mod key;
mod signature;
mod store;
mod verify;
mod x509;

include!(concat!(env!("OUT_DIR"), "/root_ca.rs"));

/// Contains list of certificates that are embedded into firmware. These
/// certificates are immutable and cannot be replaced/removed except by
/// updating firmware.
static EMBEDDED_CERTIFICATES: &'static [&'static [u8]] = &[PO_CHAIN_ROOT];

pub struct CertMgr {
    /// Volatile certificates are temporary in-RAM certificates. They are
    /// removed when `CertMgr` gets dropped or after calling
    /// `clear_volatile_certs`.
    volatile_certificates: Vec<X509Certificate<'static>>,
}

impl CertMgr {
    pub fn new() -> Self {
        Self {
            volatile_certificates: vec![],
        }
    }

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

    /// Loads volatile certificate. Volatile certificates are gone after
    /// dropping `CertMgr` or calling `clear_volatile_certs`.
    pub fn inject_volatile_cert(&mut self, cert: X509Certificate<'static>) {
        self.volatile_certificates.push(cert);
    }

    /// Removes all volatile certificates.
    pub fn clear_volatile_certs(&mut self) {
        self.volatile_certificates.clear();
    }

    /// Obtain reference to a raw (non-decoded DER) Platform Owner certificate.
    pub fn po_root_raw() -> &'static [u8] {
        // PO root must always be the first certificate
        EMBEDDED_CERTIFICATES[0]
    }
}
