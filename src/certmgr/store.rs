use core::fmt;

use trussed::types::{Location, PathBuf};

use super::{CertMgr, X509Certificate};

impl CertMgr {
    /// Attempts to load DER-encoded X.509 certificate from file.
    pub(super) fn load_certificate_from_file<'r: 't, 't, T>(
        &self,
        trussed: &'t mut T,
        id: &[u8],
    ) -> Option<X509Certificate<'r>>
    where
        T: trussed::client::FilesystemClient,
    {
        struct H<'a>(&'a [u8]);
        impl fmt::Display for H<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for b in self.0 {
                    write!(f, "{:02x}", *b)?;
                }
                Ok(())
            }
        }

        let path = format!("/cert/I_{}", H(id));
        let file = trussed::try_syscall!(
            trussed.read_file(Location::Internal, PathBuf::from(path.as_bytes()))
        )
        .ok()?;

        let cert = X509Certificate::parse_owned(file.data.to_vec())
            .map_err(|e| error!("{} is corrupted: {}", path, e))
            .ok()?;

        if let Some(subject_key_id) = cert.subject_key_id() {
            if subject_key_id.0.as_bytes() != id {
                error!("subject key id mismatch in {}", path);
                return None;
            }

            Some(cert)
        } else {
            error!("No subject key id in {}", path);
            None
        }
    }

    /// Find certificate by its Subject ID
    pub fn lookup_certificate<T>(
        &self,
        trussed: Option<&mut T>,
        id: &[u8],
    ) -> Option<X509Certificate<'static>>
    where
        T: trussed::client::FilesystemClient,
    {
        super::EMBEDDED_CERTIFICATES
            .iter()
            .map(|x| {
                let mut cert = self.load_cert(x).unwrap();
                // Each embedded certificate is trusted.
                cert.is_trusted = true;
                cert
            })
            .find(|x| x.subject_key_id().map_or(false, |x| x.0.as_bytes() == id))
            .or_else(|| {
                self.volatile_certificates
                    .iter()
                    .find(|x| x.subject_key_id().map_or(false, |x| x.0.as_bytes() == id))
                    .cloned()
                    .or_else(|| {
                        if let Some(trussed) = trussed {
                            self.load_certificate_from_file(trussed, id)
                        } else {
                            None
                        }
                    })
            })
    }
}
