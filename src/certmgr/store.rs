use core::fmt;

use alloc::vec::Vec;
use serde::Serialize;
use trussed::types::{Location, Message, PathBuf};

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
            if subject_key_id.as_bytes() != id {
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
            .find(|x| x.subject_key_id().map_or(false, |x| x.as_bytes() == id))
            .or_else(|| {
                self.volatile_certificates
                    .iter()
                    .find(|x| x.subject_key_id().map_or(false, |x| x.as_bytes() == id))
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

    /// Saves certificate chain into a single file named
    pub fn save_certchain<T>(
        &self,
        trussed: &mut T,
        cert: &[&X509Certificate],
        filename: &str,
    ) -> Result<(), ()>
    where
        T: trussed::client::FilesystemClient,
    {
        // Maybe a bit overkill but in case there is wrong usage or if in future
        // this method will be called with untrusted arguments this will be
        // detected.
        if !sanitize_path_component(filename) {
            error!("Certchain file name contains banned characters");
            return Err(());
        }

        #[derive(Serialize)]
        pub struct Chain<'a> {
            certs: &'a [&'a serde_bytes::Bytes],
        }
        let certs: Vec<_> = cert
            .iter()
            .map(|x| serde_bytes::Bytes::new(x.certificate_raw()))
            .collect();
        let chain = Chain { certs: &certs };

        let mut total_cert_len = 0;
        cert.iter()
            .for_each(|x| total_cert_len += x.certificate_raw().len());

        let mut buf = Vec::new();
        buf.resize(total_cert_len + 8 + 4 * certs.len(), 0);

        let buf = trussed::cbor_serialize(&chain, &mut buf).unwrap();

        let path_str = format!("/cert/{}", filename);
        let path = PathBuf::from(path_str.as_bytes());
        trussed::try_syscall!(trussed.write_file(
            Location::Internal,
            path,
            Message::from_slice(buf)
                .map_err(|_| error!("Chain is too big to save it in persistent storage"))?,
            None,
        ))
        .map_err(|_| error!("Failed to save cert chain to {}", path_str))?;

        debug!("Wrote {}", path_str);

        Ok(())
    }
}

/// Checks for presence of forbidden characters (or sequences of characters).
/// This exists to prevent path traversal attacks.
///
/// Return value
/// [`true`] if path is safe.
/// [`false`] if found banned characters.
fn sanitize_path_component(component: &str) -> bool {
    // TODO: should check whether these characters/sequences are valid from
    // X.509 perspective, and consider name mangling.

    let mut prev = 'a';
    for c in component.chars() {
        if c == '/' || (c == '.' && prev == '.') {
            return false;
        }
        prev = c;
    }

    true
}
