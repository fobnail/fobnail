use alloc::vec::Vec;
use serde::Serialize;
use trussed::{
    api::reply::{ReadDirFirst, ReadDirNext, ReadFile},
    types::{Location, Message, PathBuf},
};

use super::{CertMgr, X509Certificate};

impl CertMgr {
    /// Attempts to load DER-encoded X.509 certificate from file.
    pub(super) fn load_certificate_from_file<'r: 't, 't, T>(
        &self,
        fs: &'t mut T,
        path: PathBuf,
    ) -> Option<X509Certificate<'r>>
    where
        T: trussed::client::FilesystemClient,
    {
        let path_copy = path.clone();
        info!("loading {}", path);
        match trussed::try_syscall!(fs.read_file(Location::Internal, path)) {
            Ok(ReadFile { data }) => {
                let data = data.as_slice();
                match X509Certificate::parse_owned(data.to_vec()) {
                    Ok(cert) => Some(cert),
                    Err(e) => {
                        error!("Certificate stored in DB is corrupted");
                        error!("{}", e);
                        None
                    }
                }
            }
            Err(e) => {
                error!("Failed to read {}: {:?}", path_copy, e);
                None
            }
        }
    }

    /// Iterate over all non-volatile certificates.
    pub fn iter_certificates<'r>(&'r self) -> CertificateIterator<'r> {
        CertificateIterator {
            done: false,
            first: true,
            certmgr: self,
        }
    }

    /// Find certificate by its Subject ID
    pub fn lookup_certificate(&self, id: &[u8]) -> Option<X509Certificate<'static>> {
        // Start with volatile certificates
        self.volatile_certificates
            .iter()
            .find(|x| x.subject_key_id().map_or(false, |x| x.as_bytes() == id))
            .cloned()
            .or_else(|| {
                super::EMBEDDED_CERTIFICATES
                    .iter()
                    .map(|x| {
                        let mut cert = self.load_cert(x).unwrap();
                        // Each embedded certificate is trusted.
                        cert.is_trusted = true;
                        cert
                    })
                    .find(|x| x.subject_key_id().map_or(false, |x| x.as_bytes() == id))
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
            .into_iter()
            .map(|x| serde_bytes::Bytes::new(x.certificate_raw()))
            .collect();
        let chain = Chain { certs: &certs };

        let mut total_cert_len = 0;
        cert.into_iter()
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

pub struct CertificateIterator<'a> {
    done: bool,
    first: bool,
    certmgr: &'a CertMgr,
}

impl<'a> CertificateIterator<'a> {
    fn next_internal<T>(&mut self, fs: &mut T) -> Option<X509Certificate<'static>>
    where
        T: trussed::client::FilesystemClient,
    {
        loop {
            if self.first {
                self.first = false;
                // Read first directory entry
                let path_str = format!("/cert/");
                let path = PathBuf::from(path_str.as_bytes());

                let ReadDirFirst { entry } =
                    trussed::try_syscall!(fs.read_dir_first(Location::Internal, path, None))
                        .ok()?;
                if let Some(entry) = entry {
                    let path = PathBuf::from(entry.path());
                    if let Some(cert) = self.certmgr.load_certificate_from_file(fs, path) {
                        return Some(cert);
                    }
                } else {
                    // Directory is empty
                    return None;
                }
            } else {
                // Read next entry
                let ReadDirNext { entry } = trussed::try_syscall!(fs.read_dir_next()).ok()?;
                if let Some(entry) = entry {
                    let path = PathBuf::from(entry.path());
                    if let Some(cert) = self.certmgr.load_certificate_from_file(fs, path) {
                        return Some(cert);
                    }
                } else {
                    return None;
                }
            }
        }
    }

    pub fn next<T>(&mut self, fs: &mut T) -> Option<X509Certificate<'static>>
    where
        T: trussed::client::FilesystemClient,
    {
        if self.done {
            return None;
        }
        let n = Self::next_internal(self, fs);
        if n.is_none() {
            self.done = true;
        }
        n
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
