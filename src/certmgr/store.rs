use trussed::{
    api::reply::{ReadAttribute, ReadDirFirst, ReadDirNext, ReadFile},
    types::{Location, PathBuf},
};

use super::{CertMgr, X509Certificate};

/// Attribute for storing certificate flags. Currently only trusted flag is
/// implemented (CERTIFICATE_FLAG_TRUSTED), all other bits are reserved for
/// future use.
const ATTRIBUTE_CERTIFICATE_FLAGS: u8 = 0;
/// Controls whether certificate stored in DB is trusted. Should be set for root
/// CAs.
const CERTIFICATE_FLAG_TRUSTED: u8 = 1;

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
                    Ok(mut cert) => {
                        match trussed::try_syscall!(fs.read_attribute(
                            Location::Internal,
                            path_copy,
                            ATTRIBUTE_CERTIFICATE_FLAGS,
                        )) {
                            Ok(ReadAttribute { data }) => match data {
                                Some(attr) => {
                                    if let Some(&flags) = attr.first() {
                                        if flags & CERTIFICATE_FLAG_TRUSTED != 0 {
                                            cert.is_trusted = true;
                                        }
                                    }
                                }
                                None => {
                                    // Assume defaults
                                }
                            },
                            Err(_) => {
                                warn!("Failed to read certificate flags");
                            }
                        }

                        Some(cert)
                    }
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

    /// Iterate over certificates issued by a specified organization.
    pub fn iter_certificates<'r>(&'r self, organization: &'r str) -> CertificateIterator<'r> {
        let valid_path = sanitize_path_component(organization);
        if !valid_path {
            warn!(
                "Found forbidden characters in organization name ({})",
                organization
            );
        }

        CertificateIterator {
            organization,
            done: !valid_path,
            first: true,
            certmgr: self,
        }
    }
}

pub struct CertificateIterator<'a> {
    organization: &'a str,
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
                let path_str = format!("/cert/{}/", self.organization);
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
