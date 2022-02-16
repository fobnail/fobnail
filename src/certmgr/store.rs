use trussed::{
    api::reply::{ReadDirFirst, ReadDirNext, ReadFile},
    types::{Location, PathBuf},
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
                    Ok(mut cert) => {
                        // TODO: should fetch trusted flag filesystem
                        // The original idea was to use LittleFS extended
                        // attributes to store this flag
                        // TODO: check once again whether Trussed supports
                        // this (maybe there are some obscure APIs to do
                        // that).
                        cert.is_trusted = false;
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
    pub fn iter_certificates<'r, T>(
        &'r self,
        organization: &'r str,
        fs: &'r mut T,
    ) -> CertificateIterator<'r, T> {
        let valid_path = sanitize_path_component(organization);
        if !valid_path {
            warn!(
                "Found forbidden characters in organization name ({})",
                organization
            );
        }

        CertificateIterator {
            organization,
            fs,
            done: !valid_path,
            first: true,
            certmgr: self,
        }
    }
}

pub struct CertificateIterator<'a, T> {
    organization: &'a str,
    fs: &'a mut T,
    done: bool,
    first: bool,
    certmgr: &'a CertMgr,
}

impl<'a, T> CertificateIterator<'a, T>
where
    T: trussed::client::FilesystemClient,
{
    fn next(&mut self) -> Option<X509Certificate<'static>> {
        loop {
            if self.first {
                self.first = false;
                // Read first directory entry
                let path_str = format!("/cert/{}/", self.organization);
                let path = PathBuf::from(path_str.as_bytes());

                let ReadDirFirst { entry } =
                    trussed::try_syscall!(self.fs.read_dir_first(Location::Internal, path, None))
                        .ok()?;
                if let Some(entry) = entry {
                    let path = PathBuf::from(entry.path());
                    if let Some(cert) = self.certmgr.load_certificate_from_file(self.fs, path) {
                        return Some(cert);
                    }
                } else {
                    // Directory is empty
                    return None;
                }
            } else {
                // Read next entry
                let ReadDirNext { entry } = trussed::try_syscall!(self.fs.read_dir_next()).ok()?;
                if let Some(entry) = entry {
                    let path = PathBuf::from(entry.path());
                    if let Some(cert) = self.certmgr.load_certificate_from_file(self.fs, path) {
                        return Some(cert);
                    }
                } else {
                    return None;
                }
            }
        }
    }
}

impl<'a, T> Iterator for CertificateIterator<'a, T>
where
    T: trussed::client::FilesystemClient,
{
    type Item = X509Certificate<'static>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let n = Self::next(self);
        if n.is_none() {
            self.done = true;
        }
        n
    }
}

/// Checks for presense of forbidden characters (or sequences of characters).
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
