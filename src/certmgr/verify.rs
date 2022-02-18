use super::{CertMgr, Error, Result, X509Certificate};

enum Match<'a> {
    /// Exact match using Authority Key Identifier
    Exact(&'a [u8]),
    /// Non exact match (by issuer). Need to iterate over all certificates from
    /// that issuer to find signing certificate.
    NonExact(&'a str),
}

enum MaybeOwned<'a, T> {
    Borrowed(&'a T),
    Owned(T),
}

impl<T> MaybeOwned<'_, T> {
    pub fn get(&self) -> &T {
        match self {
            Self::Borrowed(inner) => inner,
            Self::Owned(inner) => &inner,
        }
    }
}

impl<'a, T> From<&'a T> for MaybeOwned<'a, T> {
    fn from(inner: &'a T) -> Self {
        Self::Borrowed(inner)
    }
}

impl<'a, T> From<T> for MaybeOwned<'a, T> {
    fn from(inner: T) -> Self {
        Self::Owned(inner)
    }
}

impl CertMgr {
    pub fn verify<T>(&self, trussed: &mut T, certificate: &X509Certificate) -> Result<()>
    where
        T: trussed::client::FilesystemClient,
    {
        const RECURSION_LIMIT: usize = 50;

        let mut recursion_level = 0;

        let mut current_child: MaybeOwned<X509Certificate> = MaybeOwned::from(certificate);
        loop {
            if current_child.get().is_trusted() {
                // We went up till root and found a trusted certificate. This
                // terminates verification process.
                return Ok(());
            }

            if recursion_level > RECURSION_LIMIT {
                return Err(Error::ExceededRecursionLimit);
            }

            match Self::get_parent_id(certificate)? {
                Match::Exact(_) => todo!(),
                Match::NonExact(organization) => {
                    let mut found_parent = None;
                    for parent in self.iter_certificates(organization, trussed) {
                        match self.verify_internal(&parent, current_child.get()) {
                            Ok(true) => {
                                found_parent = Some(MaybeOwned::from(parent));
                                break;
                            }
                            Ok(false) => {
                                // Subject is not signed by this certificate,
                                // but may be signed by another one so keep
                                // going.
                            }
                            Err(e) => {
                                error!("{}", e)
                            }
                        }
                    }
                    if let Some(parent) = found_parent {
                        current_child = parent;
                    } else {
                        return Err(Error::IssuerNotFound);
                    }
                }
            }

            recursion_level += 1;
        }
    }

    /// Verify parent-child relationship of supplied certificates.
    fn verify_internal(&self, parent: &X509Certificate, child: &X509Certificate) -> Result<bool> {
        // TODO: verify whether child issuer matches with parent subject.

        let parent_key = parent.key()?;

        let signature = child.signature()?;
        info!("Signature: {}", signature);

        if !signature.is_compatible(&parent_key) {
            debug!(
                "{} signature not compatible with {} key",
                signature, parent_key
            );
            return Ok(false);
        }

        Ok(true)
    }

    /// Gives hint about where to look for signing certificate.
    fn get_parent_id<'r>(certificate: &'r X509Certificate) -> Result<Match<'r>> {
        let issuer = certificate.issuer()?;
        // TODO: implement X509v3 Authority Key Id
        Ok(Match::NonExact(issuer.organization))
    }
}
