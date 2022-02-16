use alloc::vec::Vec;

use super::{CertMgr, Error, Result, X509Certificate};
use crate::certmgr::HashAlgorithm;
use rsa::PublicKey as _;

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
        T: trussed::client::FilesystemClient + trussed::client::Sha256,
    {
        const RECURSION_LIMIT: usize = 50;

        let mut recursion_level = 0;

        let mut current_child: MaybeOwned<X509Certificate> = MaybeOwned::from(certificate);
        loop {
            let is_selfsigned = self.verify_internal(trussed, None, current_child.get())?;

            if current_child.get().is_trusted() {
                // We went up till root and found a trusted certificate. This
                // terminates verification process.
                if !is_selfsigned {
                    // Certificate is marked as trusted, but it's not root,
                    // every root certificate must be self-signed (ie. cannot
                    // have parent).
                    //
                    // TODO: should we allow this?
                    warn!("non-root certificate marked as trusted");
                }

                return Ok(());
            } else {
                // Self-signed certificate terminates certificate chain.
                if is_selfsigned {
                    return Err(Error::UntrustedSelfSignedCert);
                }
            }

            if recursion_level > RECURSION_LIMIT {
                return Err(Error::ExceededRecursionLimit);
            }

            match Self::get_parent_id(certificate)? {
                Match::Exact(_) => todo!(),
                Match::NonExact(organization) => {
                    let mut found_parent = None;

                    // FIXME:
                    // We cannot call self.verify_internal() while iterating because
                    // both iter_certificate() and verify_internal() need exclusive
                    // access to trussed.
                    //
                    // For now we load certificates into memory before checking them.
                    // While this works when there is a small number of certificates
                    // it will fill memory when there are more.
                    let potential_parents: Vec<X509Certificate> =
                        self.iter_certificates(organization, trussed).collect();

                    for parent in potential_parents {
                        match self.verify_internal(trussed, Some(&parent), current_child.get()) {
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

    /// Verify parent-child relationship of supplied certificates. If parent is
    /// None then verify whether certificate is self-signed.
    fn verify_internal<T>(
        &self,
        trussed: &mut T,
        parent: Option<&X509Certificate>,
        child: &X509Certificate,
    ) -> Result<bool>
    where
        T: trussed::client::Sha256,
    {
        // TODO: verify whether child issuer matches with parent subject.

        // TODO: verify whether parent can be used for signing (using X.509v3
        // constraints)

        let parent_key = if let Some(parent) = parent {
            parent.key()?
        } else {
            // Optimization: in case of self-signed certificate Authority Key ID
            // and Subject Key ID must be the same.
            if let Some(auth_key_id) = child.authority_key_id() {
                if let Some(subj_key_id) = child.subject_key_id() {
                    if auth_key_id != subj_key_id {
                        return Ok(false);
                    }
                }
            }

            child.key()?
        };
        let signature = child.signature()?;

        if !signature.is_compatible(&parent_key) {
            debug!(
                "{} signature not compatible with {} key",
                signature, parent_key
            );
            return Ok(false);
        }

        match parent_key {
            crate::certmgr::Key::Rsa { n, e } => {
                let key = rsa::RsaPublicKey::new(
                    rsa::BigUint::from_bytes_be(n),
                    rsa::BigUint::from_slice(&[e]),
                )
                .unwrap();

                let tbs_raw = child.tbs_certificate_raw()?;

                match signature.hash_algo {
                    HashAlgorithm::Sha256 => {
                        let trussed::api::reply::Hash { hash } =
                            trussed::syscall!(trussed.hash_sha256(tbs_raw));

                        match key.verify(
                            rsa::PaddingScheme::PKCS1v15Sign {
                                hash: Some(rsa::Hash::SHA2_256),
                            },
                            hash.as_slice(),
                            signature.as_bytes(),
                        ) {
                            Ok(()) => Ok(true),
                            Err(_) => Ok(false),
                        }
                    }
                    _ => return Err(Error::CustomStatic("Unsupported hash algorithm")),
                }
            }
        }
    }

    /// Gives hint about where to look for signing certificate.
    fn get_parent_id<'r>(certificate: &'r X509Certificate) -> Result<Match<'r>> {
        let issuer = certificate.issuer()?;

        if let Some(key_id) = certificate.authority_key_id() {
            Ok(Match::Exact(key_id))
        } else {
            Ok(Match::NonExact(issuer.organization))
        }
    }
}
