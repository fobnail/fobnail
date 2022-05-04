use der::Decodable;
use x509::{KeyUsage, KeyUsages, ObjectIdentifier};

use super::{CertMgr, Error, Result, X509Certificate};
use crate::certmgr::HashAlgorithm;
use rsa::PublicKey as _;

const X509V3_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new("2.5.29.19");
const X509V3_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new("2.5.29.15");
const X509V3_SUBJECT_ALTERNATIVE_NAME: ObjectIdentifier = ObjectIdentifier::new("2.5.29.17");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMode {
    /// Verify certificate that is neither EK nor PO, no special restrictions
    /// are applied in this mode, except that certificate is required to be
    /// X.509v3.
    Normal,
    /// Verify EK scertificate. This option enforces that TCG requirements
    /// for EK certificate are met.
    Ek,
    /// Verify certificate from Platform Owner's chain.
    Po,
}

enum MaybeOwned<'a, T> {
    Borrowed(&'a T),
    Owned(T),
}

impl<T> MaybeOwned<'_, T> {
    pub fn get(&self) -> &T {
        match self {
            Self::Borrowed(inner) => inner,
            Self::Owned(inner) => inner,
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
    /// Verifies certificate chain starting with leaf and ending on trusted root.
    pub fn verify<T>(
        &self,
        trussed: &mut T,
        certificate: &X509Certificate,
        mode: VerifyMode,
    ) -> Result<()>
    where
        T: trussed::client::FilesystemClient + trussed::client::Sha256,
    {
        const RECURSION_LIMIT: usize = 50;

        let mut recursion_level = 0;

        match mode {
            VerifyMode::Ek => {
                // Make sure EK certificate meets TCG requirements
                if !Self::tcg_compliance_check(certificate) {
                    return Err(Error::DoesNotMeetTcgRequirements);
                }
            }
            VerifyMode::Po => {
                // Make sure certificate in Platform Owner's chain meets
                // requirements.
                if !Self::po_requirements_check(certificate) {
                    return Err(Error::DoesNotMeetPoRequirements);
                }
            }
            VerifyMode::Normal => {
                if certificate.version() != 3 {
                    return Err(Error::NotX509v3);
                }
            }
        }

        let mut current_child: MaybeOwned<X509Certificate> = MaybeOwned::from(certificate);
        loop {
            if !Self::extensions_check(current_child.get()) {
                return Err(Error::UnsupportedCriticalExtension);
            }

            let is_selfsigned =
                self.verify_internal(trussed, None, current_child.get(), recursion_level)?;

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

                match mode {
                    VerifyMode::Po => {
                        // Last check, make sure that the root is Platform Owner's
                        // root and not some other root.
                        if current_child.get().certificate_raw() != Self::po_root_raw() {
                            return Err(Error::UnexpectedRoot {
                                expected_root: "PO",
                            });
                        }
                    }
                    VerifyMode::Ek | VerifyMode::Normal => {
                        // Only PO certificates may be signed by PO root.
                        if current_child.get().certificate_raw() == Self::po_root_raw() {
                            return Err(Error::UnexpectedRoot {
                                expected_root: "EK",
                            });
                        }
                    }
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

            let parent = self
                .lookup_certificate(Some(trussed), Self::get_parent_id(current_child.get())?)
                .ok_or(Error::IssuerNotFound)
                .and_then(|cert| {
                    if !Self::extensions_check(&cert) {
                        warn!("Ignoring certificate with unsupported critical extensions");
                        Err(Error::IssuerNotFound)
                    } else {
                        Ok(cert)
                    }
                })?;

            match self.verify_internal(trussed, Some(&parent), current_child.get(), recursion_level)
            {
                Ok(true) => {
                    current_child = MaybeOwned::from(parent);
                }
                Ok(false) => {
                    return Err(Error::IssuerNotFound);
                }
                Err(e) => {
                    return Err(e);
                }
            }

            recursion_level += 1;
        }
    }

    /// Checks whether certificate meets requirements defined in
    /// TCG EK Credential profile version 2.3 revision 2.
    fn tcg_compliance_check(cert: &X509Certificate) -> bool {
        if cert.version() != 3 {
            error!("Expected X509v3 certificate but got v{}", cert.version());
            return false;
        }

        // Subject Alternative Name extension must be present if subject is
        // empty.
        // TODO: DN parsing must be updated, currently unknown OIDs in DN are
        // discarded, so we can get empty DN where it actually isn't.
        //
        // Currently we are not using alternative name so we just ignore it.
        //
        // Subject alternative name contains various interesting
        // information like TPM manufacturer, TPM model, TPM version and other
        // TODO: do we need anything from there?

        // EK certificate must have Basic Constraints with CA set to FALSE

        if Self::ca_constraint_check(cert).0 {
            error!("EK certificate must have Basic Constraints with CA=FALSE");
            return false;
        }

        if let Some(key_usage) = cert.extension(X509V3_KEY_USAGE) {
            // According to TCG keyEncipherment bit must be set for RSA EK
            // certificate. Currently we assume RSA.

            match KeyUsage::from_der(key_usage.extn_value) {
                Ok(key_usage) => {
                    // TODO: probably should do something with other flags too.

                    let have_key_encipherment = key_usage
                        .into_iter()
                        .any(|x| x == KeyUsages::KeyEncipherment);
                    if !have_key_encipherment {
                        error!("keyEncipherment is not set, but it is required");
                        return false;
                    }
                }
                Err(e) => {
                    error!("Key usage extension data invalid: {}", e);
                    return false;
                }
            }
        } else {
            error!("Mandatory Key Usage extension is missing");
            return false;
        }

        true
    }

    fn po_requirements_check(cert: &X509Certificate) -> bool {
        if cert.version() != 3 {
            error!("PO certificate must be X.509v3");
            return false;
        }

        if !Self::ca_constraint_check(cert).0 {
            error!("Each certificate in PO chain must have Basic Constraints with CA=TRUE");
            return false;
        }

        true
    }

    /// Checks whether there are any unsupported critical extensions. Returns
    /// true if certificate has passed verification.
    fn extensions_check(cert: &X509Certificate) -> bool {
        if let Some(extensions) = cert.extensions() {
            for ext in extensions.iter().filter(|ext| ext.critical) {
                match ext.extn_id {
                    X509V3_CONSTRAINTS => (),
                    // Extension is verified in tcg_compliance_check.
                    X509V3_KEY_USAGE => (),
                    // We don't use this extension for any purpose.
                    X509V3_SUBJECT_ALTERNATIVE_NAME => (),
                    _ => {
                        error!("Unsupported critical extension OID {}", ext.extn_id);
                        return false;
                    }
                }
            }
        }

        true
    }

    /// Checks whether certificate can be used for signing other certificates
    /// (using X.509v3 Constraints extension).
    fn ca_constraint_check(cert: &X509Certificate) -> (bool, Option<u8>) {
        if let Some(constraints) = cert
            .extensions()
            .and_then(|x| x.iter().find(|x| x.extn_id == X509V3_CONSTRAINTS))
        {
            match x509::BasicConstraints::from_der(constraints.extn_value) {
                Ok(constraints) => {
                    if constraints.ca {
                        if let Some(path_len) = constraints.path_len_constraint {
                            // From RFC5280 section 4.2.1.9:
                            // The pathLenConstraint field is meaningful only if the cA boolean is
                            // asserted and the key usage extension, if present, asserts the
                            // keyCertSign bit (Section 4.2.1.3).  In this case, it gives the
                            // maximum number of non-self-issued intermediate certificates that may
                            // follow this certificate in a valid certification path.
                            (true, Some(path_len))
                        } else {
                            (true, None)
                        }
                    } else {
                        // Constraints explicitly forbid using this certificate as cA
                        (false, None)
                    }
                }
                Err(e) => {
                    error!("Failed to parse X.509v3 constraints: {}", e);
                    (false, None)
                }
            }
        } else {
            // There is no constraints extension prior to X.509v3, in that case
            // certificate may be used for any purpose.
            // In X.509v3 if constraints extension does not explicitly allow
            // such usage if certificate then it is forbidden.
            (cert.version() < 3, None)
        }
    }

    /// Verify parent-child relationship of supplied certificates. If parent is
    /// None then verify whether certificate is self-signed.
    fn verify_internal<T>(
        &self,
        trussed: &mut T,
        parent: Option<&X509Certificate>,
        child: &X509Certificate,
        depth: usize,
    ) -> Result<bool>
    where
        T: trussed::client::Sha256,
    {
        // TODO: verify whether child issuer matches with parent subject.

        let parent_key = if let Some(parent) = parent {
            let (ca, path_len_constraint) = Self::ca_constraint_check(parent);
            if !ca {
                error!("Parent cannot be used for singing (X.509v3 constraints)");
                return Ok(false);
            }

            if let Some(path_len_constraint) = path_len_constraint.map(usize::from) {
                if depth > path_len_constraint {
                    return Err(Error::ExceededPathLenConstraint);
                }
            }

            parent.key()?
        } else {
            if !Self::ca_constraint_check(child).0 {
                // If certificate constraints don't allow signing certificates,
                // then certificate cannot sign itself.
                return Ok(false);
            }

            // Optimization: in case of self-signed certificate Authority Key ID
            // and Subject Key ID must be the same.
            if let Some(auth_key_id) = child.authority_key_id().and_then(|x| x.key_identifier) {
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
                    _ => Err(Error::CustomStatic("Unsupported hash algorithm")),
                }
            }
        }
    }

    /// Gives hint about where to look for issuer certificate.
    fn get_parent_id<'r>(certificate: &'r X509Certificate) -> Result<&'r [u8]> {
        if let Some(id) = certificate
            .authority_key_id()
            .and_then(|x| x.key_identifier)
        {
            Ok(id.as_bytes())
        } else {
            Err(Error::AuthKeyIdMissing)
        }
    }
}
