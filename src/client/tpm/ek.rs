use crate::{
    certmgr::{CertMgr, VerifyMode, X509Certificate},
    client::proto,
};

/// Verifies whether entire EK chain is rooted in a trusted certificate and
/// returns EK certificate.
pub fn load<T>(
    trussed: &mut T,
    certmgr: &mut CertMgr,
    chain: &[u8],
) -> Result<X509Certificate<'static>, ()>
where
    T: trussed::client::FilesystemClient + trussed::client::Sha256,
{
    /// Minimal number of certificates required in a chain (including EK
    /// certificate and excluding root CA).
    const MIN_CERTS: usize = 1;
    /// Max number of certificates allowed in a chain.
    const MAX_CERTS: usize = 2;

    let chain = trussed::cbor_deserialize::<proto::CertChain>(chain)
        .map_err(|e| error!("Failed to deserialize EK certchain: {}", e))?;

    let num_certs = chain.certs.len();
    if !matches!(num_certs, MIN_CERTS..=MAX_CERTS) {
        error!(
            "Expected between {} and {} certificates but got {}",
            MIN_CERTS, MAX_CERTS, num_certs
        );
        return Err(());
    }

    for (is_leaf, cert) in chain
        .certs
        .iter()
        .enumerate()
        .map(|(i, x)| (i == num_certs - 1, x))
    {
        match certmgr.load_cert_owned(cert) {
            Ok(cert) => match certmgr.verify(
                trussed,
                &cert,
                if is_leaf {
                    VerifyMode::Ek
                } else {
                    VerifyMode::Normal
                },
            ) {
                Ok(()) => {
                    if is_leaf {
                        // We are done, there is no need to inject EK as we won't
                        // use it to verify signatures. We need only public key
                        // to complete Credential Activation and verify AIK.

                        // Clear certchain, we won't need it anymore.
                        certmgr.clear_volatile_certs();

                        info!("X.509 version {}", cert.version());
                        if let Ok(issuer) = cert.issuer() {
                            info!("Issuer: {}", issuer);
                        }

                        if let Ok(subject) = cert.subject() {
                            info!("Subject: {}", subject);
                        }

                        if let Ok(key) = cert.key() {
                            info!("Key: {}", key);
                        }

                        return Ok(cert);
                    }

                    certmgr.inject_volatile_cert(cert);
                }
                Err(e) => {
                    certmgr.clear_volatile_certs();
                    error!("Cert verification failed: {}", e);
                    return Err(());
                }
            },
            Err(e) => {
                certmgr.clear_volatile_certs();
                error!("Invalid certificate: {}", e);
                return Err(());
            }
        }
    }

    unreachable!()
}
