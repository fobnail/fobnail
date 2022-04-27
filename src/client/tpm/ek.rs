use crate::certmgr::{CertMgr, Result, X509Certificate};

/// Verifies whether EK is signed by a trusted certificate and loads it.
pub fn load<T>(
    trussed: &mut T,
    certmgr: &CertMgr,
    raw_cert: &[u8],
) -> Result<X509Certificate<'static>>
where
    T: trussed::client::FilesystemClient + trussed::client::Sha256,
{
    let cert = certmgr.load_cert_owned(raw_cert)?;

    info!("X.509 version {}", cert.version());
    let issuer = cert.issuer()?;
    info!("Issuer: {}", issuer);
    let subject = cert.subject()?;
    info!("Subject: {}", subject);
    let key = cert.key()?;
    info!("Key: {}", key);

    certmgr.verify(trussed, &cert, crate::certmgr::VerifyMode::Ek)?;

    Ok(cert)
}
