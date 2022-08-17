use coap_server::app::{CoapError, Request, Response};
use trussed::types::Location;

use crate::{
    certmgr::CertMgr, server::proto, udp::Endpoint, util::crypto::Ed25519Key, ServerState,
};

/// Verify certchain. On success certificates are loaded into certstore as
/// volatile certificates so that they can be used later.
fn verify_certchain<T>(trussed: &mut T, certmgr: &mut CertMgr, chain: &[u8]) -> Result<(), ()>
where
    T: trussed::client::FilesystemClient + trussed::client::Sha256,
{
    /// Minimal number of certificates required in a chain (including root).
    const MIN_CERTS: usize = 2;
    /// Max number of certificates allowed in a chain (including root).
    const MAX_CERTS: usize = 3;

    let chain = trussed::cbor_deserialize::<proto::CertChain>(chain)
        .map_err(|e| error!("Failed to deserialize PO certchain: {}", e))?;

    let num_certs = chain.certs.len();
    if !matches!(num_certs, MIN_CERTS..=MAX_CERTS) {
        error!(
            "Expected between {} and {} certificates but got {}",
            MIN_CERTS, MAX_CERTS, num_certs
        );
        return Err(());
    }

    let mut it = chain.certs.iter();
    let root_raw = it.next().unwrap();
    // Attester sends full chain, including root ca. Check only whether received
    // root CA matches embedded CA.
    if &root_raw[..] != CertMgr::po_root_raw() {
        error!("Received root CA doesn't match with CA stored in firmware");
        return Err(());
    }

    for cert in it {
        match certmgr.load_cert_owned(cert) {
            Ok(cert) => match certmgr.verify(trussed, &cert, crate::certmgr::VerifyMode::Po) {
                Ok(()) => {
                    // Inject as volatile certificate, we will save
                    // certificates to persistent storage only after entire
                    // chain has been verified.
                    certmgr.inject_volatile_cert(cert);
                }
                Err(e) => {
                    error!("Cert verification failed: {}", e);
                    return Err(());
                }
            },
            Err(e) => {
                error!("Invalid certificate: {}", e);
                return Err(());
            }
        }
    }

    Ok(())
}

fn load_certchain<T>(trussed: &mut T)
where
    T: trussed::client::FilesystemClient + trussed::client::Sha256,
{
    let key = Ed25519Key::generate(trussed, Location::Internal).unwrap();
    // Trussed does not have APIs to turn once volatile key
    // into persistent one, i.e. we cannot change key location.
    // To workaround this problem we generate key only once
    // (device reset wipes out the key) and load the same key
    // on subsequent provisioning attempts.
    key.assign_name(trussed, "token").unwrap();
}

pub async fn token_provision_certchain(
    request: Request<Endpoint>,
    _state: &ServerState,
) -> Result<Response, CoapError> {
    if !request.unmatched_path.is_empty() {
        return Err(CoapError::not_found());
    }

    info!("commencing token provisioning");

    let response = request.new_response();
    Ok(response)
}

pub async fn token_provision_complete(
    _request: Request<Endpoint>,
    _state: &ServerState,
) -> Result<Response, CoapError> {
    todo!()
}
