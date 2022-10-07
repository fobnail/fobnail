use core::sync::atomic::Ordering;

use alloc::sync::Arc;
use coap_lite::ContentFormat;
use coap_server::app::{CoapError, Request, Response};
use pal::{
    embassy_util::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex},
    led,
};
use trussed::{
    api::reply::SerializeKey,
    types::{KeyId, KeySerialization, Location, Mechanism},
};

use crate::{
    certmgr::{CertMgr, Key},
    server::{proto, token_provisioning::csr::make_csr},
    udp::Endpoint,
    util::{
        coap::{
            decode_cbor_req, get_raw_payload, response_empty, response_with_payload,
            verify_response_content_format,
        },
        crypto::Ed25519Key,
    },
    Client, ServerState,
};

mod csr;

/// Verify certchain. On success certificates are loaded into certstore as
/// volatile certificates so that they can be used later.
fn verify_certchain<T>(
    trussed: &mut T,
    certmgr: &mut CertMgr,
    chain: proto::CertChain,
) -> Result<(), ()>
where
    T: trussed::client::FilesystemClient + trussed::client::Sha256,
{
    /// Minimal number of certificates required in a chain (including root).
    const MIN_CERTS: usize = 2;
    /// Max number of certificates allowed in a chain (including root).
    const MAX_CERTS: usize = 3;

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

/// Verify generated Identity/Encryption certificate. If verification is
/// successful save it to persistent storage, completing Fobnail token
/// provisioning.
fn verify_certificate<T>(
    trussed: &mut T,
    certmgr: &mut CertMgr,
    cert_raw: &[u8],
    key: KeyId,
) -> Result<(), CoapError>
where
    T: trussed::client::FilesystemClient + trussed::client::Sha256 + trussed::client::CryptoClient,
{
    let cert = certmgr.load_cert(cert_raw).map_err(|e| {
        error!("{}", e);
        CoapError::forbidden()
    })?;
    certmgr
        .verify(trussed, &cert, crate::certmgr::VerifyMode::TokenCert)
        .map_err(|e| {
            error!("{}", e);
            CoapError::forbidden()
        })?;

    let cert_key = cert.key().map_err(|e| {
        error!("{}", e);
        CoapError::forbidden()
    })?;
    match cert_key {
        Key::Ed25519(cert_key) => {
            let SerializeKey {
                serialized_key: key,
            } = trussed::try_syscall!(trussed.serialize_key(
                Mechanism::Ed255,
                key,
                KeySerialization::Raw
            ))
            .map_err(|e| {
                error!("Trussed key serialization failed: {:?}", e);
                CoapError::forbidden()
            })?;

            if key.as_slice() != cert_key {
                error!("Generated certificate public key mismatch");
                return Err(CoapError::forbidden());
            }
        }
        _ => {
            error!("Generated certificate algorithm mismatch");
            return Err(CoapError::forbidden());
        }
    }

    certmgr
        .save_certificate(trussed, &cert, "token_cert")
        .map_err(|()| CoapError::internal("Internal error"))?;

    Ok(())
}

fn load_token_key<'r, T>(trussed: &mut T) -> Result<Ed25519Key<'r>, ()>
where
    T: trussed::client::FilesystemClient + trussed::client::Sha256,
{
    let key = match Ed25519Key::load_named(trussed, Location::Internal, "token") {
        Ok(key) => key,
        Err(()) => {
            info!("Generating new Ed25519 keypair");
            match Ed25519Key::generate(trussed, Location::Internal) {
                // Trussed does not have APIs to turn once volatile key
                // into persistent one, i.e. we cannot change key location.
                // To workaround this problem we generate key only once
                // (device reset wipes out the key) and load the same key
                // on subsequent provisioning attempts.
                Ok(key) => match key.assign_name(trussed, "token") {
                    Ok(()) => key,
                    Err(()) => {
                        error!("Could not assign name to generated key");
                        key.delete(trussed);
                        return Err(());
                    }
                },
                Err(()) => {
                    error!("Failed to generate Ed25519 keypair");
                    return Err(());
                }
            }
        }
    };

    Ok(key)
}

pub async fn token_provision_certchain(
    request: Request<Endpoint>,
    state: &ServerState,
    _client: Arc<Mutex<CriticalSectionRawMutex, Client>>,
) -> Result<Response, CoapError> {
    if !request.unmatched_path.is_empty() || state.token_provisioned.load(Ordering::SeqCst) {
        return Err(CoapError::not_found());
    }

    verify_response_content_format(&request, ContentFormat::ApplicationOctetStream)?;
    let chain = decode_cbor_req(&request.original)?;

    info!("Commencing token provisioning");
    let mut trussed = state.trussed.lock().await;
    let mut certmgr = state.certmgr.lock().await;
    // Clear any certificates from previous provisioning attempt.
    certmgr.clear_volatile_certs();

    verify_certchain(&mut *trussed, &mut *certmgr, chain).map_err(|()| {
        error!("PO chain verification failed");
        CoapError::forbidden()
    })?;
    info!("Certificate chain loaded");

    let token_key =
        load_token_key(&mut *trussed).map_err(|()| CoapError::internal("Internal error"))?;

    let csr = make_csr(&mut *trussed, token_key.id(), pal::device_id()).map_err(|()| {
        error!("Failed to generate CSR");
        CoapError::internal("Internal error")
    })?;

    Ok(response_with_payload(&request, csr))
}

pub async fn token_provision_complete(
    request: Request<Endpoint>,
    state: &ServerState,
    _client: Arc<Mutex<CriticalSectionRawMutex, Client>>,
) -> Result<Response, CoapError> {
    if !request.unmatched_path.is_empty() || state.token_provisioned.load(Ordering::SeqCst) {
        return Err(CoapError::not_found());
    }

    let cert_raw = get_raw_payload(&request.original)?;

    let mut trussed = state.trussed.lock().await;
    let mut certmgr = state.certmgr.lock().await;
    let token_key =
        load_token_key(&mut *trussed).map_err(|()| CoapError::internal("Internal error"))?;

    verify_certificate(&mut *trussed, &mut certmgr, cert_raw, token_key.id())?;
    info!("Token provisioning complete");
    state.token_provisioned.store(true, Ordering::SeqCst);

    // Execute 2 commands, LED controller will complete signaling provisioning
    // completion before processing next command.
    led::control(led::LedState::TokenProvisioningComplete);
    led::control(led::LedState::TokenWaiting);

    Ok(response_empty(&request))
}
