use core::sync::atomic::Ordering;

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use coap_lite::{ContentFormat, ResponseType};
use coap_server::app::{CoapError, Request, Response};
use pal::embassy_util::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex};
use rsa::PublicKeyParts;
use trussed::{
    client::{CryptoClient, FilesystemClient},
    config::MAX_MESSAGE_LENGTH,
    types::{Location, Mechanism, Message, PathBuf},
};

use crate::{
    certmgr::X509Certificate,
    udp::Endpoint,
    util::{
        coap::{
            decode_cbor_req, decode_signed_cbor_req, response_empty, verify_response_content_format,
        },
        create_object, crypto, format_hex,
        signing::Nonce,
        tpm, HexFormatter, ObjectId,
    },
    Client, ServerState,
};

use super::proto;

struct AikObject {
    aik: crypto::Key<'static>,
    secret: Vec<u8>,
    ek_id: ObjectId,
}

struct ProvisioningContext {
    metadata: Option<Vec<u8>>,
    rim: Option<Vec<u8>>,
    aik: crypto::Key<'static>,
}

impl ProvisioningContext {
    pub fn new(aik: crypto::Key<'static>) -> Self {
        Self {
            metadata: None,
            rim: None,
            aik,
        }
    }
}

#[derive(Default)]
pub struct Data {
    ek_certificates: BTreeMap<ObjectId, X509Certificate<'static>>,
    aik_keys: BTreeMap<ObjectId, AikObject>,
    pcs: BTreeMap<ObjectId, ProvisioningContext>,
}

pub async fn process_ek(
    request: Request<Endpoint>,
    state: &ServerState,
    client: Arc<Mutex<CriticalSectionRawMutex, Client>>,
) -> Result<Response, CoapError> {
    if !request.unmatched_path.is_empty() || !state.token_provisioned.load(Ordering::SeqCst) {
        return Err(CoapError::not_found());
    }

    let chain = decode_cbor_req(&request.original)?;

    let mut trussed = state.trussed.lock().await;
    let mut certmgr = state.certmgr.lock().await;
    let cert = tpm::ek::load(&mut *trussed, &mut *certmgr, chain).map_err(|()| {
        error!("EK certificate verification failed");
        CoapError::forbidden()
    })?;

    // RNG locks Trussed, need to drop our lock now to prevent deadlock.
    drop(trussed);
    Ok(create_object(
        &request,
        &mut client.lock().await.provisioning.ek_certificates,
        cert,
        &mut state.rng.clone(),
    ))
}

pub async fn process_aik(
    request: Request<Endpoint>,
    state: &ServerState,
    client: Arc<Mutex<CriticalSectionRawMutex, Client>>,
) -> Result<Response, CoapError> {
    if !request.unmatched_path.is_empty() || !state.token_provisioned.load(Ordering::SeqCst) {
        return Err(CoapError::not_found());
    }

    verify_response_content_format(&request, ContentFormat::ApplicationCBOR)?;

    let mut client = client.lock().await;
    let proto::Aik { aik, ek: ek_id } = decode_cbor_req(&request.original)?;
    let ek_cert = client
        .provisioning
        .ek_certificates
        .get(&ek_id)
        .ok_or_else(CoapError::not_found)?;

    let mut trussed = state.trussed.lock().await;
    let (public, secret, challenge) = tpm::aik::decode(&mut *trussed, aik)
        .and_then(|(tpm_public, loaded_key_name)| {
            tpm::prepare_aik_challenge(
                &mut *trussed,
                tpm::mu::LoadedKeyName::decode(&loaded_key_name).unwrap(),
                ek_cert,
            )
            .map(|x| (tpm_public, x))
        })
        .map_err(|()| {
            error!("AIK verification failed (stage 1)");
            CoapError::forbidden()
        })
        .and_then(|(public, (secret, id_object, encrypted_secret))| {
            trussed::cbor_serialize_bytes::<_, 512>(&proto::Challenge {
                id_object: &&id_object,
                encrypted_secret: &&encrypted_secret,
            })
            .map(|x| (public, secret, x))
            .map_err(|e| {
                error!("CBOR encode failed: {}", e);
                CoapError::forbidden()
            })
        })?;

    let aik = tpm::aik::load(&public).map_err(|()| {
        error!("Failed to load AIK");
        CoapError::forbidden()
    })?;

    // RNG locks Trussed, need to drop our lock now to prevent deadlock.
    drop(trussed);
    let mut response = create_object(
        &request,
        &mut client.provisioning.aik_keys,
        AikObject { aik, secret, ek_id },
        &mut state.rng.clone(),
    );
    response
        .message
        .set_content_format(ContentFormat::ApplicationCBOR);
    response.message.payload = challenge.to_vec();
    Ok(response)
}

async fn pc_process_meta(
    request: Request<Endpoint>,
    state: &ServerState,
    pc: &mut ProvisioningContext,
    nonce: Nonce,
) -> Result<Response, CoapError> {
    let mut trussed = state.trussed.lock().await;
    let (metadata, raw_metadata) = decode_signed_cbor_req::<_, proto::Metadata, _>(
        &request.original,
        &mut *trussed,
        &pc.aik,
        &nonce,
    )
    .map_err(|e| {
        error!("Could not decode metadata");
        e
    })?;

    if metadata.version != proto::CURRENT_VERSION {
        error!(
            "Unsupported metadata version {}, expected version {}",
            metadata.version,
            proto::CURRENT_VERSION
        );
        return Err(CoapError::bad_request("Unsupported metadata version"));
    }

    macro_rules! assert_exists {
        ($what:literal, $var:expr) => {
            if $var.is_empty() {
                error!(concat!($what, " is empty"));
                return Err(CoapError::bad_request(concat!($what, " is missing")));
            }
        };
    }
    assert_exists!("Manufacturer", metadata.manufacturer);
    assert_exists!("Product name", metadata.product_name);
    assert_exists!("Serial", metadata.serial_number);

    info!("Received attester metadata:");
    info!("  Version      : {}", metadata.version);
    info!("  MAC          : {}", metadata.mac);
    info!("  Manufacturer : {}", metadata.manufacturer);
    info!("  Product      : {}", metadata.product_name);
    info!("  Serial       : {}", metadata.serial_number);

    let mut response = response_empty(&request);
    if pc.metadata.replace(raw_metadata.to_vec()).is_some() {
        response.set_status(ResponseType::Changed);
    }
    Ok(response)
}

async fn pc_process_rim(
    request: Request<Endpoint>,
    state: &ServerState,
    pc: &mut ProvisioningContext,
    nonce: Nonce,
) -> Result<Response, CoapError> {
    let mut trussed = state.trussed.lock().await;
    let (rim, raw_rim) = decode_signed_cbor_req::<_, proto::Rim, _>(
        &request.original,
        &mut *trussed,
        &pc.aik,
        &nonce,
    )
    .map_err(|e| {
        error!("Could not decode RIM");
        e
    })?;
    rim.verify().map_err(|()| {
        error!("RIM is invalid");
        CoapError::bad_request("Invalid RIM")
    })?;
    if raw_rim.len() > trussed::config::MAX_MESSAGE_LENGTH {
        error!(
            "RIM is too big: size exceeds MAX_MESSAGE_LENGTH ({} vs {})",
            raw_rim.len(),
            trussed::config::MAX_MESSAGE_LENGTH
        );
        return Err(CoapError::bad_request("RIM too big"));
    }

    for bank in rim.banks.iter() {
        info!("{}:", bank.algo_id);
        for (i, pcr) in bank {
            info!("  pcr{:02}: {}", i, HexFormatter(pcr));
        }
    }

    let mut response = response_empty(&request);
    if pc.rim.replace(raw_rim.to_vec()).is_some() {
        response.set_status(ResponseType::Changed);
    }
    Ok(response)
}

async fn pc_complete(
    request: Request<Endpoint>,
    state: &ServerState,
    pc: &mut ProvisioningContext,
) -> Result<Response, CoapError> {
    let not_ready = || {
        error!("Provisioning Context is not complete");
        CoapError::forbidden()
    };

    let mut trussed = state.trussed.lock().await;

    let metadata = pc.metadata.as_deref().ok_or_else(not_ready)?;
    let rim = pc.rim.as_deref().ok_or_else(not_ready)?;

    let metadata_hash = trussed::try_syscall!(trussed.hash(
        Mechanism::Sha256,
        trussed::Bytes::from_slice(metadata).unwrap(),
    ))
    .map(|x| format_hex(&x.hash))
    .map_err(|e| {
        error!("Failed to compute SHA-256: {:?}", e);
        CoapError::internal("Internal error")
    })?;
    let meta_dir = PathBuf::from(b"/meta/");
    let path_str = format!("/meta/{}_aik", metadata_hash);

    if trussed::try_syscall!(trussed.locate_file(
        Location::Internal,
        Some(meta_dir),
        PathBuf::from(metadata_hash.as_str())
    ))
    .map(|x| x.path.is_some())
    .map_err(|_| {
        error!("Locate failed (file system problem?)");
        CoapError::internal("Internal error")
    })? {
        error!("{} is already provisioned", metadata_hash);
        error!("Refusing to re-provision");
        return Err(CoapError::forbidden());
    }

    let serialized = match &pc.aik {
        crypto::Key::Rsa(rsa) => {
            let e_v = rsa.inner.e().to_bytes_be();
            let mut e_a = [0u8; 4];
            if !e_v.is_empty() {
                e_a[4 - e_v.len()..].copy_from_slice(&e_v);
            }
            let e = u32::from_be_bytes(e_a);

            let key = proto::PersistentRsaKey {
                n: &rsa.inner.n().to_bytes_be()[..],
                e,
            };
            trussed::cbor_serialize_bytes::<_, MAX_MESSAGE_LENGTH>(&key).unwrap()
        }
        crypto::Key::Ed25519(_) => {
            error!("Platform provisioning with Ed25519 keys is not supported");
            return Err(CoapError::internal("Internal error"));
        }
    };

    let aik = Message::from_slice(&serialized).unwrap();
    let path = PathBuf::from(path_str.as_str());
    trussed::try_syscall!(trussed.write_file(Location::Internal, path, aik, None)).map_err(
        |e| {
            error!("Failed to save AIK: {:?}", e);
            CoapError::internal("Internal error")
        },
    )?;

    let path_str = format!("/meta/{}", metadata_hash);
    let rim = Message::from_slice(rim).unwrap();
    let path = PathBuf::from(path_str.as_str());
    trussed::try_syscall!(trussed.write_file(Location::Internal, path, rim, None)).map_err(
        |e| {
            error!("Failed to save RIM: {:?}", e);
            CoapError::internal("Internal error")
        },
    )?;

    info!("Wrote {}", path_str);
    info!("Provisioning is complete");

    let mut response = response_empty(&request);
    response.set_status(ResponseType::Changed);
    Ok(response)
}

async fn credential_activation_handler(
    request: Request<Endpoint>,
    state: &ServerState,
    client: Arc<Mutex<CriticalSectionRawMutex, Client>>,
) -> Result<Response, CoapError> {
    let mut client = client.lock().await;

    let ca: proto::CredentialActivationResult = decode_cbor_req(&request.original)?;
    // Remove EK and AIK, on successful Credential Activation AIK will be
    // bound to the Provisioning Context. EK is not needed anymore.
    let _ek = client
        .provisioning
        .ek_certificates
        .remove(&ca.ek)
        .ok_or_else(|| {
            error!("EKid {} not found", ca.ek);
            CoapError::not_found()
        })?;
    let aik = client
        .provisioning
        .aik_keys
        .remove(&ca.aik)
        .ok_or_else(|| {
            error!("AIKid {} not found", ca.aik);
            CoapError::not_found()
        })?;

    if aik.ek_id != ca.ek || ca.secret != aik.secret {
        error!("Attester has failed Credential Activation");
        return Err(CoapError::forbidden());
    }

    Ok(create_object(
        &request,
        &mut client.provisioning.pcs,
        ProvisioningContext::new(aik.aik),
        &mut state.rng.clone(),
    ))
}

pub async fn main_handler(
    request: Request<Endpoint>,
    state: &ServerState,
    client: Arc<Mutex<CriticalSectionRawMutex, Client>>,
) -> Result<Response, CoapError> {
    if !state.token_provisioned.load(Ordering::SeqCst) {
        return Err(CoapError::not_found());
    }

    if request.unmatched_path.is_empty() {
        return credential_activation_handler(request, state, client).await;
    }

    let pc_id = request
        .unmatched_path
        .first()
        .and_then(|x| x.parse::<u32>().ok())
        .ok_or_else(CoapError::not_found)?;
    let endpoint = request.unmatched_path.get(1).map(|x| &**x);

    let mut client = client.lock().await;
    // Treat lack of nonce as a signing error - client can't sign anything
    // properly without asking for the nonce
    let nonce = client.nonce.take().ok_or_else(CoapError::forbidden);

    let pc = client
        .provisioning
        .pcs
        .get_mut(&pc_id)
        .ok_or_else(CoapError::not_found)?;

    match endpoint {
        Some("meta") => pc_process_meta(request, state, pc, nonce?).await,
        Some("rim") => pc_process_rim(request, state, pc, nonce?).await,
        None => {
            let result = pc_complete(request, state, pc).await;
            // We are done, context is not needed anymore.
            client.provisioning.pcs.remove(&pc_id);
            result
        }
        Some(_) => Err(CoapError::not_found()),
    }
}
