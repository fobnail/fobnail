use core::sync::atomic::Ordering;

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use coap_lite::{ContentFormat, ResponseType};
use coap_server::app::{CoapError, Request, Response};
use pal::{
    embassy_util::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex},
    led,
};
use sha2::Digest;
use trussed::{
    api::reply::ReadFile,
    types::{Location, PathBuf},
};

use crate::{
    server::proto,
    udp::Endpoint,
    util::{
        coap::{
            assert_content_format, decode_signed_cbor_req, response_empty,
            verify_response_content_format,
        },
        create_object, crypto, format_hex,
        policy::Policy,
        signing::{self, generate_nonce, hash_signed_object, Nonce},
        tpm, HexFormatter, ObjectId,
    },
    Client, ServerState,
};

#[derive(Default)]
pub struct Data {
    acs: BTreeMap<ObjectId, AttestationContext>,
    /// Hash of platform's metadata, used to identify attested platform. If platform
    /// has not been attested yet (or failed attestation) this is empty.
    metadata_hash: Vec<u8>,
}

impl Data {
    #[inline(always)]
    pub fn platform(&self) -> Option<&[u8]> {
        if !self.metadata_hash.is_empty() {
            Some(&self.metadata_hash)
        } else {
            None
        }
    }
}

pub struct AttestationContext {
    rim: Vec<u8>,
    nonce: Nonce,
    policy: Policy,
    aik: crypto::Key<'static>,
    metadata_hash: Vec<u8>,
}

/// Load AIK from internal storage.
fn load_aik<T>(trussed: &mut T, metadata_hash: &[u8]) -> Result<crypto::Key<'static>, ()>
where
    T: trussed::client::FilesystemClient,
{
    let metadata_hash = format_hex(metadata_hash);
    let path_str = format!("/meta/{}_aik", metadata_hash);
    let path = PathBuf::from(path_str.as_bytes());

    debug!("Loading AIK from {}", path_str);

    let ReadFile { data } = trussed::try_syscall!(trussed.read_file(Location::Internal, path))
        .map_err(|_| error!("Failed to load AIK (is the platform provisioned?)"))?;
    let proto::PersistentRsaKey { n, e } = trussed::cbor_deserialize(&data).map_err(|e| {
        error!("Failed to deserialize persistent key: {}", e);
        error!("AIK is corrupted, please re-provision your platform");
    })?;

    crypto::RsaKey::load(n, e)
        .map(crypto::Key::Rsa)
        .map_err(|_| {
            error!("AIK is corrupted, please re-provision your platform");
        })
}

fn load_rim<T>(trussed: &mut T, metadata_hash: &[u8]) -> Result<Vec<u8>, ()>
where
    T: trussed::client::FilesystemClient,
{
    let path_str = format!("/meta/{}", HexFormatter(metadata_hash));
    let path = PathBuf::from(path_str.as_str());
    match trussed::try_syscall!(trussed.read_file(Location::Internal, path)) {
        Ok(ReadFile { data }) => {
            let mut data_copy = Vec::new();
            data_copy.extend_from_slice(&data);
            Ok(data_copy)
        }
        Err(trussed::Error::FilesystemReadFailure) => {
            error!("Failed to read {} (is the platform provisioned?)", path_str);
            Err(())
        }
        Err(e) => {
            error!("Unknown file system error: {:?}", e);
            Err(())
        }
    }
}

async fn verify_evidence<T>(
    trussed: &mut T,
    evidence: &[u8],
    ac: &mut AttestationContext,
) -> Result<(), CoapError>
where
    T: trussed::client::CryptoClient,
{
    // Load and verify integrity of RIM stored in internal memory.
    // TODO: ideally we would do all verification during deserialize stage
    // but serde doesn't allow this currently (at least not easily), also
    // validity of one field may depend on another field which brings more
    // problems.
    // https://github.com/serde-rs/serde/issues/939
    let rim = trussed::cbor_deserialize::<proto::Rim>(&ac.rim).map_err(|e| {
        error!("Failed to deserialize RIM from internal storage: {}", e);
        error!("RIM is corrupted, please re-provision your platform");
        CoapError::internal("Internal error")
    })?;
    rim.verify().map_err(|_| {
        error!("RIM is corrupted, please re-provision your platform");
        CoapError::internal("Internal error")
    })?;

    // Nonce is inside TPMS_ATTEST structure, not here
    let evidence = signing::verify_signed_object(trussed, evidence, &ac.aik, &[])
        .map_err(|_| {
            error!("Evidence has invalid signature");
        })
        .and_then(tpm::mu::Quote::decode)
        .map_err(|()| CoapError::forbidden())?;

    let tpm::mu::Quote {
        extra_data,
        safe,
        banks,
        digest,
    } = evidence;

    if extra_data != ac.nonce {
        error!("Evidence nonce is invalid");
        return Err(CoapError::forbidden());
    }

    if safe == 0 {
        error!("TPM clock is not safe");
        return Err(CoapError::forbidden());
    }

    // Step 1: check if evidence contains bank that we did not request
    for bank in &banks {
        ac.policy
            .banks
            .iter()
            .find(|x| bank.algo_id == x.algo_id)
            .ok_or_else(|| {
                error!("Evidence contains bank we didn't request");
                CoapError::forbidden()
            })?;
    }

    // Step 2: check if evidence contains all banks we are interested in.
    // Check whether selected PCRs match policy's PCR selection.
    for bank in ac.policy.banks {
        banks
            .iter()
            .find(|x| x.algo_id == bank.algo_id)
            .ok_or_else(|| {
                error!(
                    "Required PCR bank ({}) not provided in evidence",
                    bank.algo_id
                );
                CoapError::forbidden()
            })
            .and_then(|x| {
                if bank.pcrs == x.pcrs {
                    Ok(())
                } else {
                    error!("Attester provided evidence with wrong PCR select");
                    error!("expected 0x{:08x} got 0x{:08x}", bank.pcrs, x.pcrs);
                    Err(CoapError::forbidden())
                }
            })?;
    }

    // Don't use Trussed here. Trussed doesn't provide update() method so we
    // would have to merge all PCRs into continuous memory region
    // TODO: move to Trussed when it gains required APIs
    let mut hasher = if digest.len() == 32 {
        // assume SHA-256
        sha2::Sha256::new()
    } else {
        error!("Unsupported hash algorithm for TPM quote");
        return Err(CoapError::forbidden());
    };

    // Step 3: Hash PCRs required by policy.
    //
    // Attester must hash PCR banks in the order defined by policy. PCRs
    // itself are always hashed starting with the lowest selected PCR.
    for bank in ac.policy.banks {
        // Policy contains information about what we want to verify, actual
        // PCRs we need to load from RIM
        let bank_rim = rim
            .banks
            .inner
            .iter()
            .find(|x| x.algo_id == bank.algo_id)
            .ok_or_else(|| {
                error!("RIM is missing required bank {}", bank.algo_id);
                error!("This may be caused by platform's TPM lacking PCR bank required by the current policy");
                CoapError::forbidden()
            })?;

        let mut hashed_pcrs = 0u32;
        for (i, pcr) in bank_rim {
            if bank.pcrs & (1 << i) == 0 {
                continue;
            }

            hasher.update(pcr);
            hashed_pcrs |= 1 << i;
        }

        // Check whether all PCRs required by policy are present.
        if hashed_pcrs != bank.pcrs {
            error!(
                "RIM is missing required set of PCRs from bank {}",
                bank.algo_id
            );
            return Err(CoapError::forbidden());
        }
    }

    // Step 4: compare hashes
    let pcr_digest_from_rim = hasher.finalize();
    if &pcr_digest_from_rim[..] == digest {
        Ok(())
    } else {
        error!("PCRs don't match");
        Err(CoapError::forbidden())
    }
}

pub async fn attest(
    request: Request<Endpoint>,
    state: &ServerState,
    client: Arc<Mutex<CriticalSectionRawMutex, Client>>,
) -> Result<Response, CoapError> {
    if !state.token_provisioned.load(Ordering::SeqCst) {
        return Err(CoapError::not_found());
    }

    if !request.unmatched_path.is_empty() {
        let ac_id = request
            .unmatched_path
            .first()
            .and_then(|x| x.parse::<u32>().ok())
            .ok_or_else(CoapError::not_found)?;

        if request.unmatched_path.len() != 1 {
            return Err(CoapError::not_found());
        }

        assert_content_format(&request.original, ContentFormat::ApplicationCBOR)?;
        let evidence = &request.original.message.payload[..];
        let mut client = client.lock().await;
        let ac = client
            .attestation
            .acs
            .get_mut(&ac_id)
            .ok_or_else(CoapError::not_found)?;

        let mut trussed = state.trussed.lock().await;
        match verify_evidence(&mut *trussed, evidence, ac).await {
            Ok(()) => {
                info!("Attestation successful");
                client.attestation.metadata_hash =
                    client.attestation.acs.remove(&ac_id).unwrap().metadata_hash;
                debug_assert!(!client.attestation.metadata_hash.is_empty());

                let mut response = response_empty(&request);
                response.set_status(ResponseType::Changed);

                *state.clients_with_fts_access.lock().await += 1;
                led::control(led::LedState::AttestationOk);
                return Ok(response);
            }
            Err(e) => {
                led::control(led::LedState::AttestationFailed);
                return Err(e);
            }
        }
    }

    assert_content_format(&request.original, ContentFormat::ApplicationCBOR)?;
    verify_response_content_format(&request, ContentFormat::ApplicationCBOR)?;

    // Treat lack of nonce as a signing error - client can't sign anything
    // properly without asking for the nonce
    let mut client = client.lock().await;
    let nonce = client.nonce.take().ok_or_else(CoapError::forbidden)?;
    let mut trussed = state.trussed.lock().await;
    let metadata_hash = hash_signed_object(&mut *trussed, &request.original.message.payload)
        .map_err(|()| CoapError::bad_request("Invalid CBOR"))?;

    let aik = load_aik(&mut *trussed, &metadata_hash).map_err(|()| CoapError::not_found())?;
    let meta: proto::Metadata =
        decode_signed_cbor_req(&request.original, &mut *trussed, &aik, &nonce)
            .map(|(meta, _)| meta)?;

    info!("Attesting platform:");
    info!("  MAC          : {}", meta.mac);
    info!("  Manufacturer : {}", meta.manufacturer);
    info!("  Product      : {}", meta.product_name);
    info!("  Serial       : {}", meta.serial_number);

    let rim = load_rim(&mut *trussed, &metadata_hash).map_err(|()| CoapError::not_found())?;
    // TODO: policy should be loaded from
    // internal storage
    let policy = Policy::default();
    let quote_nonce = generate_nonce(&mut *trussed);

    let quote_request = trussed::cbor_serialize_bytes::<_, 512>(&proto::QuoteRequest {
        nonce: proto::Nonce::new(&quote_nonce),
        banks: policy.banks,
    })
    .map_err(|e| {
        error!("CBOR serialization failed: {}", e);
        CoapError::internal("Internal error")
    })?;

    // RNG locks Trussed, need to drop our lock now to prevent deadlock.
    drop(trussed);
    let mut response = create_object(
        &request,
        &mut client.attestation.acs,
        AttestationContext {
            rim,
            nonce: quote_nonce,
            policy,
            aik,
            metadata_hash: metadata_hash.to_vec(),
        },
        &mut state.rng.clone(),
    );
    response
        .message
        .set_content_format(ContentFormat::ApplicationCBOR);
    response.message.payload = quote_request.to_vec();
    Ok(response)
}
