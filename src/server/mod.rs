use alloc::sync::Arc;
use coap_server::app::{CoapError, Request, Response};
use pal::embassy_util::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex};

use crate::{
    udp::Endpoint,
    util::{coap::response_with_payload, signing},
    Client, ServerState,
};

use self::proto::SupportedApiVersions;

pub mod attestation;
pub mod fts;
pub mod proto;
pub mod provisioning;
pub mod token_provisioning;

pub async fn generate_nonce(
    request: Request<Endpoint>,
    state: &ServerState,
    client: Arc<Mutex<CriticalSectionRawMutex, Client>>,
) -> Result<Response, CoapError> {
    if !request.unmatched_path.is_empty() {
        return Err(CoapError::not_found());
    }

    let nonce = {
        let mut trussed = state.trussed.lock().await;
        signing::generate_nonce(&mut *trussed)
    };

    client.lock().await.nonce = Some(nonce);
    Ok(response_with_payload(&request, nonce.to_vec()))
}

pub async fn get_api_version(
    request: Request<Endpoint>,
    state: &ServerState,
    client: Arc<Mutex<CriticalSectionRawMutex, Client>>,
) -> Result<Response, CoapError> {
    if !request.unmatched_path.is_empty() {
        return Err(CoapError::not_found());
    }

    let payload = trussed::cbor_serialize_bytes::<_, 512>(&SupportedApiVersions { versions: &[1] })
        .map_err(|e| {
            error!("CBOR encode failed: {}", e);
            CoapError::forbidden()
        })?;

    Ok(response_with_payload(&request, payload.to_vec()))
}
