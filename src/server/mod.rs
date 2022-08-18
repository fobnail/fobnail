use alloc::sync::Arc;
use coap_server::app::{CoapError, Request, Response};
use pal::embassy_util::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex};

use crate::{udp::Endpoint, util::signing, Client, ServerState};

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
    let mut response = request.new_response();
    response.message.payload = nonce.to_vec();
    Ok(response)
}
