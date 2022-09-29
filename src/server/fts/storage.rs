use alloc::{sync::Arc, vec::Vec};
use coap_lite::{RequestType, ResponseType};
use coap_server::app::{CoapError, Request, Response};
use pal::embassy_util::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex};
use trussed::types::{HugeMessage, Location, PathBuf};

use crate::{
    udp::Endpoint,
    util::{
        coap::{
            get_raw_payload, response_empty, response_with_payload, verify_response_content_format,
        },
        HexFormatter,
    },
    Client, ServerState,
};

fn sanitize_filename(name: &str) -> bool {
    match name {
        "" | "." | ".." => false,
        name if name.chars().any(|x| x == '/' || x == '\x00') => false,
        _ => true,
    }
}

fn get_filename(platform: &[u8], filename: &str) -> PathBuf {
    let name = format!("{}_{}", HexFormatter(platform), filename);
    PathBuf::from(name.as_bytes())
}

fn get_path(platform: &[u8], filename: &str) -> PathBuf {
    let path = format!("/{}_{}", HexFormatter(platform), filename);
    PathBuf::from(path.as_bytes())
}

async fn file_read<T>(
    trussed: &mut T,
    platform: &[u8],
    filename: &str,
) -> Result<Vec<u8>, CoapError>
where
    T: trussed::client::FilesystemClient,
{
    trussed::try_syscall!(trussed.locate_file(
        Location::Internal,
        None,
        get_filename(platform, filename)
    ))
    .map_err(|_| {
        error!("Storage error when trying to locate {}", filename);
        CoapError::internal("Internal error")
    })?
    .path
    .ok_or_else(CoapError::not_found)?;

    let path = get_path(platform, filename);

    Ok(
        trussed::try_syscall!(trussed.read_file(Location::Internal, path))
            .map_err(|_| {
                error!("Storage error when trying to read {}", filename);
                CoapError::internal("Internal error")
            })?
            .data
            .to_vec(),
    )
}

async fn file_write<T>(
    trussed: &mut T,
    platform: &[u8],
    filename: &str,
    data: &[u8],
) -> Result<bool, CoapError>
where
    T: trussed::client::FilesystemClient,
{
    let path = get_path(platform, filename);
    let exists = trussed::try_syscall!(trussed.locate_file(
        Location::Internal,
        None,
        get_filename(platform, filename)
    ))
    .map_err(|_| {
        error!("Storage error when trying to locate {}", filename);
        CoapError::internal("Internal error")
    })?
    .path
    .is_some();

    trussed::try_syscall!(trussed.write_file(
        Location::Internal,
        path,
        HugeMessage::from_slice(data).map_err(|_| CoapError::internal("File is too big"))?,
        None
    ))
    .map_err(|_| {
        error!("Storage error when trying to write {}", filename);
        CoapError::internal("Internal error")
    })?;

    Ok(exists)
}

async fn file_delete<T>(trussed: &mut T, platform: &[u8], filename: &str) -> Result<bool, CoapError>
where
    T: trussed::client::FilesystemClient,
{
    let path = get_path(platform, filename);
    let exists = trussed::try_syscall!(trussed.locate_file(
        Location::Internal,
        None,
        get_filename(platform, filename)
    ))
    .map_err(|_| {
        error!("Storage error when trying to locate {}", filename);
        CoapError::internal("Internal error")
    })?
    .path
    .is_some();

    if !exists {
        return Ok(false);
    }

    trussed::try_syscall!(trussed.remove_file(Location::Internal, path)).map_err(|_| {
        error!("Storage error when trying to delete {}", filename);
        CoapError::internal("Internal error")
    })?;

    Ok(true)
}

pub async fn handler(
    request: Request<Endpoint>,
    state: &ServerState,
    client: Arc<Mutex<CriticalSectionRawMutex, Client>>,
) -> Result<Response, CoapError> {
    let client = client.lock().await;
    if request.unmatched_path.len() != 1 {
        return Err(CoapError::not_found());
    }

    let platform = client
        .attestation
        .platform()
        .ok_or_else(CoapError::not_found)?;

    let method = *request.original.get_method();
    if !matches!(
        method,
        RequestType::Get | RequestType::Put | RequestType::Delete
    ) {
        return Err(CoapError::method_not_allowed());
    }

    verify_response_content_format(&request, coap_lite::ContentFormat::ApplicationOctetStream)?;

    let filename = request.unmatched_path.first().unwrap();
    info!(
        "{:?}: {} {}",
        request.original.source.unwrap(),
        match method {
            RequestType::Get => "READ",
            RequestType::Put => "WRITE",
            RequestType::Delete => "DELETE",
            _ => unreachable!(),
        },
        filename
    );

    if !sanitize_filename(filename.as_str()) {
        error!("Path sanitization failed");
        return match method {
            // If path is invalid then file can not exist.
            RequestType::Get => Err(CoapError::not_found()),
            // Refuse to create file with a forbidden characters.
            RequestType::Put => Err(CoapError::forbidden()),
            // If the file does not exist we return 2.02
            RequestType::Delete => Ok(response_empty(&request)),
            _ => unreachable!(),
        };
    }

    let mut trussed = state.trussed.lock().await;
    match method {
        RequestType::Get => file_read(&mut *trussed, platform, filename)
            .await
            .map(|data| response_with_payload(&request, data)),
        RequestType::Put => file_write(
            &mut *trussed,
            platform,
            filename,
            get_raw_payload(&request.original)?,
        )
        .await
        .map(|did_exist_before| {
            let mut r = response_empty(&request);
            if did_exist_before {
                r.set_status(ResponseType::Changed);
            }
            r
        }),
        RequestType::Delete => file_delete(&mut *trussed, platform, filename)
            .await
            .map(|_removed| response_empty(&request)),
        _ => unreachable!(),
    }
}
