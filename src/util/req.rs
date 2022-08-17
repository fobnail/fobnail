use coap_lite::{CoapRequest, ContentFormat};
use coap_server::app::CoapError;
use serde::Deserialize;

fn assert_content_format<Endpoint>(
    request: &CoapRequest<Endpoint>,
    format: ContentFormat,
) -> Result<(), CoapError> {
    let f = request
        .message
        .get_content_format()
        .unwrap_or(ContentFormat::ApplicationOctetStream);
    if format != f {
        error!(
            "{:?} /{}: unexpected Content-Format: expected {:?} got {:?}",
            request.get_method(),
            request.get_path(),
            format,
            f
        );
        return Err(CoapError::bad_request(
            "Unsupported Content-Format for this request",
        ));
    }

    Ok(())
}

pub fn decode_cbor_req<'a: 'de, 'de, T, Endpoint>(
    request: &'a CoapRequest<Endpoint>,
) -> Result<T, CoapError>
where
    T: Deserialize<'de> + 'a,
{
    assert_content_format(request, ContentFormat::ApplicationCBOR)?;

    trussed::cbor_deserialize(&request.message.payload).map_err(|e| {
        error!("CBOR request deserialization failed: {}", e);
        CoapError::bad_request("CBOR decode failed")
    })
}

pub fn get_raw_payload<Endpoint>(request: &CoapRequest<Endpoint>) -> Result<&[u8], CoapError> {
    assert_content_format(request, ContentFormat::ApplicationOctetStream)?;
    Ok(&request.message.payload)
}
