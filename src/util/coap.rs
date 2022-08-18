use alloc::{borrow::ToOwned, vec::Vec};
use coap_lite::{
    option_value::OptionValueU32, CoapOption, CoapRequest, ContentFormat, RequestType, ResponseType,
};
use coap_server::app::{CoapError, Request, Response};
use serde::Deserialize;

use super::{
    crypto,
    signing::{decode_signed_object, Nonce},
};

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

pub fn decode_signed_cbor_req<'a: 'de, 'de, T, D, Endpoint>(
    request: &'a CoapRequest<Endpoint>,
    trussed: &mut T,
    key: &crypto::Key,
    nonce: &Nonce,
) -> Result<(D, &'a [u8]), CoapError>
where
    T: trussed::client::CryptoClient,
    D: Deserialize<'de> + 'a,
{
    assert_content_format(request, ContentFormat::ApplicationCBOR)?;

    // FIXME: this will return 4.03 if object can't be deserialized. 4.03 should
    // be returned only on signature verification failure, if either inner or
    // outer can't be deserialized 4.00 should be returned instead.
    decode_signed_object::<_, D>(trussed, &request.message.payload, key, nonce)
        .map_err(|()| CoapError::bad_request("CBOR decode failed"))
}

pub fn get_raw_payload<Endpoint>(request: &CoapRequest<Endpoint>) -> Result<&[u8], CoapError> {
    assert_content_format(request, ContentFormat::ApplicationOctetStream)?;
    Ok(&request.message.payload)
}

pub fn is_response_cacheable<Endpoint>(request: &Request<Endpoint>) -> bool {
    request.original.get_method() == &RequestType::Get
}

pub fn response_empty<Endpoint>(request: &Request<Endpoint>) -> Response {
    let mut resp = request.new_response();
    if is_response_cacheable(&request) {
        resp.message
            .set_options_as(CoapOption::MaxAge, [OptionValueU32(0)].into());
    }
    resp
}

pub fn verify_response_content_format<Endpoint>(
    request: &Request<Endpoint>,
    format: ContentFormat,
) -> Result<(), CoapError> {
    if let Some(opt) = request.original.message.get_option(CoapOption::Accept) {
        for opt in opt.iter().filter_map(|x| {
            let value = u32::from_be_bytes(x[..].try_into().ok()?);
            ContentFormat::try_from(value as usize).ok()
        }) {
            if opt == format {
                return Ok(());
            }
        }

        return Err(CoapError {
            code: Some(ResponseType::NotAcceptable),
            message: "Not acceptable".to_owned(),
        });
    } else {
        Ok(())
    }
}

pub fn response_with_payload<Endpoint>(request: &Request<Endpoint>, payload: Vec<u8>) -> Response {
    let mut resp = request.new_response();
    if is_response_cacheable(&request) {
        resp.message
            .set_options_as(CoapOption::MaxAge, [OptionValueU32(0)].into());
    }
    resp.message.payload = payload;

    resp
}
