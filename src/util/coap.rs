use alloc::{borrow::ToOwned, vec::Vec};
use coap_lite::{
    option_value::OptionValueU32, CoapOption, CoapRequest, ContentFormat, RequestType, ResponseType,
};
use coap_server::app::{CoapError, Request, Response};
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
