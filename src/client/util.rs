use core::fmt;

use alloc::string::String;
use coap_lite::{MessageClass, Packet, ResponseType};

pub struct HexFormatter<'a>(pub &'a [u8]);
impl fmt::Display for HexFormatter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for &x in self.0 {
            write!(f, "{:02x}", x)?;
        }
        Ok(())
    }
}

pub fn format_hex(data: &[u8]) -> String {
    format!("{}", HexFormatter(data))
}

/// Handles server error responses - communication with server works and we
/// received a valid response, but that response contains an error.
pub fn handle_server_error_response(result: &Packet) -> Result<(), ()> {
    match result.header.code {
        #[rustfmt::skip]
            MessageClass::Response(r) => match r {
                // 200 (success codes)
                ResponseType::Created => return Ok(()),
                ResponseType::Deleted => return Ok(()),
                ResponseType::Valid => return Ok(()),
                ResponseType::Changed => return Ok(()),
                ResponseType::Content => return Ok(()),
                ResponseType::Continue => return Ok(()),

                // 400 codes
                ResponseType::BadRequest => error!("server error: Bad request"),
                ResponseType::Unauthorized => error!("server error: Unauthorized"),
                ResponseType::BadOption => error!("server error: Bad option"),
                ResponseType::Forbidden => error!("server error: Forbidden"),
                ResponseType::NotFound => error!("server error: Not found"),
                ResponseType::MethodNotAllowed => error!("server error: Method not allowed"),
                ResponseType::NotAcceptable => error!("server error: Not acceptable"),
                ResponseType::Conflict => error!("server error: Conflict"),
                ResponseType::PreconditionFailed => error!("server error: Precondition failed"),
                ResponseType::RequestEntityTooLarge => error!("server error: RequestEntityTooLarge"),
                ResponseType::UnsupportedContentFormat => error!("server error: Unsupported content format"),
                ResponseType::RequestEntityIncomplete => error!("server error: Request entity incomplete"),
                ResponseType::UnprocessableEntity => error!("server error: Unprocessable entity"),
                ResponseType::TooManyRequests => error!("server error: Too many requests"),

                // 500 codes
                ResponseType::InternalServerError => error!("server error: Internal server error"),
                ResponseType::NotImplemented => error!("server error: Not implemented"),
                ResponseType::BadGateway => error!("server error: Bad gateway"),
                ResponseType::ServiceUnavailable => error!("server error: Service unavailable"),
                ResponseType::GatewayTimeout => error!("server error: Gateway timeout"),
                ResponseType::ProxyingNotSupported => error!("server error: Proxying not supported"),
                ResponseType::HopLimitReached => error!("server error: Hop limit Reached"),

                ResponseType::UnKnown => error!("unknown server error"),
            },
        // CoapClient revokes any packets that are not response packet
        _ => unreachable!("This packet type should be handled by CoapClient"),
    }

    Err(())
}
