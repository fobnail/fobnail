use alloc::{
    collections::{BTreeMap, LinkedList},
    string::{String, ToString},
};
use coap_lite::{option_value::OptionValueString, CoapOption};
use coap_server::app::{Request, Response};
use core::fmt;
use rand_core::RngCore;

use crate::util::coap::response_empty;

pub mod coap;
pub mod crypto;
pub mod policy;
pub mod provisioning;
pub mod rng;
pub mod signing;
pub mod tpm;

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

pub type ObjectId = u32;
pub fn create_object<R: RngCore, T, Endpoint>(
    request: &Request<Endpoint>,
    map: &mut BTreeMap<ObjectId, T>,
    object: T,
    rng: &mut R,
) -> Response {
    let rand = rng.next_u32();
    assert!(map.insert(rand, object).is_none());
    let mut r = response_empty(&request);
    r.message.set_options_as(
        CoapOption::LocationPath,
        LinkedList::from([OptionValueString(rand.to_string())]),
    );
    r
}
