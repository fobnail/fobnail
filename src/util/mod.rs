use alloc::string::String;
use core::fmt;

pub mod crypto;
pub mod policy;
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
