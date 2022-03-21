use core::fmt;

use alloc::string::String;

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
