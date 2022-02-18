use alloc::vec::Vec;
use core::fmt;
use serde::Deserialize;

pub const CURRENT_VERSION: u8 = 1;

#[derive(Deserialize)]
pub struct MacAddress(pub [u8; 6]);

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, x) in self.0.iter().enumerate() {
            write!(f, "{}{:02X}", if i > 0 { ":" } else { "" }, x)?;
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[repr(transparent)]
pub struct Serial(pub Vec<u8>);

impl fmt::Display for Serial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for x in &self.0 {
            write!(f, "{:02X}", x)?;
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[repr(u8)]
pub enum HashType {
    SHA1 = 0,
    SHA256 = 1,
    SHA512 = 2,
}

impl fmt::Display for HashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SHA1 => write!(f, "SHA-1"),
            Self::SHA256 => write!(f, "SHA-256"),
            Self::SHA512 => write!(f, "SHA-512"),
        }
    }
}

// We cannot use enum representation because cbor-smol does not support
// deserialize_any (which is used in automatically derived implementation,
// implementing this manually could work, but it would require a massive amount
// of work).
//
// cbor-smol won't implement this feature:
// https://github.com/nickray/cbor-smol/blob/main/src/de.rs#L293
//
// The only reason we choosed cbor-smol over alternative solutions is that it
// already is exported by Trussed and we don't want to pull many crates for the
// same purpose.
// TODO: maybe we can easily remove that dependency from Trussed and then use
// some other crate?
#[derive(Deserialize)]
pub struct Hash {
    pub id: HashType,
    pub hash: Vec<u8>,
}

#[derive(Deserialize)]
pub struct Metadata {
    pub version: u8,
    pub mac: MacAddress,
    pub sn: Serial,
    #[serde(rename = "EK_hash")]
    pub ek_hash: Hash,
}

#[derive(Deserialize)]
pub struct MetadataWithSignature<'a> {
    pub encoded_metadata: &'a [u8],
    pub signature: &'a [u8],
}

#[derive(Debug, Deserialize)]
pub struct RsaKey<'a> {
    pub n: &'a [u8],
    pub e: u32,
}

#[repr(u8)]
#[derive(Debug, Deserialize)]
pub enum KeyType {
    Ed25519 = 0,
    Rsa = 1,
}

#[derive(Debug, Deserialize)]
pub struct AikKey<'a> {
    #[serde(rename = "type")]
    pub key_type: KeyType,
    // cbor-smol (used by Trussed) does not implement `deserialize_any` so we
    // can't deserialize enums.
    // For now we need RSA only, and probably we won't any other keys for a long
    // time.
    #[serde(borrow)]
    pub key: RsaKey<'a>,
}
