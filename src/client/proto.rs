use alloc::{string::String, vec::Vec};
use core::{fmt, marker::PhantomData};
use serde::{Deserialize, Serialize};

pub const CURRENT_VERSION: u8 = 1;

pub struct MacAddress(pub [u8; 6]);

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, x) in self.0.iter().enumerate() {
            write!(f, "{}{:02X}", if i > 0 { ":" } else { "" }, x)?;
        }
        Ok(())
    }
}

impl<'de> serde::Deserialize<'de> for MacAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        struct MacVisitor;
        impl<'de> serde::de::Visitor<'de> for MacVisitor {
            type Value = MacAddress;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a MAC address")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != 6 {
                    Err(serde::de::Error::invalid_length(v.len(), &"6"))
                } else {
                    Ok(MacAddress(v.try_into().unwrap()))
                }
            }
        }

        deserializer.deserialize_bytes(MacVisitor)
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
// The only reason we choose cbor-smol over alternative solutions is that it
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
    pub manufacturer: String,
    pub product_name: String,
    pub serial_number: String,
}

#[derive(Deserialize)]
pub struct SignedObject<'a> {
    /// Contains CBOR-encoded object.
    pub data: &'a [u8],
    /// Contains `data` signature.
    pub signature: &'a [u8],
}

#[derive(Debug, Serialize)]
pub struct Challenge<'a> {
    // Due to https://github.com/serde-rs/serde/issues/518 we need to use
    // serde_bytes crate so that cbor-smol serializes data as sequence of bytes
    // and not sequence of objects - when serialized a sequence of objects each
    // byte in array is preceded by a major number, doubling size of serialized
    // data.
    //
    // See also serde_bytes README
    // https://github.com/serde-rs/bytes/blob/master/README.md
    #[serde(rename = "idObject", with = "serde_bytes")]
    pub id_object: &'a [u8],
    #[serde(rename = "encSecret", with = "serde_bytes")]
    pub encrypted_secret: &'a [u8],
}

/// Helper class to deserialize an array of byte strings.
#[derive(Debug, Default)]
pub struct ArrayOf<'a, T> {
    pub inner: Vec<T>,
    phantom: PhantomData<&'a ()>,
}

impl<T> ArrayOf<'_, T> {
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.inner.iter()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<T> IntoIterator for ArrayOf<'_, T> {
    type Item = T;
    type IntoIter = <Vec<T> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        Vec::<T>::into_iter(self.inner)
    }
}

impl<'a, 'de: 'a, T> serde::Deserialize<'de> for ArrayOf<'a, T>
where
    T: serde::Deserialize<'de> + 'a,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor<'a, T> {
            phantom: PhantomData<&'a T>,
        }
        impl<'a, 'de, T> serde::de::Visitor<'de> for Visitor<'a, T>
        where
            T: serde::Deserialize<'de>,
        {
            type Value = ArrayOf<'a, T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an array of objects")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut elements = vec![];
                while let Some(x) = seq.next_element::<T>()? {
                    elements.push(x);
                }
                Ok(ArrayOf {
                    inner: elements,
                    phantom: PhantomData,
                })
            }
        }
        deserializer.deserialize_seq(Visitor::<T> {
            phantom: PhantomData,
        })
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct Pcrs<'a> {
    pub pcrs: u32,
    #[serde(borrow)]
    pub pcr: ArrayOf<'a, &'a serde_bytes::Bytes>,
}

#[derive(Debug, Deserialize)]
pub struct Rim<'a> {
    pub update_ctr: u32,
    #[serde(borrow, default)]
    pub sha1: Pcrs<'a>,
    #[serde(borrow, default)]
    pub sha256: Pcrs<'a>,
    #[serde(borrow, default)]
    pub sha384: Pcrs<'a>,
}

#[derive(Debug, Serialize)]
pub struct Nonce<'a> {
    #[serde(with = "serde_bytes")]
    pub nonce: &'a [u8],
}

impl<'a> Nonce<'a> {
    #[inline]
    pub fn new(nonce: &'a [u8]) -> Self {
        Self { nonce }
    }
}
