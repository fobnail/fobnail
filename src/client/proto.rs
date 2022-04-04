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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u16)]
pub enum PcrAlgo {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Unknown(u16),
}

impl From<u16> for PcrAlgo {
    fn from(x: u16) -> Self {
        // FIXME: due to https://github.com/rust-lang/rust/issues/60553 we map
        // identity map raw values into corresponding enum constants. Rust is free
        // to assign any discrimant to each variant.
        match x {
            0x04 => Self::Sha1,
            0x0b => Self::Sha256,
            0x0c => Self::Sha384,
            0x0d => Self::Sha512,
            _ => Self::Unknown(x),
        }
    }
}

impl From<PcrAlgo> for u16 {
    fn from(x: PcrAlgo) -> Self {
        match x {
            PcrAlgo::Sha1 => 0x04,
            PcrAlgo::Sha256 => 0x0b,
            PcrAlgo::Sha384 => 0x0c,
            PcrAlgo::Sha512 => 0x0d,
            PcrAlgo::Unknown(x) => x,
        }
    }
}

impl<'de> serde::Deserialize<'de> for PcrAlgo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = PcrAlgo;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an integer")
            }

            fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(PcrAlgo::from(v))
            }
        }

        deserializer.deserialize_u16(Visitor)
    }
}

impl serde::Serialize for PcrAlgo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u16((*self).into())
    }
}

impl fmt::Display for PcrAlgo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha1 => write!(f, "sha1"),
            Self::Sha256 => write!(f, "sha256"),
            Self::Sha384 => write!(f, "sha384"),
            Self::Sha512 => write!(f, "sha512"),
            Self::Unknown(u) => write!(f, "unknown (0x{:04x})", u),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct PcrBank<'a> {
    pub algo_id: PcrAlgo,
    pub pcrs: u32,
    #[serde(borrow)]
    pub pcr: ArrayOf<'a, &'a serde_bytes::Bytes>,
}

impl PcrBank<'_> {
    /// Check if specified PCR is present
    pub fn pcr_present(&self, index: u32) -> bool {
        if index > 31 {
            return false;
        }
        self.pcrs & (1 << index) != 0
    }

    /// Obtain PCR by its index.
    pub fn pcr(&self, index: u32) -> Option<&[u8]> {
        if !self.pcr_present(index) {
            None
        } else {
            let mut bitmap = self.pcrs;
            bitmap &= (1 << index) - 1;

            Some(&self.pcr.inner.get(bitmap.count_ones() as usize).unwrap()[..])
        }
    }
}

impl<'a> IntoIterator for &'a PcrBank<'a> {
    type Item = <Self::IntoIter as Iterator>::Item;
    type IntoIter = PcrIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        PcrIterator {
            bank: self,
            pcr_index: 0,
            pcr_offset: 0,
            bitmap: self.pcrs,
        }
    }
}

pub struct PcrIterator<'a> {
    bank: &'a PcrBank<'a>,
    pcr_index: u32,
    pcr_offset: u32,
    bitmap: u32,
}

impl<'a> Iterator for PcrIterator<'a> {
    type Item = (u32, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(&pcr) = self.bank.pcr.inner.get(self.pcr_offset as usize) {
            self.pcr_offset += 1;

            while self.bitmap & 1 != 1 {
                assert_ne!(self.bitmap, 0);
                self.pcr_index += 1;
                self.bitmap >>= 1;
            }
            self.bitmap >>= 1;
            let index = self.pcr_index;
            self.pcr_index += 1;

            Some((index, &pcr[..]))
        } else {
            None
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Rim<'a> {
    pub update_ctr: u32,
    #[serde(borrow)]
    pub banks: ArrayOf<'a, PcrBank<'a>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PersistentRsaKey<'a> {
    #[serde(with = "serde_bytes")]
    pub n: &'a [u8],
    pub e: u32,
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

impl<'a> Rim<'a> {
    pub fn verify(&self) -> Result<(), ()> {
        for bank in self.banks.iter() {
            Self::do_verify_pcrs(bank)?;
        }
        Ok(())
    }

    fn do_verify_pcrs(pcrs: &PcrBank) -> Result<(), ()> {
        // pcrs is a bitmask representing which PCRs are present and which are
        // not.
        let n1 = pcrs.pcrs.count_ones() as usize;
        let n2 = pcrs.pcr.len();
        if n1 != n2 {
            error!(
                "PCR count does not match, count from mask is {}, but really there are {} PCRs",
                n1, n2
            );
            return Err(());
        }

        // All PCRs in a single bank must have the same size
        let expected_pcr_len = pcrs.pcr.inner.get(0).map(|x| x.len()).unwrap_or(0);
        for pcr in pcrs.pcr.iter() {
            if pcr.len() != expected_pcr_len {
                error!(
                    "Invalid PCR size {}, expected {}",
                    pcr.len(),
                    expected_pcr_len
                );
                return Err(());
            }
        }

        Ok(())
    }
}

#[derive(Serialize)]
pub struct QuoteRequest<'a> {
    #[serde(flatten)]
    pub nonce: Nonce<'a>,
    pub banks: &'a [super::policy::Bank],
}

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    use super::{ArrayOf, PcrAlgo, PcrBank};

    #[test]
    fn test_pcr_bank_get() {
        let pcr0 = &[
            0x96, 0xd8, 0x63, 0xde, 0xd7, 0x45, 0x94, 0xca, 0x52, 0x75, 0x71, 0x95, 0x5c, 0x5e,
            0x13, 0xff, 0x2b, 0x1b, 0xa4, 0xa2,
        ];
        let pcr1 = &[
            0x2d, 0x7d, 0xda, 0x44, 0x1b, 0x16, 0x25, 0x55, 0x11, 0x5e, 0x60, 0xa1, 0x1b, 0x24,
            0xf1, 0x57, 0xbe, 0xfa, 0x15, 0x71,
        ];
        let pcr2 = &[
            0xc0, 0x50, 0xab, 0xe4, 0xce, 0x87, 0xa2, 0xa7, 0x54, 0x93, 0xe7, 0x8a, 0xfb, 0xed,
            0x49, 0x0e, 0x5b, 0x39, 0x10, 0xb5,
        ];
        let pcr8 = &[
            0xc7, 0x14, 0x62, 0xb0, 0x4d, 0x76, 0x8e, 0xf1, 0x54, 0xe3, 0xaa, 0x26, 0x1c, 0x6f,
            0x0a, 0xc3, 0x32, 0x79, 0xaa, 0x1b,
        ];

        let bank = PcrBank {
            algo_id: PcrAlgo::Sha1,
            pcrs: 0x107,
            pcr: ArrayOf {
                inner: vec![
                    serde_bytes::Bytes::new(pcr0),
                    serde_bytes::Bytes::new(pcr1),
                    serde_bytes::Bytes::new(pcr2),
                    serde_bytes::Bytes::new(pcr8),
                ],
                phantom: PhantomData,
            },
        };

        assert_eq!(bank.pcr(1), Some(&pcr1[..]));
        assert_eq!(bank.pcr(0), Some(&pcr0[..]));
        assert_eq!(bank.pcr(2), Some(&pcr2[..]));
        assert_eq!(bank.pcr(4), None);
        assert_eq!(bank.pcr(7), None);
        assert_eq!(bank.pcr(6), None);
        assert_eq!(bank.pcr(8), Some(&pcr8[..]));
        assert_eq!(bank.pcr(31), None);
        assert_eq!(bank.pcr(452), None);
    }

    // TODO:
    // check PCR iterator
    // check RIM integrity verification
    // should also check deserializing and serializing of data, one day it could
    // break after serde (unlikely) update or cbor-smol (possible)
}
