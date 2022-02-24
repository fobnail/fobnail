use alloc::vec::Vec;

/// Corresponds to TPM2_ALG_ID type. Definitions must match with TPM2_ALG_*
/// constants from tss2_tpm2_types.h
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Algorithm {
    Sha256 = 0xb,
}

pub struct LoadedKeyName<'a> {
    algorithm: Algorithm,
    hash: &'a [u8],
    raw_data: &'a [u8],
}

impl<'a> LoadedKeyName<'a> {
    pub fn decode(data: &'a [u8]) -> Result<Self, ()> {
        let algorithm = u16::from_be_bytes(data.get(..2).ok_or(())?.try_into().unwrap());
        match algorithm {
            0xb => {
                let hash = data.get(2..).ok_or(())?;
                if hash.len() != 32 {
                    error!("Invalid LKN: algorithm={} len={}", algorithm, data.len());
                    return Err(());
                }

                Ok(Self {
                    algorithm: Algorithm::Sha256,
                    hash,
                    raw_data: data,
                })
            }
            _ => {
                error!("Unsupported algorithm ID=0x{:02x}", algorithm);
                Err(())
            }
        }
    }

    #[inline]
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    #[inline]
    pub fn hash(&self) -> &[u8] {
        self.hash
    }

    #[inline]
    pub fn raw_data(&self) -> &[u8] {
        self.raw_data
    }
}

pub struct ByteArray<'a> {
    inner: &'a [u8],
}

impl<'a> ByteArray<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { inner: buffer }
    }

    pub fn encode(&self) -> Vec<u8> {
        let buf_len: u16 = self.inner.len().try_into().expect("buffer to big for TPM");
        let mut v = Vec::with_capacity(buf_len as usize + 2);
        v.extend_from_slice(&buf_len.to_be_bytes());
        v.extend_from_slice(self.inner);
        v
    }
}

pub struct IDObject<'a> {
    integrity_hmac: &'a [u8],
    enc_identity: &'a [u8],
}

impl<'a> IDObject<'a> {
    pub fn new(integrity_hmac: &'a [u8], enc_identity: &'a [u8]) -> Self {
        Self {
            integrity_hmac,
            enc_identity,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let id_object_size = 2 // ID object size
                    + 2 // Integrity HMAC size
                    + self.integrity_hmac.len()
                    + self.enc_identity.len();
        let mut id_object = Vec::with_capacity(id_object_size);
        // Structure:
        //   u16  - size of structure (except this field)
        //   u16  - size of HMAC
        //   []u8 - HMAC
        //   []u8 - encIdentity
        id_object.extend_from_slice(&(id_object_size as u16 - 2).to_be_bytes());
        id_object.extend_from_slice(&u16::to_be_bytes(
            self.integrity_hmac.len().try_into().unwrap(),
        ));
        id_object.extend_from_slice(&self.integrity_hmac);
        id_object.extend_from_slice(&self.enc_identity);
        assert_eq!(id_object.len(), id_object_size);
        id_object
    }
}
