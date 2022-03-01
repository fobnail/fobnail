use alloc::vec::Vec;

macro_rules! decode {
    ($cursor:expr, $data:expr, [u8]) => {{
        let array_len = decode!($cursor, $data, u16);

        if array_len > 0 {
            if let Some(data) = $data.get($cursor..$cursor + array_len as usize) {
                #[allow(unused_assignments)]
                {
                    $cursor += array_len as usize;
                }
                data
            } else {
                error!("Data truncated");
                return Err(());
            }
        } else {
            &[]
        }
    }};

    ($cursor:expr, $data:expr, $t:ty) => {{
        let s = ::core::mem::size_of::<$t>();
        if let Some(data) = $data.get($cursor..$cursor + s) {
            #[allow(unused_assignments)]
            {
                $cursor += s;
            }
            <$t>::from_be_bytes(data.try_into().unwrap())
        } else {
            error!("Data truncated");
            return Err(());
        }
    }};
}

macro_rules! ensure {
    ($x:expr, $($msg:tt)+) => {{
        if !($x) {
            error!($($msg)+);
            return Err(());
        }
    }};
}

/// Corresponds to TPM2_ALG_ID type. Definitions must match with TPM2_ALG_*
/// constants from tss2_tpm2_types.h
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Algorithm {
    Invalid = 0x0,
    Rsa = 0x1,
    Sha256 = 0xb,
    Null = 0x10,
    RsaSsa = 0x14,
    RsaPss = 0x16,
}

impl Algorithm {
    pub fn is_null(self) -> bool {
        self == Algorithm::Null
    }

    pub fn is_hash(self) -> bool {
        match self {
            Self::Sha256 => true,
            Self::Invalid | Self::Null | Self::Rsa | Self::RsaSsa | Self::RsaPss => false,
        }
    }

    pub fn is_asymmetric(self) -> bool {
        match self {
            Self::Rsa | Self::RsaPss | Self::RsaSsa => true,
            Self::Invalid | Self::Null | Self::Sha256 => false,
        }
    }

    pub fn try_from_u8(value: u16) -> Result<Self, ()> {
        Ok(match value {
            0x0 => Algorithm::Invalid,
            0x1 => Algorithm::Rsa,
            0xb => Algorithm::Sha256,
            0x10 => Algorithm::Null,
            0x14 => Algorithm::RsaSsa,
            0x16 => Algorithm::RsaPss,
            _ => {
                error!("Unknown/unsupported algorithm ID 0x{:02x}", value);
                return Err(());
            }
        })
    }

    pub fn new_asymmetric(value: u16) -> Result<Self, ()> {
        let this = Self::try_from_u8(value)?;
        if !this.is_asymmetric() {
            error!(
                "Algorithm ID 0x{:02x} is not a supported asymmetric algorithm",
                value
            );
            return Err(());
        }
        Ok(this)
    }

    pub fn new_hash(value: u16) -> Result<Self, ()> {
        let this = Self::try_from_u8(value)?;
        if !this.is_hash() {
            error!(
                "Algorithm ID 0x{:02x} is not a supported hash algorithm",
                value
            );
            return Err(());
        }
        Ok(this)
    }

    #[inline(always)]
    pub fn as_raw(self) -> u16 {
        self as u16
    }
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

pub enum PublicKey<'a> {
    Rsa { modulus: &'a [u8], exponent: u32 },
}

pub struct Public<'a> {
    pub raw_data: &'a [u8],
    pub hash_algorithm: Algorithm,
    pub object_attributes: u32,
    pub key: PublicKey<'a>,
}

impl<'a> Public<'a> {
    pub fn decode(data: &'a [u8]) -> Result<Self, ()> {
        let mut cursor = 0;
        let len = decode!(cursor, data, u16);
        ensure!(len as usize == data.len() - 2, "Invalid TPM2B_PUBLIC size");
        let algorithm = Algorithm::new_asymmetric(decode!(cursor, data, u16))?;
        let hash_algorithm = Algorithm::new_hash(decode!(cursor, data, u16))?;
        let object_attributes = decode!(cursor, data, u32);
        let auth_policy = decode!(cursor, data, [u8]);
        ensure!(auth_policy.len() == 0, "authPolicy is not supported");

        // Decode TPMU_PUBLIC_PARMS, contents depend on algorithm type
        match algorithm {
            Algorithm::Rsa => {
                // Decode TPMS_RSA_PARMS structure
                // TODO: TPMT_SYM_DEF_OBJECT is absent from TPMS_RSA_PARMS when
                // decoding AIK, however it may be present depending on flags.
                // Need to inspect this.
                // let symmetric_algorithm_id = decode!(cursor, data, u16);
                // let symmetric_key_bits = decode!(cursor, data, u16);
                // let symmetric_sym_mode = decode!(cursor, data, u16);

                let rsa_scheme = Algorithm::try_from_u8(decode!(cursor, data, u16))?;
                let rsa_scheme_details = decode!(cursor, data, u16);
                // TODO: do we need to support this?
                ensure!(
                    rsa_scheme.is_null() && rsa_scheme_details == 0x10,
                    "Non-null scheme, this is not supported"
                );

                let rsa_key_bits = decode!(cursor, data, u16);
                ensure!(
                    rsa_key_bits.is_power_of_two(),
                    "RSA key size not power-of-two"
                );
                let exponent = {
                    // If exponent is 0 use defaults
                    let t = decode!(cursor, data, u32);
                    if t == 0 {
                        65537
                    } else {
                        t
                    }
                };

                let modulus = decode!(cursor, data, [u8]);
                ensure!(
                    modulus.len() == rsa_key_bits as usize / 8,
                    "Key size does not match ({} vs {})",
                    rsa_key_bits / 8,
                    modulus.len()
                );

                Ok(Self {
                    raw_data: data,
                    object_attributes,
                    hash_algorithm,
                    key: PublicKey::Rsa { exponent, modulus },
                })
            }
            _ => {
                error!("Unsupported asymmetric algorithm {:?}", algorithm);
                return Err(());
            }
        }
    }
}
