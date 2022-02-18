use core::{fmt, mem::ManuallyDrop};

use super::{Error, HashAlgorithm, Key, Result, Signature};
use alloc::vec::Vec;
use der::Decodable;
use x509::{
    der::{asn1::UIntBytes, Length, Sequence, Tag, Tagged},
    ObjectIdentifier, PKIX_AT_COUNTRYNAME, PKIX_AT_ORGANIZATIONNAME, PKIX_AT_STATEORPROVINCENAME,
};

/// Structure representing either or issuer or subject.
#[derive(Debug)]
pub struct IssuerSubject<'a> {
    pub country: &'a str,
    pub state: &'a str,
    pub organization: &'a str,
}

impl fmt::Display for IssuerSubject<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "C = {}, ST = {}, O = {}",
            self.country, self.state, self.organization
        )
    }
}

pub struct X509Certificate<'a> {
    inner: ManuallyDrop<x509::Certificate<'a>>,
    // Must be put after inner, so it's dropped later
    // Dropping this before inner will result in UB
    // Since there is an active borrow (from inner) owned cannot
    // be mutated.
    owned: Option<ManuallyDrop<Vec<u8>>>,
    pub(super) is_trusted: bool,
}

impl<'a> X509Certificate<'a> {
    pub fn parse_owned(data: Vec<u8>) -> Result<Self> {
        let mut decoder = x509::der::Decoder::new(unsafe {
            ::core::slice::from_raw_parts(data.as_ptr(), data.len())
        })?;
        let cert = decoder.decode::<x509::Certificate>()?;

        Ok(Self {
            inner: ManuallyDrop::new(cert),
            owned: Some(ManuallyDrop::new(data)),
            // Certificates loaded from memory are never trusted. Only
            // certificate loaded from persistent storage may be trusted.
            is_trusted: false,
        })
    }

    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let mut decoder = x509::der::Decoder::new(data)?;
        let cert = decoder.decode::<x509::Certificate>()?;

        Ok(Self {
            inner: ManuallyDrop::new(cert),
            owned: None,
            // Certificates loaded from memory are never trusted. Only
            // certificate loaded from persistent storage may be trusted.
            is_trusted: false,
        })
    }

    #[inline]
    pub fn version(&self) -> u8 {
        match self.inner.tbs_certificate.version {
            x509::Version::V1 => 1,
            x509::Version::V2 => 2,
            x509::Version::V3 => 3,
        }
    }

    #[inline]
    pub fn issuer(&self) -> Result<IssuerSubject> {
        parse_issuer_subject(&self.inner.tbs_certificate.issuer)
    }

    #[inline]
    pub fn subject(&self) -> Result<IssuerSubject> {
        parse_issuer_subject(&self.inner.tbs_certificate.subject)
    }

    pub fn key(&self) -> Result<Key> {
        const OID_RSA: ObjectIdentifier = ObjectIdentifier::new("1.2.840.113549.1.1.1");

        let info = &self.inner.tbs_certificate.subject_public_key_info;
        match info.algorithm.oid {
            OID_RSA => {
                info.algorithm
                    .parameters_any()?
                    .tag()
                    .assert_eq(Tag::Null)?;

                let mut decoder = x509::der::Decoder::new(&info.subject_public_key)?;
                let x = RsaPublicKey::decode(&mut decoder)?;

                let mut exponent_bytes = [0u8; 4];
                if x.e.len().is_zero() || x.e.len() > Length::new(4) {
                    return Err(Error::CustomStatic("Invalid exponent length"));
                }
                let b = x.e.as_bytes();
                let l = b.len();
                exponent_bytes[..l].copy_from_slice(b);
                let exponent = u32::from_le_bytes(exponent_bytes);

                info!("n: {:#?}", x.n);
                info!("e: {}", exponent);

                Ok(Key::Rsa {
                    n: x.n.as_bytes(),
                    e: exponent,
                })
            }
            _ => Err(Error::CustomStatic("Unsupported algorithm")),
        }
    }

    pub fn signature(&self) -> Result<Signature> {
        const OID_SHA224_WITH_RSA: ObjectIdentifier =
            ObjectIdentifier::new("1.2.840.113549.1.1.14");
        const OID_SHA256_WITH_RSA: ObjectIdentifier =
            ObjectIdentifier::new("1.2.840.113549.1.1.11");
        const OID_SHA384_WITH_RSA: ObjectIdentifier =
            ObjectIdentifier::new("1.2.840.113549.1.1.12");
        const OID_SHA512_WITH_RSA: ObjectIdentifier =
            ObjectIdentifier::new("1.2.840.113549.1.1.13");

        match self.inner.signature_algorithm.oid {
            OID_SHA224_WITH_RSA => Ok(Signature::rsa(HashAlgorithm::Sha224)),
            OID_SHA256_WITH_RSA => Ok(Signature::rsa(HashAlgorithm::Sha256)),
            OID_SHA384_WITH_RSA => Ok(Signature::rsa(HashAlgorithm::Sha384)),
            OID_SHA512_WITH_RSA => Ok(Signature::rsa(HashAlgorithm::Sha512)),
            _ => Err(Error::CustomStatic("Unsupported signature type")),
        }
    }

    pub fn is_trusted(&self) -> bool {
        self.is_trusted
    }
}

fn parse_issuer_subject<'r>(name: &'r x501::name::Name) -> Result<IssuerSubject<'r>> {
    let mut country = None;
    let mut state = None;
    let mut organization = None;

    for x in name.iter() {
        for y in x.iter() {
            macro_rules! getstr {
                ($target:expr) => {
                    if let Some(x) = parse_string(&y.value) {
                        if $target.is_some() {
                            error!("Duplicated field {}", stringify!($target));
                            return Err(Error::CustomStatic("Duplicated field"));
                        }
                        $target = Some(x);
                    } else {
                        error!("Invalid string in {}", stringify!($target));
                        return Err(Error::CustomStatic("Invalid string"));
                    }
                };
            }

            match y.oid {
                PKIX_AT_COUNTRYNAME => {
                    getstr!(country);
                }
                PKIX_AT_STATEORPROVINCENAME => {
                    getstr!(state);
                }
                PKIX_AT_ORGANIZATIONNAME => {
                    getstr!(organization);
                }
                oid => {
                    warn!("Unknown OID {}", oid);
                }
            }
        }
    }

    macro_rules! u {
        ($var:ident) => {
            let $var = {
                if let Some(v) = $var {
                    v
                } else {
                    error!("Field {} is missing", stringify!($var));
                    return Err(Error::CustomStatic("Required field is missing"));
                }
            };
        };
    }

    u!(country);
    u!(state);
    u!(organization);

    Ok(IssuerSubject {
        country,
        state,
        organization,
    })
}

fn parse_string<'r>(data: &'r x509::der::asn1::Any) -> Option<&'r str> {
    let s = data
        .utf8_string()
        .map(|x| x.as_str())
        .or(data.printable_string().map(|x| x.as_str()))
        .ok()?;
    Some(s)
}

impl<'a> Drop for X509Certificate<'a> {
    fn drop(&mut self) {
        unsafe {
            // Data is referenced by inner and must be dropped after inner,
            // otherwise we may get UB.

            ManuallyDrop::drop(&mut self.inner);
            if let Some(mut data) = self.owned.take() {
                ManuallyDrop::drop(&mut data)
            }
        }
    }
}

#[derive(Sequence)]
struct RsaPublicKey<'a> {
    pub n: UIntBytes<'a>,
    pub e: UIntBytes<'a>,
}
