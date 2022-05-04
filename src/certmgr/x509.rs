use core::{fmt, mem::ManuallyDrop};

use super::{Error, HashAlgorithm, Key, Result, Signature};
use alloc::vec::Vec;
use der::{
    oid::{
        db::{
            rfc2256::STATE_OR_PROVINCE_NAME,
            rfc4519::{COUNTRY_NAME, ORGANIZATION_NAME},
        },
        ObjectIdentifier,
    },
    Decode,
};
use x509::{
    der::{asn1::UIntBytes, Length, Sequence, Tag, Tagged},
    ext::pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier},
};

/// Structure representing either or issuer or subject.
#[derive(Debug)]
pub struct IssuerSubject<'a> {
    pub country: Option<&'a str>,
    pub state: Option<&'a str>,
    pub organization: Option<&'a str>,
}

impl fmt::Display for IssuerSubject<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(country) = self.country {
            write!(f, "C = {}, ", country)?;
        }

        if let Some(state) = self.state {
            write!(f, "ST = {}, ", state)?;
        }

        if let Some(organization) = self.organization {
            write!(f, "O = {}", organization)?;
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct X509Certificate<'a> {
    // These fields are kept because we need to extract raw TBS certificate to
    // verify signature. Keeping reference theoretically could result in
    // undefined behaviour when dropping X509Certificate - in drop() we destroy
    // `owned` field which causes reference to become invalid, Rust forbids
    // invalid references, having one (even if it's not used) is considered UB.
    raw_certificate: *const u8,
    raw_certificate_len: usize,
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
        let slice = unsafe { ::core::slice::from_raw_parts(data.as_ptr(), data.len()) };
        let mut decoder = x509::der::Decoder::new(slice)?;
        let cert = decoder.decode::<x509::Certificate>()?;

        Ok(Self {
            inner: ManuallyDrop::new(cert),
            owned: Some(ManuallyDrop::new(data)),
            // Certificates loaded from memory are never trusted. Only
            // certificate loaded from persistent storage may be trusted.
            is_trusted: false,
            raw_certificate: slice.as_ptr(),
            raw_certificate_len: slice.len(),
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
            raw_certificate: data.as_ptr(),
            raw_certificate_len: data.len(),
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
        const OID_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

        let info = &self.inner.tbs_certificate.subject_public_key_info;
        match info.algorithm.oid {
            OID_RSA => {
                info.algorithm
                    .parameters_any()?
                    .tag()
                    .assert_eq(Tag::Null)?;

                let mut decoder = x509::der::Decoder::new(info.subject_public_key)?;
                let x = RsaPublicKey::decode(&mut decoder)?;

                let mut exponent_bytes = [0u8; 4];
                if x.e.len().is_zero() || x.e.len() > Length::new(4) {
                    return Err(Error::CustomStatic("Invalid exponent length"));
                }
                let b = x.e.as_bytes();
                let l = b.len();
                exponent_bytes[..l].copy_from_slice(b);
                let exponent = u32::from_le_bytes(exponent_bytes);

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
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.14");
        const OID_SHA256_WITH_RSA: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
        const OID_SHA384_WITH_RSA: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
        const OID_SHA512_WITH_RSA: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

        let get_rsa_signature = || -> Result<&[u8]> {
            self.inner
                .signature
                .as_bytes()
                .ok_or(Error::CustomStatic("Invalid signature length"))
        };

        match self.inner.signature_algorithm.oid {
            OID_SHA224_WITH_RSA => {
                // RSA signature size always matches
                Ok(Signature::rsa(HashAlgorithm::Sha224, get_rsa_signature()?))
            }
            OID_SHA256_WITH_RSA => Ok(Signature::rsa(HashAlgorithm::Sha256, get_rsa_signature()?)),
            OID_SHA384_WITH_RSA => Ok(Signature::rsa(HashAlgorithm::Sha384, get_rsa_signature()?)),
            OID_SHA512_WITH_RSA => Ok(Signature::rsa(HashAlgorithm::Sha512, get_rsa_signature()?)),
            _ => Err(Error::CustomStatic("Unsupported signature type")),
        }
    }

    pub fn is_trusted(&self) -> bool {
        self.is_trusted
    }

    /// Obtain certificate in raw form.
    pub fn certificate_raw(&self) -> &[u8] {
        // SAFETY: self.raw_certificate refers to data that is valid until we
        // call drop()
        let data =
            unsafe { core::slice::from_raw_parts(self.raw_certificate, self.raw_certificate_len) };
        data
    }

    /// Workaround for getting TBS certificate as raw byte array. Needed for
    /// certificate chain verification.
    pub fn tbs_certificate_raw(&self) -> Result<&[u8]> {
        // SAFETY: self.raw_certificate refers to data that is valid until we
        // call drop()
        let data =
            unsafe { core::slice::from_raw_parts(self.raw_certificate, self.raw_certificate_len) };

        ///Structure supporting deferred decoding of fields in the Certificate SEQUENCE
        pub struct DeferDecodeCertificate<'a> {
            pub tbs_certificate: &'a [u8],
            pub signature_algorithm: &'a [u8],
            pub signature: &'a [u8],
        }

        impl<'a> Decode<'a> for DeferDecodeCertificate<'a> {
            fn decode(decoder: &mut der::Decoder<'a>) -> der::Result<DeferDecodeCertificate<'a>> {
                decoder.sequence(|decoder| {
                    let tbs_certificate = decoder.tlv_bytes()?;
                    let signature_algorithm = decoder.tlv_bytes()?;
                    let signature = decoder.tlv_bytes()?;
                    Ok(Self {
                        tbs_certificate,
                        signature_algorithm,
                        signature,
                    })
                })
            }
        }

        let mut decoder = x509::der::Decoder::new(data)?;
        let raw = decoder.decode::<DeferDecodeCertificate>()?;

        Ok(raw.tbs_certificate)
    }

    /// Returns an array of X.509v3 extensions.
    pub fn extensions(&self) -> Option<&x509::ext::Extensions> {
        self.inner.tbs_certificate.extensions.as_ref()
    }

    /// Lookups X.509v3 extensions by its OID.
    pub fn extension(&self, oid: ObjectIdentifier) -> Option<&x509::ext::Extension> {
        self.extensions()?.iter().find(|x| x.extn_id == oid)
    }

    /// Obtain X.509v3 Authority Key Identifier
    pub fn authority_key_id(&self) -> Option<AuthorityKeyIdentifier> {
        let extension = self.extension(ObjectIdentifier::new_unwrap("2.5.29.35"))?;
        let key_id = AuthorityKeyIdentifier::from_der(extension.extn_value).ok()?;
        Some(key_id)
    }

    /// Obtain X.509v3 Subject Key Identifier
    pub fn subject_key_id(&self) -> Option<SubjectKeyIdentifier> {
        let extension = self.extension(ObjectIdentifier::new_unwrap("2.5.29.14"))?;
        let key_id = SubjectKeyIdentifier::from_der(extension.extn_value).ok()?;
        Some(key_id)
    }
}

fn parse_issuer_subject<'r>(name: &'r x509::name::Name) -> Result<IssuerSubject<'r>> {
    let mut country = None;
    let mut state = None;
    let mut organization = None;

    for x in name.0.iter() {
        for y in x.0.iter() {
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
                COUNTRY_NAME => {
                    getstr!(country);
                }
                STATE_OR_PROVINCE_NAME => {
                    getstr!(state);
                }
                ORGANIZATION_NAME => {
                    getstr!(organization);
                }
                oid => {
                    warn!("Unknown OID {}", oid);
                }
            }
        }
    }

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
        .or_else(|_| data.printable_string().map(|x| x.as_str()))
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
