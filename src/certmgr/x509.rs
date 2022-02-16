use core::fmt;

use super::{Error, Result};
use x509::{PKIX_AT_COUNTRYNAME, PKIX_AT_ORGANIZATIONNAME, PKIX_AT_STATEORPROVINCENAME};

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
    pub inner: x509::Certificate<'a>,
}

impl<'a> X509Certificate<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let mut decoder = x509::der::Decoder::new(data)?;
        let cert = decoder.decode::<x509::Certificate>()?;

        Ok(Self { inner: cert })
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
