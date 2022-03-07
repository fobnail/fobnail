use core::fmt::Display;

pub type Result<T> = ::core::result::Result<T, Error>;

// TODO: consider using thiserror when support for no_std lands
// https://github.com/dtolnay/thiserror/pull/64

#[derive(Debug)]
pub enum Error {
    X509(x509::der::Error),
    X509Spki(x509::spki::Error),
    CustomStatic(&'static str),
    ExceededRecursionLimit,
    IssuerNotFound,
    UntrustedSelfSignedCert,
    UnsupportedCriticalExtension,
    DoesNotMeetTcgRequirements,
}

impl From<x509::der::Error> for Error {
    fn from(e: x509::der::Error) -> Self {
        Self::X509(e)
    }
}

impl From<x509::spki::Error> for Error {
    fn from(e: x509::spki::Error) -> Self {
        Self::X509Spki(e)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::X509(e) => e.fmt(f),
            Self::X509Spki(e) => e.fmt(f),
            Self::CustomStatic(e) => e.fmt(f),
            Self::ExceededRecursionLimit => write!(f, "exceeded recursion limit"),
            Self::IssuerNotFound => write!(f, "no issuer certicate found"),
            Self::UntrustedSelfSignedCert => write!(f, "untrusted self-signed certificate"),
            Self::UnsupportedCriticalExtension => write!(f, "unsupported critical extension"),
            Self::DoesNotMeetTcgRequirements => {
                write!(f, "certificate does not meet TCG requirements")
            }
        }
    }
}
