use core::fmt::Display;

pub type Result<T> = ::core::result::Result<T, Error>;

// TODO: consider using thiserror when support for no_std lands
// https://github.com/dtolnay/thiserror/pull/64

#[derive(Debug)]
pub enum Error {
    X509(x509::der::Error),
    X509Spki(spki::Error),
    CustomStatic(&'static str),
    ExceededRecursionLimit,
    IssuerNotFound,
    UntrustedSelfSignedCert,
    UnsupportedCriticalExtension,
    DoesNotMeetTcgRequirements,
    DoesNotMeetPoRequirements,
    ExceededPathLenConstraint,
    AuthKeyIdMissing,
    NotX509v3,
    UnexpectedRoot { expected_root: &'static str },
}

impl From<x509::der::Error> for Error {
    fn from(e: x509::der::Error) -> Self {
        Self::X509(e)
    }
}

impl From<spki::Error> for Error {
    fn from(e: spki::Error) -> Self {
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
            Self::IssuerNotFound => write!(f, "no issuer certificate found"),
            Self::UntrustedSelfSignedCert => write!(f, "untrusted self-signed certificate"),
            Self::UnsupportedCriticalExtension => write!(f, "unsupported critical extension"),
            Self::DoesNotMeetTcgRequirements => {
                write!(f, "certificate does not meet TCG requirements")
            }
            Self::DoesNotMeetPoRequirements => {
                write!(f, "certificate does not meet requirements for PO chain")
            }
            Self::ExceededPathLenConstraint => {
                write!(f, "exceeded path length constraint")
            }
            Self::AuthKeyIdMissing => write!(f, "certificate doesn't have Authority Key ID set"),
            Self::NotX509v3 => write!(f, "certificate is not X.509v3"),
            Self::UnexpectedRoot { expected_root } => {
                write!(f, "chain should terminate on {} root", expected_root)
            }
        }
    }
}
