use core::fmt;

pub enum Key<'a> {
    Rsa { n: &'a [u8], e: u32 },
    Ed25519(&'a [u8]),
}

impl Key<'_> {
    pub fn is_rsa(&self) -> bool {
        match self {
            Self::Rsa { .. } => true,
            Self::Ed25519 { .. } => false,
        }
    }

    pub fn is_ed25519(&self) -> bool {
        match self {
            Self::Rsa { .. } => false,
            Self::Ed25519 { .. } => true,
        }
    }
}

impl fmt::Display for Key<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rsa { n, .. } => {
                write!(f, "RSA{}", n.len() * 8)
            }
            Self::Ed25519 { .. } => {
                write!(f, "Ed25519")
            }
        }
    }
}
