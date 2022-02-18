use core::fmt;

pub enum Key<'a> {
    Rsa { n: &'a [u8], e: u32 },
}

impl Key<'_> {
    pub fn is_rsa(&self) -> bool {
        match self {
            Self::Rsa { .. } => true,
        }
    }
}

impl fmt::Display for Key<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rsa { n, .. } => {
                write!(f, "RSA{}", n.len())
            }
        }
    }
}
