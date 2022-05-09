use core::fmt;

use super::Key;

pub enum HashAlgorithm {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

pub enum SignatureAlgorithm {
    Rsa,
    Ed25519,
}

pub struct Signature<'a> {
    pub hash_algo: HashAlgorithm,
    pub sig_algo: SignatureAlgorithm,
    pub signature: &'a [u8],
}

impl<'a> Signature<'a> {
    pub fn rsa(hash: HashAlgorithm, signature: &'a [u8]) -> Self {
        Self {
            hash_algo: hash,
            sig_algo: SignatureAlgorithm::Rsa,
            signature,
        }
    }

    pub fn ed25519(signature: &'a [u8]) -> Self {
        Self {
            hash_algo: HashAlgorithm::Sha512,
            sig_algo: SignatureAlgorithm::Ed25519,
            signature,
        }
    }

    pub fn is_compatible(&self, key: &Key) -> bool {
        match self.sig_algo {
            SignatureAlgorithm::Rsa => key.is_rsa(),
            SignatureAlgorithm::Ed25519 => key.is_ed25519(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.signature
    }
}

impl fmt::Display for Signature<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.sig_algo {
            SignatureAlgorithm::Rsa => match self.hash_algo {
                HashAlgorithm::Sha224 => write!(f, "sha224WithRSAEncryption"),
                HashAlgorithm::Sha256 => write!(f, "sha256WithRSAEncryption"),
                HashAlgorithm::Sha384 => write!(f, "sha384WithRSAEncryption"),
                HashAlgorithm::Sha512 => write!(f, "sha512WithRSAEncryption"),
            },
            SignatureAlgorithm::Ed25519 => write!(f, "ED25519"),
        }
    }
}
