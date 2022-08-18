use alloc::vec::Vec;

use super::{super::crypto, mu};

/// Decode TPM2B_PUBLIC structure containing AIK key, AIK name, attributes.
/// Verify key attributes and compute key name.
pub fn decode<'r, T>(trussed: &mut T, data: &'r [u8]) -> Result<(mu::Public<'r>, Vec<u8>), ()>
where
    T: trussed::client::Sha256,
{
    const TPMA_OBJECT_FIXEDTPM: u32 = 0x00000002;
    const TPMA_OBJECT_FIXEDPARENT: u32 = 0x00000010;
    const TPMA_OBJECT_SENSITIVEDATAORIGIN: u32 = 0x00000020;
    const TPMA_OBJECT_USERWITHAUTH: u32 = 0x00000040;
    const TPMA_OBJECT_NODA: u32 = 0x00000400;
    const TPMA_OBJECT_DECRYPT: u32 = 0x00020000;
    const TPMA_OBJECT_SIGN_ENCRYPT: u32 = 0x00040000;

    const EXPECTED_AIK_ATTRIBUTES: u32 = TPMA_OBJECT_USERWITHAUTH
        | TPMA_OBJECT_SIGN_ENCRYPT
        | TPMA_OBJECT_DECRYPT
        | TPMA_OBJECT_FIXEDTPM
        | TPMA_OBJECT_FIXEDPARENT
        | TPMA_OBJECT_SENSITIVEDATAORIGIN
        | TPMA_OBJECT_NODA;

    let public = mu::Public::decode(data)?;
    if public.object_attributes != EXPECTED_AIK_ATTRIBUTES {
        error!(
            "Key attributes are not valid for AIK, expected {} got {}",
            EXPECTED_AIK_ATTRIBUTES, public.object_attributes
        );
        return Err(());
    }

    let name = match public.hash_algorithm {
        mu::Algorithm::Sha256 => {
            // We hash all bytes except first two which are size of
            // TPM2B_PUBLIC structure.

            let trussed::api::reply::Hash { hash } =
                trussed::syscall!(trussed.hash_sha256(&public.raw_data[2..]));

            // Prepend algorithm ID to turn hash into name.
            let mut name = Vec::with_capacity(2 + hash.len());
            name.extend_from_slice(&public.hash_algorithm.as_raw().to_be_bytes());
            name.extend_from_slice(&hash);
            name
        }
        _ => {
            // TODO: to avoid matching hash algorithms in multiple places
            // we should create a universal helper method/class which takes
            // algorithm as parameter (instead of generics) and then calls
            // proper APIs.
            error!("Unsupported hash algorithm");
            error!("Cannot compute LKN");
            return Err(());
        }
    };

    Ok((public, name))
}

pub fn load(key: &mu::Public) -> Result<crypto::Key<'static>, ()> {
    match key.key {
        mu::PublicKey::Rsa { exponent, modulus } => match modulus.len() * 8 {
            1024 | 2048 | 4096 | 8192 => {
                let key = crypto::RsaKey::load(modulus, exponent)?;
                Ok(key.into())
            }

            n => {
                error!("Unsupported RSA key size {}", n * 8);
                Err(())
            }
        },
    }
}
