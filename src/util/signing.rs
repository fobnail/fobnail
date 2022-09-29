use core::any::type_name;

use crate::{server::proto::SignedObject, util::crypto};
use rsa::PublicKey as _;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use trussed::types::Mechanism;

pub const NONCE_SIZE: usize = 32;

/// Verifies signature and returns contained raw data if signature is valid.
pub fn verify_signed_object<'a, T>(
    _trussed: &mut T,
    data: &'a [u8],
    signing_key: &crypto::Key,
    nonce: &[u8],
) -> Result<&'a [u8], ()>
where
    T: trussed::client::CryptoClient,
{
    let signed_object = trussed::cbor_deserialize::<SignedObject>(data).map_err(|e| {
        error!("Failed to deserialize signed object (outer): {}", e);
    })?;

    // We expect SHA256 for RSA and SHA512 for Ed25519
    match signing_key {
        crypto::Key::Rsa(key) => {
            // FIXME: we can't use Trussed due to limitations of its IPC, we
            // would have to allocate continuous buffer to hold all data we want
            // to hash on stack causing excessive stack usage which may result
            // in stack overflows.
            let mut hasher = Sha256::new();
            hasher.update(signed_object.data);
            hasher.update(nonce);
            let hash = hasher.finalize();

            // Currently, Trussed does not provide RSA support so we use
            // rsa crate directly.
            match key.inner.verify(
                rsa::PaddingScheme::PKCS1v15Sign {
                    hash: Some(rsa::Hash::SHA2_256),
                },
                &hash,
                signed_object.signature,
            ) {
                Ok(()) => Ok(signed_object.data),
                Err(e) => {
                    error!("Signature verification failed: {}", e);
                    Err(())
                }
            }
        }
        crypto::Key::Ed25519 { .. } => {
            error!("Ed25519 signed objects are not supported");
            Err(())
        }
    }
}

/// Verifies signature and decodes a CBOR-encoded object if signature is valid.
pub fn decode_signed_object<'a: 'de, 'de, S, T>(
    trussed: &mut S,
    data: &'a [u8],
    signing_key: &crypto::Key,
    nonce: &[u8],
) -> Result<(T, &'a [u8]), ()>
where
    S: trussed::client::CryptoClient,
    T: Deserialize<'de> + 'a,
{
    let data = verify_signed_object(trussed, data, signing_key, nonce)?;
    let inner_object = trussed::cbor_deserialize::<T>(data).map_err(|e| {
        error!(
            "Failed to deserialize inner object ({}): {}",
            type_name::<T>(),
            e
        )
    })?;
    Ok((inner_object, data))
}

/// Computes SHA-256 hash of inner object
pub fn hash_signed_object<T>(trussed: &mut T, data: &[u8]) -> Result<trussed::types::ShortData, ()>
where
    T: trussed::client::CryptoClient,
{
    let signed_object = trussed::cbor_deserialize::<SignedObject>(data).map_err(|e| {
        error!("Failed to deserialize signed object (outer): {}", e);
    })?;

    let sha = trussed::try_syscall!(trussed.hash(
        Mechanism::Sha256,
        trussed::Bytes::from_slice(signed_object.data).unwrap(),
    ))
    .map_err(|e| {
        error!("Failed to compute SHA-256: {:?}", e);
    })?;

    Ok(sha.hash)
}

pub type Nonce = [u8; NONCE_SIZE];

pub fn generate_nonce<T>(trussed: &mut T) -> Nonce
where
    T: trussed::client::CryptoClient,
{
    let r = trussed::syscall!(trussed.random_bytes(NONCE_SIZE));
    r.bytes.as_slice().try_into().unwrap()
}
