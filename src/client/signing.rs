use core::any::type_name;

use super::{crypto, proto::SignedObject};
use rsa::PublicKey as _;
use serde::Deserialize;
use trussed::types::Mechanism;

/// Verifies signature and decodes a CBOR-encoded object if signature is valid.
pub fn decode_signed_object<'a: 'de, 'de, S, T>(
    trussed: &mut S,
    data: &'a [u8],
    signing_key: &crypto::Key,
) -> Result<(T, &'a [u8], trussed::types::ShortData), ()>
where
    S: trussed::client::CryptoClient,
    T: Deserialize<'de> + 'a,
{
    let signed_object = trussed::cbor_deserialize::<SignedObject>(data).map_err(|e| {
        error!("Failed to deserialize signed object (outer): {}", e);
    })?;

    // We expect SHA256 for RSA and SHA512 for Ed25519
    match signing_key {
        crypto::Key::Rsa(key) => {
            let sha = trussed::try_syscall!(trussed.hash(
                Mechanism::Sha256,
                trussed::Bytes::from_slice(signed_object.data).unwrap(),
            ))
            .map_err(|e| {
                error!("Failed to compute SHA-256: {:?}", e);
            })?;
            // Currently, Trussed does not provide RSA support so we use
            // rsa crate directly.
            match key.inner.verify(
                rsa::PaddingScheme::PKCS1v15Sign {
                    hash: Some(rsa::Hash::SHA2_256),
                },
                &sha.hash,
                signed_object.signature,
            ) {
                Ok(()) => {
                    let inner_object =
                        trussed::cbor_deserialize::<T>(signed_object.data).map_err(|e| {
                            error!(
                                "Failed to deserialize inner object ({}): {}",
                                type_name::<T>(),
                                e
                            )
                        })?;
                    Ok((inner_object, signed_object.data, sha.hash))
                }
                Err(e) => {
                    error!("Signature verification failed: {}", e);
                    Err(())
                }
            }
        }
    }
}
