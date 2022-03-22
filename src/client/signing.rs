use core::any::type_name;

use super::{crypto, proto::SignedObject};
use rsa::PublicKey as _;
use serde::Deserialize;
use trussed::{
    config::MAX_SIGNATURE_LENGTH,
    types::{Mechanism, SignatureSerialization},
};

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
        crypto::Key::Ed25519(key) => {
            if signed_object.signature.len() > MAX_SIGNATURE_LENGTH {
                // If verify_ed255() is called with to big signature then Trussed
                // will panic, so we need to handle that case ourselves.
                error!("Signature size exceeds MAX_SIGNATURE_LENGTH");
                return Err(());
            }

            match trussed::try_syscall!(trussed.verify(
                Mechanism::Ed255,
                key.key_id(),
                signed_object.data,
                signed_object.signature,
                SignatureSerialization::Raw
            )) {
                Ok(v) if v.valid => {
                    let sha = trussed::try_syscall!(trussed.hash(
                        Mechanism::Sha256,
                        trussed::Bytes::from_slice(signed_object.data).unwrap(),
                    ))
                    .map_err(|e| {
                        error!("Failed to compute SHA-256: {:?}", e);
                    })?;

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
                Ok(_) => {
                    error!("Signature is invalid");
                    Err(())
                }
                Err(e) => {
                    error!("verify_ed255() failed: {:?}", e);
                    Err(())
                }
            }
        }
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
