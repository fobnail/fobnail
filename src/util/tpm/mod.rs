use alloc::vec::Vec;
use hmac::{Mac, NewMac};
use rsa::PublicKey as _;
use trussed::api::reply::RandomBytes;

use crate::certmgr::X509Certificate;

use super::crypto::{rng::TrussedRng, RsaKey};

mod aes;
pub mod aik;
pub mod ek;
#[cfg(test)]
mod fake_rng;
mod kdf;
pub mod mu;

struct HexFormat<'a>(&'a [u8]);
impl core::fmt::Display for HexFormat<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for x in self.0 {
            write!(f, "{:02x}", *x)?;
        }
        Ok(())
    }
}

pub fn make_credential_rsa<T>(
    trussed: &mut T,
    loaded_key_name: mu::LoadedKeyName,
    ek_key: &RsaKey,
    sym_block_size: usize,
    secret: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), ()>
where
    T: trussed::client::CryptoClient + trussed::client::Sha256 + trussed::client::Aes256Cbc,
{
    // The seed length should match the keysize used by the EKs symmetric cipher.
    // For typical RSA EKs, this will be 128 bits (16 bytes).
    // Spec: TCG 2.0 EK Credential Profile revision 14, section 2.1.5.1.
    let RandomBytes { bytes: seed } = trussed::try_syscall!(trussed.random_bytes(sym_block_size))
        .map_err(|e| {
        error!("Failed to generate seed: {:?}", e);
    })?;

    make_credential_rsa_internal(
        &mut TrussedRng(trussed),
        loaded_key_name,
        ek_key,
        secret,
        &seed,
    )
}

fn make_credential_rsa_internal<R>(
    rng: &mut R,
    loaded_key_name: mu::LoadedKeyName,
    ek_key: &RsaKey,
    secret: &[u8],
    seed: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), ()>
where
    R: rand_core::RngCore,
{
    match loaded_key_name.algorithm() {
        mu::Algorithm::Sha256 => {
            // FIXME: should use Trussed for SHA256
            // Trussed does support SHA256 but it is not easy to integrate
            // with RSA library, or even impossible because Trussed
            // requires a single, continuous memory buffer to hash, ie.
            // there is no update() method
            let padding =
                rsa::PaddingScheme::new_oaep_with_label::<sha2::Sha256, _>("IDENTITY\x00");
            let encrypted_secret = ek_key.inner.encrypt(rng, padding, seed).unwrap();

            // Generate the encrypted credential by convolving the seed with the digest of
            // the AIK, and using the result as the key to encrypt the secret.
            // See section 24.4 of TPM 2.0 specification, part 1.
            let aes_key = kdf::kdf_a(
                loaded_key_name.algorithm(),
                seed,
                "STORAGE",
                loaded_key_name.raw_data(),
                &[],
                (seed.len() * 8).try_into().unwrap(),
            );

            // Prepend a 2 byte size field to secret
            let cv = mu::ByteArray::new(secret).encode();

            // FIXME: Once again we cannot use Trussed ...
            // Trussed implements AES CBC 256 but we need AES CFB 128.
            let mut enc_identity = vec![0u8; cv.len()];

            aes::aes128_cfb_encrypt(
                &aes_key,
                // Use null IV
                &[0u8; 16],
                &cv,
                &mut enc_identity,
            );

            // Generate the integrity HMAC, which is used to protect the integrity of the
            // encrypted structure.
            // See section 24.5 of the TPM specification revision 2 part 1.
            let mac_key = kdf::kdf_a(
                loaded_key_name.algorithm(),
                seed,
                "INTEGRITY",
                &[],
                &[],
                (loaded_key_name.hash().len() * 8).try_into().unwrap(),
            );

            let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&mac_key).unwrap();
            mac.update(&enc_identity);
            mac.update(loaded_key_name.raw_data());

            let integrity_hmac = mac.finalize().into_bytes();

            // Construct ID object
            let id_object = mu::IDObject::new(&integrity_hmac, &enc_identity).encode();
            let encrypted_secret_with_size = mu::ByteArray::new(&encrypted_secret).encode();

            Ok((id_object, encrypted_secret_with_size))
        }
        _ => {
            error!(
                "Algorithm {:?} is unsupported or invalid",
                loaded_key_name.algorithm()
            );
            Err(())
        }
    }
}

// Return type is not that complex. Eventually we may use struct.
#[allow(clippy::type_complexity)]
pub fn prepare_aik_challenge<T>(
    trussed: &mut T,
    loaded_key_name: mu::LoadedKeyName,
    ek_cert: &X509Certificate,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), ()>
where
    T: trussed::client::CryptoClient + trussed::client::Sha256 + trussed::client::Aes256Cbc,
{
    let RandomBytes { bytes: secret } =
        trussed::try_syscall!(trussed.random_bytes(32)).map_err(|e| {
            error!("Failed to generate secret: {:?}", e);
        })?;

    match ek_cert.key().map_err(|e| {
        error!("Failed to extract EK public key: {}", e);
    })? {
        crate::certmgr::Key::Rsa { n, e } => {
            let ek_key = RsaKey::load(n, e)?;

            let (id_object, encrypted_secret) =
                make_credential_rsa(trussed, loaded_key_name, &ek_key, 16, secret.as_slice())
                    .unwrap();

            let mut secret_copy = Vec::new();
            secret_copy.extend_from_slice(secret.as_slice());

            Ok((secret_copy, id_object, encrypted_secret))
        }
        crate::certmgr::Key::Ed25519 { .. } => {
            error!("Credential Activation with Ed25519 is not supported");
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use rand_core::RngCore;

    use super::{make_credential_rsa_internal, mu};
    use crate::util::crypto::RsaKey;

    #[test]
    fn test_credential_activation() {
        let modulus: [u8; 256] = [
            0xac, 0x8a, 0xa6, 0xb8, 0x0b, 0xee, 0x21, 0xc6, 0xa4, 0x20, 0x43, 0xdd, 0xda, 0x16,
            0x65, 0x6a, 0xfa, 0x1b, 0xdb, 0x57, 0xa1, 0x43, 0xbc, 0xda, 0x1d, 0xdb, 0x89, 0x40,
            0xd6, 0xcd, 0xb8, 0xa5, 0x52, 0x73, 0x51, 0xd3, 0x96, 0xfc, 0x3d, 0x0e, 0x45, 0x8d,
            0xd3, 0x76, 0xf4, 0x4a, 0x4b, 0x5c, 0x44, 0x87, 0xec, 0x8f, 0x0f, 0xe8, 0x9a, 0xa3,
            0xe5, 0xeb, 0x44, 0x61, 0x0b, 0x1d, 0x23, 0xab, 0x1b, 0x18, 0x9d, 0xfe, 0x46, 0x93,
            0x88, 0xe1, 0x7c, 0x29, 0xd4, 0x79, 0x05, 0x62, 0x70, 0x0a, 0x87, 0x9d, 0x41, 0xab,
            0x2a, 0x33, 0x24, 0x2c, 0x81, 0x93, 0x65, 0x53, 0xa9, 0xca, 0xa0, 0x44, 0x5c, 0x7b,
            0x1d, 0x86, 0xe8, 0x30, 0xe8, 0xce, 0x47, 0x54, 0x82, 0xb2, 0x7f, 0x03, 0x4e, 0x2a,
            0x1b, 0xcb, 0x64, 0xa4, 0x47, 0xf0, 0x99, 0x2f, 0xb4, 0x49, 0x55, 0x84, 0xb4, 0x3a,
            0x13, 0x6f, 0x87, 0xf3, 0x75, 0xe8, 0x4a, 0x99, 0x2d, 0xf6, 0x80, 0xa7, 0x18, 0xfc,
            0x8d, 0xd9, 0x9e, 0x6a, 0x44, 0xff, 0x9f, 0x85, 0x08, 0x91, 0xca, 0x53, 0x02, 0x0f,
            0xc4, 0x73, 0xf0, 0x00, 0x67, 0x61, 0x5a, 0x86, 0x04, 0x1a, 0xc6, 0xfb, 0x67, 0x01,
            0xb7, 0xfd, 0x2e, 0x14, 0xb8, 0xf1, 0x1f, 0x1d, 0xa6, 0x9b, 0xfe, 0x2c, 0x23, 0xfd,
            0x6c, 0x70, 0x6e, 0x71, 0xad, 0xca, 0xc3, 0x2e, 0xf6, 0xbd, 0x59, 0x90, 0x78, 0xd0,
            0xc7, 0xa1, 0x5b, 0x95, 0x65, 0x4b, 0xa1, 0x70, 0xaa, 0xad, 0x39, 0x74, 0xab, 0x4b,
            0x1a, 0x99, 0x3b, 0x96, 0xe7, 0x63, 0x1f, 0x7f, 0x26, 0xdb, 0x38, 0x4c, 0xe7, 0xf5,
            0x1d, 0x29, 0x9d, 0xf8, 0xb2, 0x42, 0x5a, 0x4b, 0xf0, 0x22, 0xca, 0x3f, 0x8f, 0xe4,
            0x04, 0xf5, 0x06, 0x92, 0x4b, 0xd9, 0x9b, 0x63, 0x09, 0xb0, 0x5d, 0x9c, 0xc0, 0xd4,
            0x49, 0xb4, 0x45, 0xd5,
        ];

        let aik_digest: [u8; 34] = [
            // Need to prepend algorithm ID
            0x00, 0x0b, // Original contents from Go implementation
            0xe6, 0xc9, 0xe9, 0x7f, 0xda, 0x91, 0x7c, 0xa0, 0xf6, 0x4d, 0xbe, 0xf6, 0x78, 0xb0,
            0x19, 0xa8, 0x2f, 0xda, 0xfc, 0xcc, 0x94, 0x86, 0x0f, 0x88, 0xbd, 0xdc, 0x03, 0x66,
            0x44, 0xc9, 0x2b, 0xdc,
        ];

        let expected: [u8; 328] = [
            0x00, 0x44, 0x00, 0x20, 0x84, 0x0d, 0x42, 0xed, 0x51, 0x91, 0x06, 0xa0, 0x6f, 0x23,
            0x7e, 0xec, 0x99, 0x42, 0x29, 0x47, 0xf0, 0x04, 0x9c, 0x48, 0xb0, 0xe3, 0x59, 0xdb,
            0xfe, 0x01, 0x0f, 0xb4, 0x38, 0x03, 0x5e, 0x7e, 0x05, 0xc0, 0xf2, 0x95, 0x39, 0x5c,
            0xbd, 0x30, 0xe0, 0x97, 0x50, 0x9d, 0x4e, 0xe8, 0x99, 0x93, 0x72, 0x5c, 0x79, 0xc8,
            0x67, 0xae, 0x96, 0xdf, 0x74, 0x35, 0xf2, 0x9d, 0x9f, 0x52, 0xa7, 0x4b, 0x8e, 0x03,
            0x01, 0x00, 0xa4, 0x31, 0xfb, 0xce, 0x1c, 0xcb, 0x02, 0xab, 0x0d, 0x31, 0x28, 0x84,
            0x76, 0xfd, 0x31, 0xa0, 0x6a, 0xc6, 0x7f, 0xfb, 0x0e, 0x09, 0x8c, 0xd2, 0x71, 0xc6,
            0x75, 0xa4, 0x32, 0x2f, 0xee, 0xe1, 0xce, 0x37, 0x7c, 0x8c, 0x32, 0xb5, 0xfc, 0x6d,
            0xe3, 0x8b, 0xb4, 0x26, 0x7d, 0xbc, 0x44, 0x37, 0xbd, 0x6e, 0x22, 0xe8, 0xd7, 0x56,
            0x50, 0x91, 0x1d, 0xfd, 0x47, 0x8c, 0x62, 0xe7, 0x35, 0xf9, 0x47, 0x2e, 0xe0, 0x80,
            0x79, 0xb5, 0xe5, 0x2d, 0x13, 0x18, 0x4d, 0xca, 0xfb, 0x4e, 0x5c, 0x43, 0x3b, 0x14,
            0xd5, 0xe7, 0x2a, 0x8a, 0x12, 0xda, 0x5b, 0x4b, 0x03, 0x42, 0xfb, 0x8e, 0x59, 0x32,
            0xab, 0x01, 0x8c, 0xec, 0x21, 0x34, 0x30, 0xae, 0x23, 0x78, 0x5b, 0xf2, 0xd7, 0x74,
            0x45, 0x35, 0xe9, 0x3a, 0x4b, 0x94, 0x5d, 0xe4, 0xc1, 0xf7, 0x46, 0x90, 0x6e, 0xaa,
            0x92, 0xf9, 0x36, 0x35, 0xff, 0xca, 0xbe, 0x20, 0xef, 0x10, 0xb2, 0x13, 0x64, 0x66,
            0x5e, 0xb0, 0x92, 0x0f, 0x60, 0xe2, 0x4e, 0x6e, 0xb0, 0x53, 0xf3, 0xed, 0x3b, 0x16,
            0x17, 0x51, 0x57, 0x57, 0x7a, 0xe2, 0xda, 0x2c, 0x3e, 0xbd, 0x83, 0x9a, 0x67, 0x10,
            0x05, 0xa1, 0x01, 0x1b, 0x98, 0x6b, 0xd4, 0xa8, 0x98, 0x12, 0x3c, 0x13, 0x0b, 0xdc,
            0xc6, 0x6f, 0xac, 0x95, 0xf2, 0x69, 0x4c, 0xaf, 0xd4, 0x9e, 0xb8, 0x3e, 0x14, 0xdf,
            0xdd, 0xfe, 0x7d, 0x24, 0xd0, 0x86, 0xa3, 0x92, 0x53, 0x65, 0x8b, 0xf8, 0xd1, 0x86,
            0xe4, 0x21, 0xe6, 0x78, 0x6b, 0x4d, 0x95, 0xe0, 0xf3, 0x49, 0x0f, 0xb0, 0x41, 0xab,
            0x69, 0x23, 0xfc, 0x78, 0x9a, 0x1f, 0xe3, 0xdb, 0xd1, 0xeb, 0x8d, 0xc4, 0xb6, 0x83,
            0xbc, 0xf2, 0x3c, 0xe9, 0x4c, 0x2f, 0xbf, 0xf5, 0x3b, 0xb7, 0xca, 0x21, 0x82, 0x0b,
            0x11, 0x0c, 0xa9, 0x1d, 0xac, 0xcc,
        ];

        let secret: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
        ];

        let lkn = mu::LoadedKeyName::decode(&aik_digest).unwrap();
        let ek_key = RsaKey::load(&modulus, 65537).unwrap();

        let mut rng = super::fake_rng::FakeRng::new(99);
        let mut seed = [0u8; 16];
        rng.fill_bytes(&mut seed[..]);

        let (id_object, credential) =
            make_credential_rsa_internal(&mut rng, lkn, &ek_key, &secret, &seed).unwrap();

        let mut activation_blob = Vec::with_capacity(id_object.len() + credential.len());
        activation_blob.extend_from_slice(&id_object);
        activation_blob.extend_from_slice(&credential);

        assert_eq!(activation_blob, expected);
    }
}
