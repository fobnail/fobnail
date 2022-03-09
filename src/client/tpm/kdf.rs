use alloc::vec::Vec;

use super::mu::Algorithm;
use hmac::{Hmac, Mac, NewMac as _};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn kdf<M, F>(mut mac: M, bits: u32, update: F) -> Vec<u8>
where
    M: Mac,
    F: Fn(&mut M),
{
    let bytes = (bits + 7) / 8;
    let mut out: Vec<u8> = vec![];

    mac.reset();
    let mut counter: u32 = 1;
    while out.len() < bytes as usize {
        mac.update(&counter.to_be_bytes());
        update(&mut mac);

        let o = mac.finalize_reset().into_bytes();
        out.extend_from_slice(&o);
        counter += 1;
    }

    assert!(out.len() >= bytes as usize);
    // out's length is a multiple of hash size, so there will be excess bytes if bytes isn't a multiple of hash size.
    out.truncate(bytes as usize);

    // KDFa spec requires that the unused bits of the most significant octet are
    // masked off
    let mask_bits = (bits % 8) as u8;
    if mask_bits != 0 {
        out[0] &= (1 << mask_bits) - 1;
    }

    out
}

pub fn kdf_a(
    algo: Algorithm,
    key: &[u8],
    label: &str,
    context_u: &[u8],
    context_v: &[u8],
    bits: u32,
) -> Vec<u8> {
    // FIXME: Trussed has some support for KDF, but we cannot use it because of
    // lack of RSA support (and possibly for other reasons too).

    if algo != Algorithm::Sha256 {
        panic!("Unsupported algorithm {:?}", algo);
    }

    let mac = HmacSha256::new_from_slice(key).unwrap();
    kdf(mac, bits, |mac| {
        mac.update(label.as_bytes());
        mac.update(&[0]);
        mac.update(context_u);
        mac.update(context_v);
        mac.update(&bits.to_be_bytes());
    })
}

#[cfg(test)]
mod tests {
    use crate::client::tpm::mu;

    #[test]
    pub fn test_kdf() {
        // Tested against Go implementation from https://github.com/google/go-tpm/
        // TODO: should add more tests with varying key and data sizes

        let key: [u8; 16] = [
            0xe, 0x89, 0xbd, 0xa9, 0x5e, 0xc5, 0xee, 0xbc, 0xb2, 0x65, 0xec, 0x38, 0xaf, 0x51,
            0xec, 0x35,
        ];
        let context_u: [u8; 34] = [
            0x0, 0xb, 0x42, 0xaa, 0x8c, 0x55, 0x2e, 0xc0, 0xbb, 0x70, 0xb6, 0x21, 0x81, 0xf3, 0x1d,
            0x4f, 0xb4, 0x31, 0x0, 0xb0, 0x91, 0xce, 0x94, 0x46, 0x87, 0x8c, 0xe6, 0xbb, 0xb2,
            0xca, 0xb0, 0x73, 0x73, 0xeb,
        ];
        let expected_output: [u8; 16] = [
            0xe4, 0xfb, 0xd8, 0xb2, 0x2d, 0x00, 0x2a, 0x39, 0x77, 0x12, 0x92, 0xcc, 0xdb, 0xb9,
            0x7f, 0x48,
        ];

        let output = super::kdf_a(mu::Algorithm::Sha256, &key, "STORAGE", &context_u, &[], 128);
        assert_eq!(output, expected_output);
    }
}
