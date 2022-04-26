use core::marker::PhantomData;

pub mod rng;

pub struct RsaKey<'a> {
    pub inner: rsa::RsaPublicKey,
    phantom: PhantomData<&'a ()>,
}

impl RsaKey<'_> {
    pub fn load(n: &[u8], e: u32) -> Result<Self, ()> {
        match rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(n),
            rsa::BigUint::from_slice(&[e]),
        ) {
            Ok(key) => Ok(Self {
                inner: key,
                phantom: PhantomData,
            }),
            Err(e) => {
                error!("Invalid RSA key: {}", e);
                Err(())
            }
        }
    }
}

pub enum Key<'a> {
    Rsa(RsaKey<'a>),
}

/// Generate RSA private/public keypair.
pub fn generate_rsa_key<T>(trussed: &mut T, bits: usize) -> (rsa::RsaPrivateKey, rsa::RsaPublicKey)
where
    T: trussed::client::CryptoClient,
{
    info!("Generating {}-bit RSA keypair (may take a while)", bits);
    let before = pal::timer::get_time_ms() as u64;

    let priv_key = rsa::RsaPrivateKey::new(&mut rng::TrussedRng(trussed), bits).unwrap();
    let pub_key = rsa::RsaPublicKey::from(&priv_key);

    let now = pal::timer::get_time_ms() as u64;
    info!("RSA generating took {} ms", now - before);

    (priv_key, pub_key)
}
