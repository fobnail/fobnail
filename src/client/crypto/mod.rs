use core::{marker::PhantomData, mem::forget};

use trussed::{
    api::reply::GenerateKey,
    types::{KeyId, Location, Mechanism, StorageAttributes},
};

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

pub struct Ed25519Key<'a> {
    id: KeyId,
    needs_manual_drop: bool,
    phantom: PhantomData<&'a ()>,
}

impl<'a> Ed25519Key<'a> {
    pub fn generate<T>(trussed: &mut T, location: Location) -> Result<Self, ()>
    where
        T: trussed::client::CryptoClient,
    {
        let GenerateKey { key: id } = trussed::try_syscall!(trussed.generate_key(
            Mechanism::Ed255,
            StorageAttributes {
                persistence: location,
            },
        ))
        .map_err(|e| error!("Failed to generate ed25519 key: {:?}", e))?;

        Ok(Self {
            id,
            needs_manual_drop: location == Location::Volatile,
            phantom: PhantomData,
        })
    }

    pub fn delete<T>(self, trussed: &mut T)
    where
        T: trussed::client::CryptoClient,
    {
        trussed::syscall!(trussed.delete(self.id()));
        forget(self);
    }

    #[must_use]
    pub fn id(&self) -> KeyId {
        self.id
    }
}

impl Drop for Ed25519Key<'_> {
    fn drop(&mut self) {
        if self.needs_manual_drop {
            // Not the best solution, but for now I can't afford anything
            // better. To delete key we need trussed reference which introduces
            // many issues such as borrow problems - we can easily run into
            // problem when key destructor is called, but trussed is borrowed
            // elsewhere at the same time.
            // User must explicitly free each key.
            panic!("ed25519 key leak detected")
        }
    }
}

pub enum Key<'a> {
    Rsa(RsaKey<'a>),
    Ed25519(Ed25519Key<'a>),
}

impl<'a> From<RsaKey<'a>> for Key<'a> {
    fn from(key: RsaKey<'a>) -> Self {
        Self::Rsa(key)
    }
}

impl<'a> From<Ed25519Key<'a>> for Key<'a> {
    fn from(key: Ed25519Key<'a>) -> Self {
        Self::Ed25519(key)
    }
}
