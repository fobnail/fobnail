use core::marker::PhantomData;

use alloc::boxed::Box;
use trussed::{
    client, syscall,
    types::{KeyId, Location},
};

/// Represents a reference to a temporary public key managed by Trussed. When
/// all references are gone the key is removed.
pub struct Ed25519Key<'a> {
    key_id: KeyId,
    phantom: PhantomData<&'a ()>,
    // We use boxed closure to avoid having to annotate generics on Ed25519Key
    // struct, otherwise we would have to annotate them on all parent structs
    // too.
    drop_fn: Option<Box<dyn FnOnce(&KeyId) + 'a>>,
}

impl<'a> Ed25519Key<'a> {
    pub fn load<T, D>(trussed: &mut T, raw_key: &[u8], location: Location, drop_fn: D) -> Self
    where
        T: client::Ed255,
        D: FnOnce(&KeyId) + 'a,
    {
        let key_id = {
            let response = syscall!(trussed.deserialize_ed255_key(
                raw_key,
                trussed::types::KeySerialization::Raw,
                trussed::types::StorageAttributes {
                    persistence: location
                }
            ));

            response.key
        };

        debug!(
            "Loaded ed25519 key (ID {:?}) into {:?} memory",
            key_id, location
        );

        Self {
            key_id,
            phantom: PhantomData,
            drop_fn: Some(Box::new(drop_fn)),
        }
    }

    #[inline]
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }
}

impl Drop for Ed25519Key<'_> {
    fn drop(&mut self) {
        let drop_fn = self.drop_fn.take().unwrap();
        (drop_fn)(&self.key_id)
    }
}

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
    Ed25519(Ed25519Key<'a>),
    Rsa(RsaKey<'a>),
}
