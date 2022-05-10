use core::{marker::PhantomData, mem::forget};

use trussed::{
    api::reply::{Exists, GenerateKey, ReadFile},
    config::MAX_MESSAGE_LENGTH,
    types::{KeyId, Location, Mechanism, PathBuf, StorageAttributes},
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
    location: Location,
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
            location,
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

    pub fn load_named<T>(trussed: &mut T, location: Location, name: &str) -> Result<Self, ()>
    where
        T: trussed::client::CryptoClient + trussed::client::FilesystemClient,
    {
        let id = locate_key(trussed, location, name)
            .ok_or_else(|| debug!("key \"{}\" not found", name))?;

        let Exists { exists } = trussed::syscall!(trussed.exists(Mechanism::Ed255, id));
        if !exists {
            error!(
                "Name \"{}\" resolved to non-existent key ID {}",
                name,
                core::str::from_utf8(&id.hex()).unwrap_or("<invalid>")
            );
            return Err(());
        }

        Ok(Self {
            id,
            needs_manual_drop: false,
            location,
            phantom: PhantomData,
        })
    }

    pub fn assign_name<T>(&self, trussed: &mut T, name: &str) -> Result<(), ()>
    where
        T: trussed::client::FilesystemClient,
    {
        let key_serialized = trussed::cbor_serialize_bytes::<_, { MAX_MESSAGE_LENGTH }>(&self.id())
            .map_err(|e| error!("Failed to serialize key ID: {}", e))?;

        let path_str = format!("/key_{}", name);
        let path = PathBuf::from(path_str.as_bytes());

        trussed::try_syscall!(trussed.write_file(self.location, path, key_serialized, None))
            .map_err(|_| error!("Could not write {}", path_str))?;

        Ok(())
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

/// Converts named key into KeyId. Trussed currently doesn't support
/// named/labelled keys so we have to implement this on our own.
fn locate_key<T>(trussed: &mut T, location: Location, name: &str) -> Option<KeyId>
where
    T: trussed::client::FilesystemClient,
{
    let path = PathBuf::from(format!("/key_{}", name).as_bytes());
    let ReadFile { data } = trussed::try_syscall!(trussed.read_file(location, path)).ok()?;

    trussed::cbor_deserialize(&data)
        .map_err(|e| error!("Invalid serialized key ID: {}", e))
        .ok()
}
