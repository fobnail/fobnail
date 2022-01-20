use core::cell::RefCell;

use alloc::{boxed::Box, rc::Rc};
use trussed::{
    client, syscall,
    types::{KeyId, Location},
};

/// Represents a reference to a temporary public key managed by Trussed. When
/// all references are gone the key is removed.
pub struct Ed25519Key<'a> {
    key_id: KeyId,
    // Hack to avoid adding generic type T: client::Ed255. Otherwise structs
    // using this type would have to annotate generics which in turn spreads to
    // the parent struct all the way up.
    drop_fn: Box<dyn Fn() + 'a>,
}

impl<'a> Ed25519Key<'a> {
    pub fn load<T: client::Ed255 + 'a>(
        trussed: Rc<RefCell<T>>,
        raw_key: &[u8],
        location: Location,
    ) -> Self {
        let trussed2 = Rc::clone(&trussed);

        let key_id = {
            let mut b = trussed.borrow_mut();
            let response = syscall!(b.deserialize_ed255_key(
                raw_key,
                trussed::types::KeySerialization::Raw,
                trussed::types::StorageAttributes {
                    persistence: location
                }
            ));

            response.key
        };
        let key_id2 = key_id.clone();
        debug!(
            "Loaded ed25519 key (ID {:?}) into {:?} memory",
            key_id, location
        );

        Self {
            key_id,
            drop_fn: Box::new(move || {
                let key_id = key_id2;
                info!("Dropping key ID {:?}", key_id);

                let mut trussed = trussed2.borrow_mut();
                syscall!(trussed.delete(key_id));
            }),
        }
    }

    #[inline]
    pub fn key_id(&self) -> KeyId {
        self.key_id.clone()
    }
}

impl Drop for Ed25519Key<'_> {
    fn drop(&mut self) {
        let Self { drop_fn, .. } = self;
        (drop_fn)();
    }
}
