use littlefs2::const_ram_storage;
use trussed::types::{LfsResult, LfsStorage};

// Currently, we don't support persistent storage.
const_ram_storage!(InternalStorage, 4096);
const_ram_storage!(VolatileStorage, 4096);
// Currently, Trussed requires external storage with size of at least 1024
// bytes.
const_ram_storage!(ExternalStorage, 1024);

trussed::store!(
    Store,
    Internal: InternalStorage,
    External: ExternalStorage,
    Volatile: VolatileStorage
);

pub fn init() -> Store {
    Store::attach_else_format(
        InternalStorage::new(),
        ExternalStorage::new(),
        VolatileStorage::new(),
    )
}
