use std::{
    cell::RefCell,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
};

use littlefs2::{
    const_ram_storage,
    consts::{U16, U512},
};
use trussed::types::{LfsResult, LfsStorage};

// Currently, we don't support persistent storage.
const_ram_storage!(VolatileStorage, 4096);
// Currently, Trussed requires external storage with size of at least 1024
// bytes.
const_ram_storage!(ExternalStorage, 1024);

trussed::store!(
    Store,
    Internal: Flash,
    External: ExternalStorage,
    Volatile: VolatileStorage
);

pub fn init() -> Store {
    let storage_file_path = std::env::var("FOBNAIL_FLASH");

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(storage_file_path.as_deref().unwrap_or("flash.bin"))
        .unwrap();

    Store::attach_else_format(
        Flash::new(file),
        ExternalStorage::new(),
        VolatileStorage::new(),
    )
}

pub struct Flash {
    file: RefCell<File>,
}

impl Flash {
    pub fn new(file: File) -> Self {
        // Allocate space
        let size = <Self as littlefs2::driver::Storage>::BLOCK_SIZE
            * <Self as littlefs2::driver::Storage>::BLOCK_COUNT;

        file.set_len(size.try_into().unwrap()).unwrap();

        Self {
            file: RefCell::new(file),
        }
    }
}

impl littlefs2::driver::Storage for Flash {
    // Emulate flash with similar parameters to these found on nRF52840.
    const READ_SIZE: usize = 4;
    const WRITE_SIZE: usize = 4;

    // For now let's use 64 KiB only, may be extended when needed.
    const BLOCK_SIZE: usize = 4096;
    const BLOCK_COUNT: usize = 16;

    // We don't need wear-leveling on PC.
    const BLOCK_CYCLES: isize = -1;

    type CACHE_SIZE = U512;
    type LOOKAHEADWORDS_SIZE = U16;

    fn read(&self, off: usize, buf: &mut [u8]) -> LfsResult<usize> {
        // For let's just unwrap errors, we assume that littlefs won't call us
        // with some weird requests and that I/O operations are infallible.
        // If needed this may be extended into a correct error handling.

        let mut file = self.file.borrow_mut();
        file.seek(SeekFrom::Start(off.try_into().unwrap())).unwrap();
        Ok(file.read(buf).unwrap())
    }

    fn write(&mut self, off: usize, buf: &[u8]) -> LfsResult<usize> {
        let mut file = self.file.borrow_mut();
        file.seek(SeekFrom::Start(off.try_into().unwrap())).unwrap();
        Ok(file.write(buf).unwrap())
    }

    fn erase(&mut self, off: usize, len: usize) -> LfsResult<usize> {
        // Use the same erase polarity as nRF flash has.
        let pattern: u8 = 0xff;
        let buf = vec![pattern; len];

        let mut file = self.file.borrow_mut();
        file.seek(SeekFrom::Start(off.try_into().unwrap())).unwrap();
        Ok(file.write(&buf[..]).unwrap())
    }
}
