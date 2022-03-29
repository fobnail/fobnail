use core::cell::RefCell;

use embedded_storage::nor_flash::{NorFlash, ReadNorFlash};
use hal::{nvmc::Nvmc, pac::NVMC};
use littlefs2::{
    const_ram_storage,
    consts::{U16, U512},
};
use trussed::types::{LfsResult, LfsStorage};

const_ram_storage!(VolatileStorage, 4096);
// Currently, Trussed requires external storage with size of at least 1024
// bytes.
const_ram_storage!(ExternalStorage, 1024);

/// How much storage do we need. For now let's use 64 KiB, may be extended in
/// future (must be kept in sync with storage size declared in link.x file). Must
/// be multiple of 4096.
const PERSISTENT_STORAGE_SIZE: usize = 65536;

extern "C" {
    static __persistent_storage_start: usize;
    static __persistent_storage_end: usize;
}

trussed::store!(
    Store,
    Internal: Flash,
    External: ExternalStorage,
    Volatile: VolatileStorage
);

pub unsafe fn init(nvmc: NVMC) -> Store {
    const RAM_BASE: usize = 0x20000000;

    let storage_start = &__persistent_storage_start as *const _ as usize;
    let storage_size = (&__persistent_storage_end as *const _ as usize) - storage_start;

    // Ensure storage is erase block aligned.
    assert!((storage_start as usize) % 4096 == 0);
    // Length declared in linker script must match what we declared here.
    assert_eq!(storage_size, PERSISTENT_STORAGE_SIZE);
    // Make sure storage is located in ROM instead of RAM.
    assert!(storage_start < RAM_BASE);

    let storage = ::core::slice::from_raw_parts_mut(storage_start as *mut u8, storage_size);

    let flash = Flash::new(nvmc, storage);
    Store::attach_else_format(flash, ExternalStorage::new(), VolatileStorage::new())
}

pub struct Flash {
    nvmc: RefCell<Nvmc<NVMC>>,
}

impl Flash {
    pub fn new(nvmc: NVMC, storage: &'static mut [u8]) -> Self {
        let nvmc = Nvmc::new(nvmc, storage);
        Self {
            nvmc: RefCell::new(nvmc),
        }
    }
}

impl littlefs2::driver::Storage for Flash {
    const READ_SIZE: usize = 4;
    const WRITE_SIZE: usize = 4;

    const BLOCK_SIZE: usize = 4096;
    const BLOCK_COUNT: usize = PERSISTENT_STORAGE_SIZE / Self::BLOCK_SIZE;

    // Controls wear-levelling. The recommended value is between 100 and 1000
    // with 100 being more wear levelled and less performant. If we run into
    // performance issues this may be raised.
    const BLOCK_CYCLES: isize = 100;

    type CACHE_SIZE = U512;
    type LOOKAHEADWORDS_SIZE = U16;

    fn read(&self, off: usize, buf: &mut [u8]) -> LfsResult<usize> {
        let mut nvmc = self.nvmc.borrow_mut();
        nvmc.read(off.try_into().unwrap(), buf).unwrap();
        Ok(buf.len())
    }

    fn write(&mut self, off: usize, data: &[u8]) -> LfsResult<usize> {
        let mut nvmc = self.nvmc.borrow_mut();
        nvmc.write(off.try_into().unwrap(), data).unwrap();
        Ok(data.len())
    }

    fn erase(&mut self, off: usize, len: usize) -> LfsResult<usize> {
        let mut nvmc = self.nvmc.borrow_mut();
        let off: u32 = off.try_into().unwrap();
        let len: u32 = len.try_into().unwrap();
        // Use 1 ms period (the smallest possible value)
        nvmc.partial_erase(off, off + len, 1).unwrap();
        Ok(len as usize)
    }
}
