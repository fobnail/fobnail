use core::{
    alloc::{GlobalAlloc, Layout},
    cell::RefCell,
    ptr::{self, NonNull},
};

use cortex_m::interrupt::{free, Mutex};
use linked_list_allocator::Heap;

struct Allocator {
    heap: Mutex<RefCell<Heap>>,
}

impl Allocator {
    unsafe fn init(&self, base: usize, len: usize) {
        free(|cs| {
            self.heap.borrow(cs).borrow_mut().init(base as *mut u8, len);
        })
    }
}

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        free(|cs| {
            let mut heap = self.heap.borrow(cs).borrow_mut();

            #[cfg(feature = "heap_debug")]
            {
                trace!("alloc {} bytes ({} free)", layout.size(), heap.free());
            }

            let p = heap
                .allocate_first_fit(layout)
                .map_or(ptr::null_mut(), |a| a.as_ptr());

            if p.is_null() {
                error!("Failed to allocate object of size {}", layout.size());
            }
            p
        })
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        free(|cs| {
            let mut heap = self.heap.borrow(cs).borrow_mut();
            #[cfg(feature = "heap_debug")]
            {
                trace!("free {} bytes ({} free)", layout.size(), heap.free());
            }

            heap.deallocate(NonNull::new_unchecked(ptr), layout);
        })
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator {
    heap: Mutex::new(RefCell::new(Heap::empty())),
};

#[alloc_error_handler]
fn oom_handler(layout: Layout) -> ! {
    error!(
        "Out of memory, failed to allocate object of size {}",
        layout.size()
    );
    panic!("Out of memory");
}

pub fn init() {
    const RAM_TOP: usize = 0x20040000;
    const HEAP_SIZE: usize = 65536;

    let base = cortex_m_rt::heap_start() as usize;
    let end = base + HEAP_SIZE - 1;
    assert!(end > base);

    info!("using memory region: 0x{:08X} - 0x{:08X}", base, end);
    assert!(end < RAM_TOP);
    info!("{} bytes are unused", RAM_TOP - end - 1);

    unsafe { ALLOCATOR.init(base, HEAP_SIZE) };
}
