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
            self.heap.borrow(cs).borrow_mut().init(base, len);
        })
    }
}

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        free(|cs| {
            self.heap
                .borrow(cs)
                .borrow_mut()
                .allocate_first_fit(layout)
                .map_or(ptr::null_mut(), |a| a.as_ptr())
        })
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        free(|cs| {
            self.heap
                .borrow(cs)
                .borrow_mut()
                .deallocate(NonNull::new_unchecked(ptr), layout)
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

    let base = cortex_m_rt::heap_start();
    let heap_size = RAM_TOP - (base as usize);

    unsafe { ALLOCATOR.init(base as usize, heap_size) };
    debug!("Created heap with size {}", heap_size);
}
