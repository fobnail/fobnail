use core::{
    alloc::{GlobalAlloc, Layout},
    cell::RefCell,
    ptr::{self, NonNull},
};

use cortex_m::interrupt::{free, Mutex};
use linked_list_allocator::Heap;

#[cfg(feature = "heap_debug")]
struct Statistics {
    biggest_allocation: usize,
    smallest_allocation: usize,
    peak_usage: usize,
}

#[cfg(feature = "heap_debug")]
impl Statistics {
    const fn new() -> Self {
        Self {
            biggest_allocation: usize::MIN,
            smallest_allocation: usize::MAX,
            peak_usage: 0,
        }
    }
}

struct Allocator {
    heap: Mutex<RefCell<Heap>>,
    #[cfg(feature = "heap_debug")]
    stats: Mutex<RefCell<Statistics>>,
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
                let mut stats = self.stats.borrow(cs).borrow_mut();
                if layout.size() > stats.biggest_allocation {
                    stats.biggest_allocation = layout.size();
                }

                if layout.size() < stats.smallest_allocation {
                    stats.smallest_allocation = layout.size();
                }

                trace!(
                    "alloc {} bytes ({} free, {} used)",
                    layout.size(),
                    heap.free(),
                    heap.used()
                );
            }

            let p = heap
                .allocate_first_fit(layout)
                .map_or(ptr::null_mut(), |a| a.as_ptr());

            if p.is_null() {
                error!("Failed to allocate object of size {}", layout.size());

                #[cfg(feature = "heap_debug")]
                {
                    let stats = self.stats.borrow(cs).borrow();
                    debug!("Heap statistics:");
                    debug!("smallest allocation: {} bytes", stats.smallest_allocation);
                    debug!("biggest allocation:  {} bytes", stats.biggest_allocation);
                    debug!("peak usage:          {} bytes", stats.peak_usage);
                }
            }

            #[cfg(feature = "heap_debug")]
            {
                let mut stats = self.stats.borrow(cs).borrow_mut();
                let usage = heap.used();
                if usage > stats.peak_usage {
                    stats.peak_usage = usage;
                }
            }

            p
        })
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        free(|cs| {
            let mut heap = self.heap.borrow(cs).borrow_mut();
            #[cfg(feature = "heap_debug")]
            {
                trace!(
                    "free {} bytes ({} free, {} used)",
                    layout.size(),
                    heap.free(),
                    heap.used()
                );
            }

            heap.deallocate(NonNull::new_unchecked(ptr), layout);
        })
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator {
    heap: Mutex::new(RefCell::new(Heap::empty())),
    #[cfg(feature = "heap_debug")]
    stats: Mutex::new(RefCell::new(Statistics::new())),
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
    const HEAP_SIZE: usize = 65536 + 103000;

    let base = cortex_m_rt::heap_start() as usize;
    let end = base + HEAP_SIZE - 1;
    assert!(end > base);

    info!("using memory region: 0x{:08X} - 0x{:08X}", base, end);
    assert!(end < RAM_TOP);
    info!("{} bytes are unused", RAM_TOP - end - 1);

    unsafe { ALLOCATOR.init(base, HEAP_SIZE) };
}
