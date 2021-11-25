use std::mem::MaybeUninit;
use std::sync::Once;
use std::thread::sleep;
use std::time::{Duration, Instant};

static INIT: Once = Once::new();
static mut BOOT_TIME: MaybeUninit<Instant> = MaybeUninit::uninit();

pub(crate) fn init() {
    INIT.call_once(|| unsafe {
        BOOT_TIME = MaybeUninit::new(Instant::now());
    })
}

pub fn delay(duration: Duration) {
    assert!(
        INIT.is_completed(),
        "delay() called without an active driver"
    );
    sleep(duration)
}

pub fn get_time_ms() -> i64 {
    assert!(
        INIT.is_completed(),
        "get_time_ms() called without an active driver"
    );
    unsafe {
        Instant::now()
            .duration_since(BOOT_TIME.assume_init())
            .as_millis()
            .try_into()
            .unwrap()
    }
}
