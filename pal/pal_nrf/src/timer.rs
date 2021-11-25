use core::convert::TryInto;
use core::mem::MaybeUninit;
use core::time::Duration;

use hal::pac::TIMER2;
use hal::timer::OneShot;

pub type Timer = hal::Timer<TIMER2, OneShot>;

static mut TIMER: MaybeUninit<Timer> = MaybeUninit::uninit();
static mut INITIALIZED: bool = false;

pub(crate) fn init(timer: Timer) {
    let _timer = unsafe {
        TIMER = MaybeUninit::new(timer);
        INITIALIZED = true;
        TIMER.assume_init_ref()
    };
}

pub fn delay(duration: Duration) {
    unsafe {
        if !INITIALIZED {
            panic!("delay() called before driver got initialized");
        }
        let timer = TIMER.assume_init_mut();
        timer.delay(
            TryInto::<u32>::try_into(duration.as_millis()).unwrap() / 1000
                * Timer::TICKS_PER_SECOND,
        );
    }
}

/// Returns a measurement of a monotonically nondecreasing clock in
/// milliseconds.
pub fn get_time_ms() -> i64 {
    // TODO: implement this
    // Smoltcp requires a monotonic clock for timestamps, but so far it works
    // with a dummy implementation
    //
    // Soon this function may (and probably will) be used by other components.

    0
}
