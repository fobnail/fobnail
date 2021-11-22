use core::convert::TryInto;
use core::mem::MaybeUninit;
use core::time::Duration;

use hal::pac::TIMER2;
use hal::timer::OneShot;

pub type Timer = hal::Timer<TIMER2, OneShot>;

static mut TIMER: MaybeUninit<Timer> = MaybeUninit::uninit();
static mut INITIALIZED: bool = false;

pub fn init(timer: Timer) {
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
