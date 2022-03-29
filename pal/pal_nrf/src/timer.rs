use core::cell::RefCell;
use core::convert::TryInto;
use core::time::Duration;

use cortex_m::interrupt::{self, Mutex};
use hal::pac::{TIMER2, TIMER3};
use hal::timer::OneShot;

pub type DelayTimer = hal::Timer<TIMER2, OneShot>;

struct FreeTimer {
    /// Timer handle
    timer: TIMER3,
    /// Last timer value (used for overflow checks)
    last: u32,
    /// 64-bit timer value. Stored in timer ticks instead of ms to avoid losing
    /// precision as much as possible.
    value: u64,
}

struct Driver {
    /// Freerunning timer used as a monotonic clock source
    freerunning_timer: RefCell<FreeTimer>,
    delay_timer: RefCell<DelayTimer>,
}

static mut DRIVER: Option<Mutex<Driver>> = None;

// Must match with prescaler (see below)
const FREERUNNING_TIMER_FREQ_KHZ: u32 = 125;

pub(crate) fn init(delay_timer: DelayTimer, freerunning_timer: hal::Timer<TIMER3, OneShot>) {
    let free = freerunning_timer.free();
    free.tasks_stop.write(|w| w.tasks_stop().set_bit());
    free.tasks_clear.write(|w| w.tasks_clear().set_bit());
    free.intenclr.write(|w| unsafe { w.bits(0xffffffff) });
    free.shorts
        .write(|w| w.compare0_clear().disabled().compare0_stop().disabled());
    free.mode.write(|w| w.mode().timer());
    free.bitmode.write(|w| w.bitmode()._32bit());

    // Timer by default runs at 16 MHz. If resolution is set to 32 bit timer
    // will overflow every ~268 seconds. We need only 1 ms precision (1 KHz)
    // but we can divide only by power of 2. Instead set clock to 125 KHz
    // (prescaler 7). Readings will be converted to ms in software.
    //
    // freq = 16 MHz / 2^prescaler
    // NOTE: when updaing prescaler make sure to update
    // FREERUNNING_TIMER_FREQ_KHZ
    free.prescaler.write(|w| unsafe { w.prescaler().bits(7) });
    free.tasks_start.write(|w| w.tasks_start().set_bit());

    let driver = Driver {
        freerunning_timer: RefCell::new(FreeTimer {
            timer: free,
            last: 0,
            value: 0,
        }),
        delay_timer: RefCell::new(delay_timer),
    };

    unsafe { DRIVER = Some(Mutex::new(driver)) }
}

pub fn delay(duration: Duration) {
    // TODO: should use freerunning timer instead.
    // Using freerunning timer will allow us to do delays without disabling
    // interrupts. Concurrent write to the same timer may cause undefined
    // behavior.
    interrupt::free(|cs| {
        // SAFETY: DRIVER is modified only once during initialization
        let driver = unsafe {
            DRIVER
                .as_ref()
                .expect("get_time_ms() called without an active driver")
                .borrow(cs)
        };
        let mut delay_timer = driver.delay_timer.borrow_mut();
        delay_timer.delay(
            TryInto::<u32>::try_into(duration.as_millis()).unwrap() / 1000
                * DelayTimer::TICKS_PER_SECOND,
        );
    })
}

/// Returns a measurement of a monotonically nondecreasing clock in
/// milliseconds.
pub fn get_time_ms() -> i64 {
    let timer = interrupt::free(|cs| {
        // SAFETY: DRIVER is modified only once during initialization
        let driver = unsafe {
            DRIVER
                .as_ref()
                .expect("get_time_ms() called without an active driver")
                .borrow(cs)
        };
        let mut free = driver.freerunning_timer.borrow_mut();

        // Trigger capture each time to copy counter from internal register
        // into CC register which we can read.
        free.timer.tasks_capture[0].write(|w| w.tasks_capture().set_bit());
        let raw_timer = free.timer.cc[0].read().cc().bits();
        // Compute how much timer incremented since last call
        let inc: u64 = if free.last > raw_timer {
            // handle overflow
            (u32::MAX - free.last + raw_timer + 1).into()
        } else {
            (raw_timer - free.last).into()
        };
        free.last = raw_timer;

        free.value += inc;
        free.value
    });

    let timer_ms = timer / FREERUNNING_TIMER_FREQ_KHZ as u64;
    timer_ms as i64
}
