#![no_std]
#![feature(alloc_error_handler)]

extern crate nrf52840_hal as hal;

#[macro_use]
extern crate log;

#[macro_use]
extern crate rtt_target;

extern crate alloc;
pub extern crate cortex_m_rt;

use core::mem::MaybeUninit;

use cortex_m::interrupt::free;
use hal::clocks::{ExternalOscillator, Internal, LfOscStopped};
use hal::gpio::{self, Level};
use hal::pac::{interrupt, Interrupt, NVIC, TIMER0};
use hal::timer::{Instance, Periodic};
use hal::Clocks;
use hal::Timer;

pub mod ethernet;
mod heap;
mod led;
mod logger;
mod panic;
pub mod timer;
pub mod trussed;
pub(crate) mod usb;

static mut HFOSC: Option<Clocks<ExternalOscillator, Internal, LfOscStopped>> = None;

pub fn hfosc() -> &'static Clocks<ExternalOscillator, Internal, LfOscStopped> {
    unsafe { HFOSC.as_ref().unwrap() }
}

const TIMER0_PERIOD_MS: u32 = 1;

static mut TIMER0: MaybeUninit<TIMER0> = MaybeUninit::uninit();
// when timer0 fired for the last time
static mut TIMER0_LAST: u64 = 0;

#[interrupt]
#[allow(non_snake_case)]
fn TIMER0() {
    free(|cs| {
        unsafe {
            let now = timer::get_time_ms() as u64;
            let delay = now - TIMER0_LAST;
            let maximum = TIMER0_PERIOD_MS as u64 + 10;
            if delay > maximum {
                error!("");
                error!("");
                error!("");
                error!("To big delay between timer0 interrupts (USB may break)");
                error!(
                    "delay: {} ms (+{} ms above maximum)",
                    delay,
                    delay - maximum
                );
                error!("");
                error!("");
                error!("");
            }

            TIMER0_LAST = now;
        }

        usb::usb_interrupt(cs);

        // SAFETY: TIMER0 global must be properly initialized before interrupts
        // are enabled
        let timer0 = unsafe { TIMER0.assume_init_ref() };
        // Clear interrupt flag
        timer0.as_timer0().events_compare[0].reset();
    })
}

pub fn init() {
    rtt_target::rtt_init_print!();
    logger::init();
    heap::init();

    let periph = hal::pac::Peripherals::take().unwrap();
    let clocks = Clocks::new(periph.CLOCK);
    // Enable high frequency (64 MHz) clock, USB needs this
    unsafe { HFOSC = Some(clocks.enable_ext_hfosc()) };

    let rng = periph.RNG;
    let nvmc = periph.NVMC;
    unsafe {
        trussed::drivers::init(rng);
    }

    let port0 = gpio::p0::Parts::new(periph.P0);

    // Initialize timers
    // set TIMER0 to poll USB every 10 ms
    let timer0 = periph.TIMER0;
    unsafe {
        TIMER0 = MaybeUninit::new(timer0);
        let timer0 = TIMER0.assume_init_ref();
        timer0.set_periodic();
        timer0.enable_interrupt();
        timer0.timer_start(Timer::<TIMER0, Periodic>::TICKS_PER_SECOND / 1000 * TIMER0_PERIOD_MS);
    }

    // set TIMER1 to blink leds every 1 second
    led::init(
        periph.TIMER1,
        port0.p0_06.into_push_pull_output(Level::Low),
        port0.p0_08.into_push_pull_output(Level::Low),
    );

    // configure TIMER2 to be used for delays
    // configure TIMER3 as a freerunning monotonic counter
    timer::init(
        Timer::one_shot(periph.TIMER2),
        Timer::one_shot(periph.TIMER3),
    );

    trussed::storage_init(nvmc);

    usb::init(periph.USBD);

    unsafe {
        NVIC::unmask(Interrupt::TIMER0);
    }
}

/// Reduces CPU load by suspending execution till next interrupt arrives.
pub fn cpu_relax() {
    cortex_m::asm::wfi();
}
