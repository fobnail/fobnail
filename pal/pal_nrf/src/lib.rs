#![no_std]
#![feature(alloc_error_handler)]
#![feature(type_alias_impl_trait)]

extern crate nrf52840_hal as hal;

#[macro_use]
extern crate log;

#[macro_use]
extern crate rtt_target;

extern crate alloc;
pub extern crate cortex_m_rt;

use embassy::executor::Spawner;
use hal::clocks::{ExternalOscillator, Internal, LfOscStopped};
use hal::gpio::{self, Level};
use hal::pac::{
    nvmc::icachecnf::{CACHEEN_A, CACHEPROFEN_A},
    Interrupt, NVIC,
};

use hal::Clocks;
use hal::Timer;

pub use device_id::*;
pub use embassy_net;
pub use embassy_nrf;
pub use embassy_util;
pub use pal_macros::*;

pub extern crate embassy_executor as embassy;

pub mod button;
mod device_id;
mod heap;
pub mod led;
mod logger;
pub mod net;
mod panic;
pub mod timer;
pub mod trussed;
pub(crate) mod usb;

static mut HFOSC: Option<Clocks<ExternalOscillator, Internal, LfOscStopped>> = None;

pub fn hfosc() -> &'static Clocks<ExternalOscillator, Internal, LfOscStopped> {
    unsafe { HFOSC.as_ref().unwrap() }
}

pub fn init(spawner: Spawner) {
    embassy_nrf::init(Default::default());

    rtt_target::rtt_init_print!();
    logger::init();
    heap::init();

    let periph = hal::pac::Peripherals::take().unwrap();
    let clocks = Clocks::new(periph.CLOCK);
    // Enable high frequency (64 MHz) clock, USB needs this
    unsafe { HFOSC = Some(clocks.enable_ext_hfosc()) };

    let rng = periph.RNG;
    let nvmc = periph.NVMC;
    nvmc.icachecnf.modify(|_, w| {
        // Enabling I-Cache can increase overall performance but also can reduce
        // or avoid halting CPU during NVMC writes - if at time of write CPU
        // executes from I-Cache it won't be halted.
        //
        // Disable cache profiling, right now we are not using it.
        w.cacheen()
            .variant(CACHEEN_A::ENABLED)
            .cacheprofen()
            .variant(CACHEPROFEN_A::DISABLED)
    });

    unsafe { trussed::drivers::init(rng) };

    let port0 = gpio::p0::Parts::new(periph.P0);
    let port1 = gpio::p1::Parts::new(periph.P1);

    // initialize LEDs
    led::init(
        port0.p0_06.into_push_pull_output(Level::High),
        port0.p0_08.into_push_pull_output(Level::High),
    );

    // configure TIMER2 to be used for delays
    // configure TIMER3 as a freerunning monotonic counter
    timer::init(
        Timer::one_shot(periph.TIMER2),
        Timer::one_shot(periph.TIMER3),
    );

    button::init(port1.p1_06.into_pullup_input());

    // Initialize Trussed before USB. Trussed formats internal storage which
    // takes some time, now when we have partial read implemented CPU is halted
    // max 1 ms during page erases so it shouldn't break USB anymore, but better
    // be safe.
    trussed::storage_init(nvmc);

    usb::init(spawner, periph.USBD);
    net::init(spawner);

    unsafe {
        NVIC::unmask(Interrupt::TIMER0);
    }
}

/// Reduces CPU load by suspending execution till next interrupt arrives.
pub fn cpu_relax() {
    cortex_m::asm::wfi();
}
