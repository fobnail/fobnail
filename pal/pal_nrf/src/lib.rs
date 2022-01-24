#![no_std]
#![feature(alloc_error_handler)]

extern crate nrf52840_hal as hal;

#[macro_use]
extern crate log;

#[macro_use]
extern crate rtt_target;

pub extern crate cortex_m;
pub extern crate cortex_m_rt;

extern crate alloc;

use core::mem::MaybeUninit;

use cortex_m::interrupt::free;
use hal::clocks::{ExternalOscillator, Internal, LfOscStopped};
use hal::gpio::{self, Level};
use hal::pac::{interrupt, Interrupt, NVIC, TIMER0};
use hal::timer::{Instance, Periodic};
use hal::Clocks;
use hal::Timer;

mod c_compat;
pub mod ethernet;
mod heap;
mod led;
mod logger;
mod monotonic;
mod panic;
pub mod timer;
pub mod trussed;
pub mod usb;

static mut HFOSC: Option<Clocks<ExternalOscillator, Internal, LfOscStopped>> = None;

pub fn hfosc() -> &'static Clocks<ExternalOscillator, Internal, LfOscStopped> {
    unsafe { HFOSC.as_ref().unwrap() }
}

const TIMER0_PERIOD_MS: u32 = 10;

static mut TIMER0: MaybeUninit<TIMER0> = MaybeUninit::uninit();
/*#[interrupt]
#[allow(non_snake_case)]
fn TIMER0() {
    free(|cs| {
        usb::usb_interrupt(cs);

        // SAFETY: TIMER0 global must be properly initialized before interrupts
        // are enabled
        let timer0 = unsafe { TIMER0.assume_init_ref() };
        timer0.timer_start(Timer::<TIMER0, Periodic>::TICKS_PER_SECOND / 1000 * TIMER0_PERIOD_MS);
    })
}*/

mod ext {
    extern "Rust" {
        pub fn fw_main() -> !;
    }
}

#[rtic::app(device = hal::pac, peripherals = true)]
mod app {
    use hal::{
        clocks::{ExternalOscillator, Internal, LfOscStopped},
        pac::USBD,
        timer::Instance,
        usbd::{UsbPeripheral, Usbd},
        Clocks,
    };
    use usb_device::class_prelude::UsbBusAllocator;
    use usbd_ethernet::EthernetDriver;

    #[shared]
    struct Shared {
        eth: EthernetDriver<'static, Usbd<UsbPeripheral<'static>>>,
    }

    #[local]
    struct Local {
        //usb: UsbBusAllocator<Usbd<UsbPeripheral<'static>>>,
    }

    #[init(
        local = [
            hfosc: Option<Clocks<ExternalOscillator, Internal, LfOscStopped>> = None
        ],
        shared = [
            usb
        ]
    )]
    fn init(cx: init::Context) -> (Shared, Local, init::Monotonics) {
        rtt_target::rtt_init_print!();
        super::logger::init();
        super::heap::init();

        let clocks = Clocks::new(cx.device.CLOCK);
        *cx.local.hfosc = Some(clocks.enable_ext_hfosc());

        let timer0 = cx.device.TIMER0;
        timer0.set_oneshot();
        timer0.enable_interrupt();
        timer0.timer_start(
            hal::Timer::<hal::pac::TIMER0, hal::timer::Periodic>::TICKS_PER_SECOND / 1000
                * super::TIMER0_PERIOD_MS,
        );

        let usb_periph = UsbPeripheral::new(cx.device.USBD, cx.local.hfosc.as_ref().unwrap());
        *cx.local.usb = Some(Usbd::new(usb_periph));
        let eth = unsafe {
            EthernetDriver::new(
                cx.local.usb.as_ref().unwrap(),
                64,
                &mut super::usb::ETH_TX_BUF[..],
                &mut super::usb::ETH_RX_BUF[..],
            )
        };

        (Shared { eth }, Local {}, init::Monotonics())
    }

    #[task(binds = TIMER0)]
    fn usb_task(_: usb_task::Context) {
        info!("USB interrupt")
    }

    #[idle]
    fn runmain(_: runmain::Context) -> ! {
        unsafe { super::ext::fw_main() }
    }
}

/*pub fn init() {
    //rtt_target::rtt_init_print!();

    let periph = hal::pac::Peripherals::take().unwrap();
    let clocks = Clocks::new(periph.CLOCK);
    // Enable high frequency (64 MHz) clock, USB needs this
    unsafe { HFOSC = Some(clocks.enable_ext_hfosc()) };

    let port0 = gpio::p0::Parts::new(periph.P0);

    // Initialize timers
    // set TIMER0 to poll USB every 10 ms
    let timer0 = Timer::periodic(periph.TIMER0).free();
    unsafe {
        TIMER0 = MaybeUninit::new(timer0);
        let timer0 = TIMER0.assume_init_ref();
        // Periodic mode does not automatically clear counter, which causes timer to
        // fire immediatelly after interrupt handler returns
        timer0.set_oneshot();
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
    timer::init(
        Timer::one_shot(periph.TIMER2),
        Timer::one_shot(periph.TIMER3),
    );

    let rng = hal::Rng::new(periph.RNG);
    unsafe { trussed::drivers::init(rng) };

    usb::init(periph.USBD);

    unsafe {
        NVIC::unmask(Interrupt::TIMER0);
        NVIC::unmask(Interrupt::TIMER1);
        NVIC::unmask(Interrupt::USBD);
    }
}*/

/// Reduces CPU load by suspending execution till next interrupt arrives.
pub fn cpu_relax() {
    cortex_m::asm::wfi();
}
