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

use cortex_m::interrupt::free;
use hal::usbd::{UsbPeripheral, Usbd};

mod c_compat;
pub mod ethernet;
mod heap;
mod logger;
mod panic;
pub mod trussed;

use usbd_ethernet::EthernetDriver;

pub use app::Pal;
extern "Rust" {
    // Hack to call into main
    // RTIC always generates entry point so we cant have entry point in app and
    // call to PAL. To remove this hack, PAL should be turned into executable to
    // which we link application, not the other way.
    pub(crate) fn fw_main(pal: Pal) -> !;
}

#[rtic::app(
    device = hal::pac,
    peripherals = true,
    // nRF52840 provides 6 software interrupts which gives 6 priority levels.
    dispatchers = [
        SWI0_EGU0,
        SWI1_EGU1,
        SWI2_EGU2,
        SWI3_EGU3,
        SWI4_EGU4,
        SWI5_EGU5
    ]
)]
mod app {
    use alloc::boxed::Box;
    use hal::{
        clocks::{ExternalOscillator, Internal, LfOscStopped},
        pac::{Interrupt, TIMER0, USBD},
        timer::Instance,
        usbd::{UsbPeripheral, Usbd},
        Clocks, Timer,
    };
    use log::LevelFilter;
    use systick_monotonic::*;
    use usb_device::{
        class_prelude::UsbBusAllocator,
        device::{UsbDevice, UsbDeviceBuilder, UsbVidPid},
    };
    use usbd_ethernet::EthernetDriver;

    /// Contains resources that are exported outside of PAL.
    pub mod public_resources {
        pub use super::shared_resources::eth_that_needs_to_be_locked as EthDriver;
    }

    const TIMER0_PERIOD_MS: u32 = 10;
    const FOBNAIL_TOKEN_VID: u16 = 0x1234;
    const FOBNAIL_TOKEN_PID: u16 = 0x4321;
    const EEM_BUFFER_SIZE: u16 = 1500 * 2;

    pub struct Pal<'a> {
        pub eth: crate::ethernet::Phy<'a>,
    }

    #[monotonic(binds = SysTick, default = true)]
    type MonoTimer = Systick<100>; // 100 Hz

    #[shared]
    struct Shared {
        eth: EthernetDriver<'static, Usbd<UsbPeripheral<'static>>>,
    }

    #[local]
    struct Local {
        usb_dev: UsbDevice<'static, Usbd<UsbPeripheral<'static>>>,
        timer0: TIMER0,
    }

    #[init(
        local = [
            logger: crate::logger::Logger = crate::logger::Logger {},
            hfosc: Option<Clocks<ExternalOscillator, Internal, LfOscStopped>> = None,
            usb: Option<UsbBusAllocator<Usbd<UsbPeripheral<'static>>>> = None,
            eth_rx_buf: [u8; EEM_BUFFER_SIZE as usize] = [0u8; EEM_BUFFER_SIZE as usize],
            eth_tx_buf: [u8; EEM_BUFFER_SIZE as usize] = [0u8; EEM_BUFFER_SIZE as usize],
        ]
    )]
    fn init(cx: init::Context) -> (Shared, Local, init::Monotonics) {
        rtt_target::rtt_init_print!();
        log::set_logger(cx.local.logger).unwrap();
        log::set_max_level(LevelFilter::Trace);
        unsafe { crate::heap::init() };

        let clocks = Clocks::new(cx.device.CLOCK);
        *cx.local.hfosc = Some(clocks.enable_ext_hfosc());

        // SysTick is clocked at the same frequency that CPU is (64 MHz)
        let mono = Systick::new(cx.core.SYST, 64_000_000);

        // Configure TIMER0 for polling USB
        let timer0 = cx.device.TIMER0;
        timer0.set_periodic();
        timer0.enable_interrupt();
        timer0.timer_start(
            Timer::<TIMER0, hal::timer::Periodic>::TICKS_PER_SECOND / 1000 * TIMER0_PERIOD_MS,
        );

        let usb_periph = UsbPeripheral::new(cx.device.USBD, cx.local.hfosc.as_ref().unwrap());
        *cx.local.usb = Some(Usbd::new(usb_periph));
        let eth = EthernetDriver::new(
            cx.local.usb.as_ref().unwrap(),
            64,
            &mut cx.local.eth_tx_buf[..],
            &mut cx.local.eth_rx_buf[..],
        );

        let usb_dev = UsbDeviceBuilder::new(
            cx.local.usb.as_ref().unwrap(),
            UsbVidPid(FOBNAIL_TOKEN_VID, FOBNAIL_TOKEN_PID),
        )
        .manufacturer("Fobnail")
        .product("Fobnail")
        .serial_number("TEST")
        .device_class(0x00)
        .max_packet_size_0(64)
        .build();

        (
            Shared { eth },
            Local { usb_dev, timer0 },
            init::Monotonics(mono),
        )
    }

    #[task(
        binds = TIMER0,
        local = [
            usb_dev,
            timer0,
        ],
        shared = [ eth ],
        priority = 2
    )]
    fn usb_interrupt(mut cx: usb_interrupt::Context) {
        //log::info!("USB interrupt");
        cx.shared
            .eth
            .lock(|eth| while cx.local.usb_dev.poll(&mut [eth]) {});

        // Clear interrupt flag
        let timer0 = cx.local.timer0;
        timer0.as_timer0().events_compare[0].reset();
    }

    #[idle(shared = [ eth ])]
    fn fobnail_main(mut cx: fobnail_main::Context) -> ! {
        let eth = usbd_ethernet::Phy::new(crate::ethernet::Guard::new(cx.shared.eth));
        let pal = Pal { eth };
        unsafe { super::fw_main(pal) }
    }
}

/// Reduces CPU load by suspending execution till next interrupt arrives.
pub fn cpu_relax() {
    // cortex_m::asm::wfi();
}
