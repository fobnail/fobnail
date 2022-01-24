use super::hfosc;
use cortex_m::interrupt::{CriticalSection, Mutex};
use hal::pac::USBD;
use hal::usbd::{UsbPeripheral, Usbd};
use usb_device::class_prelude::UsbBusAllocator;
use usb_device::device::{UsbDevice, UsbDeviceBuilder, UsbVidPid};
use usbd_ethernet::EthernetDriver;

const FOBNAIL_TOKEN_VID: u16 = 0x1234;
const FOBNAIL_TOKEN_PID: u16 = 0x4321;

const EEM_BUFFER_SIZE: u16 = 1500 * 2;

static mut USB_BUS: Option<UsbBusAllocator<Usbd<UsbPeripheral<'static>>>> = None;
static mut USB_DEV: Option<UsbDevice<'static, Usbd<UsbPeripheral<'static>>>> = None;
static mut USB_EEM: Option<Mutex<EthernetDriver<Usbd<UsbPeripheral<'static>>>>> = None;

pub(crate) static mut ETH_RX_BUF: [u8; EEM_BUFFER_SIZE as usize] = [0u8; EEM_BUFFER_SIZE as usize];
pub(crate) static mut ETH_TX_BUF: [u8; EEM_BUFFER_SIZE as usize] = [0u8; EEM_BUFFER_SIZE as usize];

pub fn init(usbd: USBD) {
    let usb_periph = UsbPeripheral::new(usbd, hfosc());
    unsafe {
        USB_BUS = Some(Usbd::new(usb_periph));
        let usb_bus = USB_BUS.as_ref().unwrap();
        // TODO: should use larger max packet size
        let eth = EthernetDriver::new(usb_bus, 64, &mut ETH_RX_BUF, &mut ETH_TX_BUF);

        let usb_dev =
            UsbDeviceBuilder::new(&usb_bus, UsbVidPid(FOBNAIL_TOKEN_VID, FOBNAIL_TOKEN_PID))
                .manufacturer("Fobnail")
                .product("Fobnail")
                .serial_number("TEST")
                .device_class(0x00)
                .max_packet_size_0(64)
                .build();
        USB_DEV = Some(usb_dev);
        USB_EEM = Some(Mutex::new(eth));
    }
}

pub fn usb_interrupt(cs: &CriticalSection) {
    // SAFETY: usb_dev is never accessed from outside of interrupt handler
    let usb_dev = unsafe {
        USB_DEV
            .as_mut()
            .expect("USB interrupt handler called without an active driver")
    };
    // Mutex cannot ensure there is at most one mutable borrow at compile time
    // see https://github.com/rust-embedded/bare-metal/issues/16
    let eth = unsafe {
        &mut *(get_eem_driver().borrow(cs) as *const EthernetDriver<_> as *mut EthernetDriver<_>)
    };

    if !usb_dev.poll(&mut [eth]) {
        return;
    }
}

pub fn get_eem_driver() -> &'static Mutex<EthernetDriver<'static, Usbd<UsbPeripheral<'static>>>> {
    unsafe { USB_EEM.as_ref().unwrap() }
}
