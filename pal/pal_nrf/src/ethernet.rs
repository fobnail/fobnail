use cortex_m::interrupt::{free, Mutex};
use hal::usbd::{UsbPeripheral, Usbd};
use smoltcp::phy::{Checksum, ChecksumCapabilities, Device, DeviceCapabilities, RxToken, TxToken};
use smoltcp::time::Instant;
use smoltcp::wire::EthernetAddress;
use usb_device::bus::UsbBus;

use eem::EemDriver;

/// Creates Ethernet PHY which we use with smoltcp
pub fn create_phy() -> Phy<'static, Usbd<UsbPeripheral<'static>>> {
    Phy::new(crate::usb::get_eem_driver())
}

/// Returns MAC address which should be used when building interface using
/// `EthernetInterfaceBuilder`
pub fn get_ethernet_address() -> EthernetAddress {
    // FIXME: every device should have it's own unique address.
    // Maybe we can derive it from some sort hardware adress stored in nRF chip?
    EthernetAddress([0x10, 0x20, 0x30, 0x40, 0x50, 0x60])
}

pub struct Phy<'a, B>
where
    B: UsbBus,
{
    parent: &'a Mutex<EemDriver<'a, B>>,
}

impl<'a, B> Phy<'a, B>
where
    B: UsbBus,
{
    pub fn new(parent: &'a Mutex<EemDriver<'a, B>>) -> Self {
        Self { parent }
    }
}

impl<'d, 'a: 'd, B> Device<'d> for Phy<'a, B>
where
    B: UsbBus,
{
    type RxToken = &'d Self;
    type TxToken = &'d Self;

    fn receive(&'d mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        if free(|cs| self.parent.borrow(cs).incoming_packet()) {
            Some((self, self))
        } else {
            None
        }
    }

    fn transmit(&'d mut self) -> Option<Self::TxToken> {
        Some(self)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1500;
        caps.max_burst_size = None;
        caps.checksum = ChecksumCapabilities::ignored();
        caps.checksum.ipv4 = Checksum::Tx;
        caps.checksum.icmpv4 = Checksum::Tx;
        caps.checksum.udp = Checksum::Tx;
        caps.checksum.tcp = Checksum::Tx;
        caps
    }
}

impl<'a, B: UsbBus> RxToken for &'a Phy<'_, B> {
    fn consume<R, F>(self, _timestamp: Instant, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        free(|cs| {
            // Mutex cannot ensure there is at most one mutable borrow at compile time
            // see https://github.com/rust-embedded/bare-metal/issues/16
            let eem = unsafe {
                &mut *(self.parent.borrow(cs) as *const EemDriver<'_, B> as *mut EemDriver<'_, B>)
            };

            if let Some(result) = eem.read_packet(f) {
                return result;
            } else {
                // We should never reach this - PHY driver checks if there is
                // any incoming packet before creating RxToken
                error!("BUG! RX token failed to receive Ethernet packet");

                return Err(smoltcp::Error::Exhausted);
            }
        })
    }
}

impl<'a, B: UsbBus> TxToken for &'a Phy<'_, B> {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        free(|cs| {
            let eem = unsafe {
                &mut *(self.parent.borrow(cs) as *const EemDriver<'_, B> as *mut EemDriver<'_, B>)
            };

            if let Some(result) = eem.prepare_packet(len, f) {
                return result;
            } else {
                return Err(smoltcp::Error::Exhausted);
            }
        })
    }
}
