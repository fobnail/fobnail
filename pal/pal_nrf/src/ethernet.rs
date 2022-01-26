use core::cell::RefCell;

use crate::{app::public_resources::EthDriver, Pal};
use hal::usbd::{UsbPeripheral, Usbd};
use rtic::Mutex;
use smoltcp::wire::EthernetAddress;
use usbd_ethernet::{BorrowDriver, EthernetDriver};

pub type UsbDriver = Usbd<UsbPeripheral<'static>>;
pub type Phy<'a> = usbd_ethernet::Phy<'a, UsbDriver, Guard<EthDriver<'a>>>;

pub struct Guard<T> {
    mutex: RefCell<T>,
}

impl<T> Guard<T>
where
    T: Mutex,
{
    pub(crate) fn new(mutex: T) -> Self {
        Self {
            mutex: RefCell::new(mutex),
        }
    }
}

impl<'a, T> BorrowDriver<EthernetDriver<'a, UsbDriver>> for Guard<T>
where
    T: Mutex<T = EthernetDriver<'static, UsbDriver>>,
{
    fn borrow<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&EthernetDriver<'a, UsbDriver>) -> R,
    {
        let mut mutex = self.mutex.borrow_mut();
        mutex.lock(|x| f(x))
    }

    fn borrow_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut EthernetDriver<'a, UsbDriver>) -> R,
    {
        /*let mut mutex = self.mutex.borrow_mut();
        mutex.lock(|x| f(x));*/
        todo!()
    }
}

impl<'a> Pal<'a> {
    /// Returns MAC address which should be used when building interface using
    /// `EthernetInterfaceBuilder`
    pub fn get_ethernet_address(&self) -> EthernetAddress {
        // FIXME: every device should have it's own unique address.
        // Maybe we can derive it from some sort hardware adress stored in nRF chip?
        EthernetAddress([0x10, 0x20, 0x30, 0x40, 0x50, 0x60])
    }
}
