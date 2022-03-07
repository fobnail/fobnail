use cortex_m::interrupt::free;
use hal::usbd::{UsbPeripheral, Usbd};
use smoltcp::wire::EthernetAddress;

use usbd_ethernet::{BorrowDriver, EthernetDriver, Phy};

type UsbDriver = Usbd<UsbPeripheral<'static>>;

pub struct Guard;
impl<'a> BorrowDriver<EthernetDriver<'a, UsbDriver>> for Guard {
    fn borrow<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&EthernetDriver<'a, UsbDriver>) -> R,
    {
        free(|cs| {
            let driver = crate::usb::get_eem_driver().borrow(cs);
            f(driver)
        })
    }

    fn borrow_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut EthernetDriver<'a, UsbDriver>) -> R,
    {
        unsafe fn into_mutable_ref<T>(r: &T) -> &mut T {
            &mut *(r as *const T as *mut T)
        }
        free(|cs| {
            // Mutex from cortex_m crate cannot ensure at compile time there is
            // at most one mutable borrow, so it does not provide borrow_mut()
            // method.
            //
            // For example this would succeed, where it shouldn't
            // let ref1 = driver.borrow_mut(cs);
            // let ref2 = driver.borrow_mut(cs);
            // let ref3 = driver.borrow_mut(cs);
            //
            // Code below is safe as long as we don't make multiple references
            // ourselves. For more information see:
            // https://github.com/rust-embedded/cortex-m/issues/224
            // https://github.com/rust-embedded/bare-metal/issues/16
            let driver = unsafe { into_mutable_ref(crate::usb::get_eem_driver().borrow(cs)) };
            f(driver)
        })
    }
}

/// Creates Ethernet PHY which we use with smoltcp
pub fn create_phy() -> Phy<'static, UsbDriver, Guard> {
    Phy::new(Guard)
}

/// Returns MAC address which should be used when building interface using
/// `EthernetInterfaceBuilder`
pub fn get_ethernet_address() -> EthernetAddress {
    // FIXME: every device should have it's own unique address.
    // Maybe we can derive it from some sort hardware address stored in nRF chip?
    EthernetAddress([0x10, 0x20, 0x30, 0x40, 0x50, 0x60])
}
