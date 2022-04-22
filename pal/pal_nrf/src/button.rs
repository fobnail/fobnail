use cortex_m::interrupt::{free, Mutex};
use hal::{
    gpio::{p1::P1_06, Input, PullUp},
    prelude::InputPin,
};

pub(crate) type ButtonPin = P1_06<Input<PullUp>>;

struct Driver {
    pin: ButtonPin,
}

static mut DRIVER: Option<Mutex<Driver>> = None;

pub(crate) fn init(pin: ButtonPin) {
    let driver = Driver { pin };
    unsafe { DRIVER = Some(Mutex::new(driver)) }
}

pub fn is_pressed() -> bool {
    free(|cs| {
        // SAFETY: see notes in ethernet.rs
        unsafe fn into_mutable_ref<T>(r: &T) -> &mut T {
            &mut *(r as *const T as *mut T)
        }

        // SAFETY: DRIVER is modified only once during initialization
        let driver = unsafe {
            into_mutable_ref(
                DRIVER
                    .as_ref()
                    .expect("control() called without an active driver")
                    .borrow(cs),
            )
        };

        driver.pin.is_low().unwrap()
    })
}
