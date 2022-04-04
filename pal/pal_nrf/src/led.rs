use cortex_m::interrupt::{free, Mutex};
use hal::{
    gpio::{
        p0::{P0_06, P0_08},
        Output, PushPull,
    },
    prelude::OutputPin,
};
use void::Void;

pub(crate) type GreenPin = P0_06<Output<PushPull>>;
pub(crate) type RedPin = P0_08<Output<PushPull>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Led {
    Green,
    Red,
}

struct Driver {
    green: GreenPin,
    red: RedPin,
}

impl Driver {
    fn led(&mut self, led: Led) -> &mut dyn OutputPin<Error = Void> {
        match led {
            Led::Green => &mut self.green,
            Led::Red => &mut self.red,
        }
    }
}

static mut DRIVER: Option<Mutex<Driver>> = None;

pub(crate) fn init(green: GreenPin, red: RedPin) {
    let driver = Driver { green, red };
    unsafe { DRIVER = Some(Mutex::new(driver)) }
}

pub fn control(led: Led, on: bool) {
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

        let pin = driver.led(led);
        if on {
            pin.set_low().unwrap();
        } else {
            pin.set_high().unwrap();
        }
    })
}
