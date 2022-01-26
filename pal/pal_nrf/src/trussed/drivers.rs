use hal::pac::RNG;

pub struct Drivers {
    pub(crate) rng: RNG,
}

static mut DRIVERS: Option<Drivers> = None;

pub(crate) unsafe fn init(rng: RNG) {
    DRIVERS = Some(Drivers { rng })
}

pub(crate) unsafe fn get() -> Drivers {
    DRIVERS.take().unwrap()
}
