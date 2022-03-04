use hal::pac::{NVMC, RNG};

pub struct Drivers {
    pub(crate) rng: RNG,
    pub(crate) nvmc: NVMC,
}

static mut DRIVERS: Option<Drivers> = None;

pub(crate) unsafe fn init(rng: RNG, nvmc: NVMC) {
    DRIVERS = Some(Drivers { rng, nvmc })
}

pub(crate) unsafe fn get() -> Drivers {
    DRIVERS.take().unwrap()
}
