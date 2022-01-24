use hal::Rng;

pub(super) struct Drivers {
    pub rng: Rng,
}

pub(super) static mut DRIVERS: Option<Drivers> = None;

pub(crate) unsafe fn init(rng: Rng) {
    // SAFETY: called only once during PAL initialization
    DRIVERS = Some(Drivers { rng })
}
