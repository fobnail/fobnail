use std::thread::yield_now;

pub mod button;
mod device_id;
pub mod ethernet;
pub mod led;
pub mod timer;
pub mod trussed;

pub use device_id::*;
pub use embassy;
pub use pal_macros::*;

/// Reduces CPU load by yielding.
pub fn cpu_relax() {
    yield_now()
}

pub fn init() {
    pretty_env_logger::init_custom_env("FOBNAIL_LOG");
    timer::init();
    device_id::init();
}
