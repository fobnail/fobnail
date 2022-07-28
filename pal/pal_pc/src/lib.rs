#![feature(type_alias_impl_trait)]

use std::thread::yield_now;

pub mod button;
mod device_id;
pub mod led;
pub mod net;
pub mod timer;
pub mod trussed;

pub use device_id::*;
pub use embassy;
pub use embassy_net;
pub use pal_macros::*;

use embassy::executor::Spawner;

/// Reduces CPU load by yielding.
pub fn cpu_relax() {
    yield_now()
}

pub fn init(spawner: Spawner) {
    pretty_env_logger::init_custom_env("FOBNAIL_LOG");
    timer::init();
    device_id::init();

    net::init(spawner);
}
