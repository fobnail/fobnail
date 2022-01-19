use std::thread::yield_now;

pub mod ethernet;
pub mod timer;
pub mod trussed;

pub fn init() {
    pretty_env_logger::init_custom_env("FOBNAIL_LOG");
    timer::init();
}

/// Reduces CPU load by yielding.
pub fn cpu_relax() {
    yield_now()
}
