use std::thread::yield_now;

pub mod ethernet;
pub mod timer;

pub fn init() {
    pretty_env_logger::init();
    timer::init();
}

/// Reduces CPU load by yielding.
pub fn cpu_relax() {
    yield_now()
}
