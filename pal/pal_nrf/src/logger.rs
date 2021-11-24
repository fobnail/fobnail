use core::mem::MaybeUninit;

use log::{LevelFilter, Log};

struct Logger;
impl Log for Logger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        rprintln!(
            "{} {} > {}",
            record.level().as_str(),
            record.target(),
            record.args()
        );
    }

    fn flush(&self) {}
}

static mut LOGGER: MaybeUninit<Logger> = MaybeUninit::uninit();

pub fn init() {
    unsafe {
        LOGGER = MaybeUninit::new(Logger {});

        if let Err(e) = log::set_logger(LOGGER.assume_init_ref()) {
            rprintln!("Failed to initialize logging: {}", e);
        }
    }

    log::set_max_level(LevelFilter::Trace);
}
