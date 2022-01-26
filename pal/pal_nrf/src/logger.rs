use log::{LevelFilter, Log};

pub struct Logger;
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
