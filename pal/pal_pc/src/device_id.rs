use std::env;

static mut ID: u64 = 0;

pub(crate) fn init() {
    // Initialize device ID early so we detect any error on startup.
    if let Ok(id) = env::var("FOBNAIL_DEVICE_ID") {
        let id = u64::from_str_radix(&id, 16).expect("Invalid chip ID");
        unsafe { ID = id };
    }
}

pub fn device_id() -> u64 {
    unsafe { ID }
}
