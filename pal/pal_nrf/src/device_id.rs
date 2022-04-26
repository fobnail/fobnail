use core::mem::transmute;

use hal::pac::FICR;

pub fn device_id() -> u64 {
    // SAFETY: this is the only place where we use FICR registers. Anyway these
    // registers are preprogrammed in factory and we would never write them.
    let ficr: FICR = unsafe { transmute(()) };
    let id_low = ficr.deviceid[0].read().bits();
    let id_high = ficr.deviceid[1].read().bits();

    ((id_high as u64) << 32) | id_low as u64
}
