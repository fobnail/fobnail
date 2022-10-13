#[derive(Debug, PartialEq, Eq)]
pub enum LedState {
    Off,
    TokenNotProvisioned,
    TokenProvisioningComplete,
    TokenWaiting,
    PlatformProvisioningOk,
    AttestationOk,
    AttestationFailed,
}

pub fn control(state: LedState) {
    // since on PC there is no LED we could control this is no-op kept only to
    // uniform PAL interface between pal_nrf and pal_pc

    log::info!("LED controller state: {:?}", state);
}
