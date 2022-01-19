mod store;

trussed::platform!(
    Platform,
    R: chacha20::ChaCha8Rng,
    S: store::Store,
    UI: UserInterface,
);

pub struct UserInterface;
impl trussed::platform::UserInterface for UserInterface {
    // For now empty, in future can be used for receiving button press events
    // and for controlling leds.
}

/// Initialize Trussed platform
pub fn init() -> Platform {
    use trussed::service::SeedableRng;
    let rng = chacha20::ChaCha8Rng::from_rng(rand_core::OsRng).unwrap();
    let store = store::init();
    let ui = UserInterface;
    Platform::new(rng, store, ui)
}
