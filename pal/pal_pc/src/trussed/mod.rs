use std::sync::{Arc, Mutex};

use littlefs2::path::PathBuf;
use trussed::{service::SeedableRng, ClientImplementation, Interchange, Service};

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

pub struct Syscall {
    service: Arc<Mutex<Service<Platform>>>,
}
impl trussed::platform::Syscall for Syscall {
    fn syscall(&mut self) {
        let mut service = self.service.lock().unwrap();
        service.process();
    }
}

/// Initialize Trussed platform and create clients.
pub fn init(client_names: &[&str]) -> Vec<ClientImplementation<Syscall>> {
    let rng = chacha20::ChaCha8Rng::from_rng(rand_core::OsRng).unwrap();
    let store = store::init();
    let ui = UserInterface;
    let platform = Platform::new(rng, store, ui);
    let service = Arc::new(Mutex::new(Service::new(platform)));

    let mut clients = Vec::with_capacity(client_names.len());
    for &client_name in client_names {
        let client = create_client(Arc::clone(&service), client_name);
        clients.push(client);
    }

    clients
}

fn create_client(
    service: Arc<Mutex<Service<Platform>>>,
    client_name: &str,
) -> ClientImplementation<Syscall> {
    let mut locked = service.lock().unwrap();

    if let Some((req, res)) = Interchange::claim() {
        locked
            .add_endpoint(res, PathBuf::from(client_name.as_bytes()))
            // add_endpoint on error returns back responder which does not support
            // Debug trait so we need to drop it in order to use expect()
            .map_err(|_| ())
            .expect("add_endpoint() failed (out of resources)");

        drop(locked);
        ClientImplementation::new(req, Syscall { service })
    } else {
        panic!(
            "Out of resource when creating Trussed client ({})",
            client_name
        );
    }
}

pub fn reset_device(_trussed: &mut trussed::ClientImplementation<crate::trussed::Syscall>) -> ! {
    unimplemented!("Device reset is not implemented in PC PAL")
}
