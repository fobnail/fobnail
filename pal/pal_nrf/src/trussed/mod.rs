use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use littlefs2::path::PathBuf;
use trussed::{service::SeedableRng, ClientImplementation, Interchange, Service};

pub(crate) mod drivers;
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
    service: Rc<RefCell<Service<Platform>>>,
}
impl trussed::platform::Syscall for Syscall {
    fn syscall(&mut self) {
        let mut service = self.service.borrow_mut();
        service.process();
    }
}

/// Initialize Trussed platform and create clients.
pub fn init(client_names: &[&str]) -> Vec<ClientImplementation<Syscall>> {
    let drivers::Drivers { rng } = unsafe { drivers::get() };
    let rng = hal::Rng::new(rng);

    let rng = chacha20::ChaCha8Rng::from_rng(rng).unwrap();
    let store = store::init();
    let ui = UserInterface;
    let platform = Platform::new(rng, store, ui);
    let service = Rc::new(RefCell::new(Service::new(platform)));

    let mut clients = Vec::with_capacity(client_names.len());
    for &client_name in client_names {
        let client = create_client(Rc::clone(&service), client_name);
        clients.push(client);
    }

    clients
}

fn create_client(
    service: Rc<RefCell<Service<Platform>>>,
    client_name: &str,
) -> ClientImplementation<Syscall> {
    let mut service_borrowed = service.borrow_mut();

    if let Some((req, res)) = Interchange::claim() {
        service_borrowed
            .add_endpoint(res, PathBuf::from(client_name.as_bytes()))
            // add_endpoint on error returns back responder which does not support
            // Debug trait so we need to drop it in order to use expect()
            .map_err(|_| ())
            .expect("add_endpoint() failed (out of resources)");

        drop(service_borrowed);
        ClientImplementation::new(req, Syscall { service })
    } else {
        panic!(
            "Out of resource when creating Trussed client ({})",
            client_name
        );
    }
}
