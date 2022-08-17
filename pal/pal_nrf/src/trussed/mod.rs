use alloc::sync::Arc;
use alloc::vec::Vec;
use cortex_m::peripheral::SCB;
use embassy_util::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex};

use hal::pac::NVMC;
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
    service: Arc<Mutex<CriticalSectionRawMutex, Service<Platform>>>,
}
impl trussed::platform::Syscall for Syscall {
    fn syscall(&mut self) {
        loop {
            if let Ok(mut service) = self.service.try_lock() {
                service.process();
                break;
            }
        }
    }
}

static mut STORE: Option<store::Store> = None;

pub(crate) fn storage_init(nvmc: NVMC) {
    unsafe {
        let store = store::init(nvmc);
        STORE = Some(store);
    }
}

/// Initialize Trussed platform and create clients.
pub fn init(client_names: &[&str]) -> Vec<ClientImplementation<Syscall>> {
    let drivers::Drivers { rng } = unsafe { drivers::get() };
    let rng = hal::Rng::new(rng);

    let rng = chacha20::ChaCha8Rng::from_rng(rng).unwrap();
    let store = unsafe { STORE.take().unwrap() };
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
    service: Arc<Mutex<CriticalSectionRawMutex, Service<Platform>>>,
    client_name: &str,
) -> ClientImplementation<Syscall> {
    let mut requester = None;

    loop {
        if let Ok(mut locked) = service.try_lock() {
            if let Some((req, res)) = Interchange::claim() {
                locked
                    .add_endpoint(res, PathBuf::from(client_name.as_bytes()))
                    // add_endpoint on error returns back responder which does not support
                    // Debug trait so we need to drop it in order to use expect()
                    .map_err(|_| ())
                    .expect("add_endpoint() failed (out of resources)");

                requester = Some(req);
            } else {
                panic!(
                    "Out of resource when creating Trussed client ({})",
                    client_name
                );
            }
        }

        if let Some(requester) = requester {
            return ClientImplementation::new(requester, Syscall { service });
        }
    }
}

/// Resets device back into its factory state - erase persistent storage and
/// reboot. After reboot device enters provisioning mode.
pub fn reset_device(_trussed: &mut trussed::ClientImplementation<crate::trussed::Syscall>) -> ! {
    // We take trussed reference to ensure no one is using it, otherwise we
    // could potentially trigger undefined behaviour if Trussed makes any
    // assumptions on flash contents.

    // SAFETY: once storage is erased we never return and never again use
    // Trussed
    unsafe { store::erase_storage() };
    SCB::sys_reset();
}
