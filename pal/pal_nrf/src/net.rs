use core::{
    pin::Pin,
    ptr,
    task::{Context, Waker},
};

use embassy::{executor::Spawner, util::Forever};
use embassy_net::{
    Config, ConfigStrategy, Device, Ipv4Address, Ipv4Cidr, PacketBuf, Stack, StackResources,
};
use futures_util::Future;
use smoltcp::phy::{Checksum, ChecksumCapabilities};

use crate::usb;

pub struct Ethernet {
    waker: Option<Waker>,
}

impl Ethernet {
    pub fn new() -> Self {
        Self { waker: None }
    }
}

impl Device for Ethernet {
    fn register_waker(&mut self, w: &Waker) {
        match self.waker {
            // Optimization: If both the old and new Wakers wake the same task, we can simply
            // keep the old waker, skipping the clone. (In most executor implementations,
            // cloning a waker is somewhat expensive, comparable to cloning an Arc).
            Some(ref w2) if (w2.will_wake(w)) => {}
            _ => {
                // clone the new waker and store it
                if let Some(old_waker) = core::mem::replace(&mut self.waker, Some(w.clone())) {
                    // We had a waker registered for another task. Wake it, so the other task can
                    // reregister itself if it's still interested.
                    //
                    // If two tasks are waiting on the same thing concurrently, this will cause them
                    // to wake each other in a loop fighting over this WakerRegistration. This wastes
                    // CPU but things will still work.
                    //
                    // If the user wants to have two tasks waiting on the same thing they should use
                    // a more appropriate primitive that can store multiple wakers.
                    old_waker.wake()
                }
            }
        }
    }

    fn link_state(&mut self) -> embassy_net::LinkState {
        embassy_net::LinkState::Up
    }

    fn capabilities(&self) -> embassy_net::DeviceCapabilities {
        let mut caps = embassy_net::DeviceCapabilities::default();
        caps.max_transmission_unit = 1514; // 1500 IP + 14 ethernet header
        caps.medium = embassy_net::Medium::Ethernet;
        caps.checksum = ChecksumCapabilities::ignored();
        caps.checksum.ipv4 = Checksum::Tx;
        caps.checksum.icmpv4 = Checksum::Tx;
        caps.checksum.udp = Checksum::Tx;
        caps.checksum.tcp = Checksum::Tx;
        caps
    }

    fn is_transmit_ready(&mut self) -> bool {
        true
    }

    fn transmit(&mut self, pkt: PacketBuf) {
        if usb::TX_CHANNEL.try_send(pkt).is_err() {
            warn!("TX failed")
        }
    }

    fn receive<'a>(&mut self) -> Option<PacketBuf> {
        let p = usb::RX_CHANNEL.try_recv().ok();
        if let Some(p) = p {
            return Some(p);
        } else if let Some(w) = self.waker.as_ref() {
            let mut cx = Context::from_waker(w);
            // Channel doesn't have support for poll_ready() so we have to use
            // separate channel to signal readiness.
            Pin::new(&mut usb::SIGNAL.wait()).poll(&mut cx).is_ready();
        }
        None
    }

    fn ethernet_address(&self) -> [u8; 6] {
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
    }
}

#[embassy::task]
async fn net_task(stack: &'static Stack<&'static mut Ethernet>) -> ! {
    stack.run().await
}

#[repr(transparent)]
struct Safe {
    ptr: *const Stack<&'static mut Ethernet>,
}
unsafe impl Sync for Safe {}
static mut STACK_PTR: Safe = Safe { ptr: ptr::null() };
pub(crate) fn init(spawner: Spawner) {
    static DEVICE: Forever<Ethernet> = Forever::new();
    static RESOURCES: Forever<StackResources<1, 2, 8>> = Forever::new();
    static STACK: Forever<Stack<&mut Ethernet>> = Forever::new();

    let device = DEVICE.put(Ethernet::new());
    let resources = RESOURCES.put_with(StackResources::new);

    let stack = STACK.put(Stack::new(
        device,
        ConfigStrategy::Static(Config {
            address: Ipv4Cidr::new(Ipv4Address::new(169, 254, 0, 1), 16),
            gateway: None,
            dns_servers: Default::default(),
        }),
        resources,
        // TODO: rng
        0,
    ));
    spawner.spawn(net_task(stack)).unwrap();
    unsafe {
        STACK_PTR = Safe {
            ptr: stack as *const _,
        }
    }
}

pub fn stack() -> &'static Stack<&'static mut Ethernet> {
    unsafe {
        let p = STACK_PTR.ptr;
        assert!(!p.is_null());
        &*p
    }
}
