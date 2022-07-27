use core::task::Waker;

use embassy_net::{Device, PacketBuf};

struct Ethernet {}

impl Device for Ethernet {
    fn register_waker(&mut self, waker: &Waker) {
        // loopy loopy wakey wakey
        waker.wake_by_ref()
    }

    fn link_state(&mut self) -> embassy_net::LinkState {
        embassy_net::LinkState::Up
    }

    fn capabilities(&self) -> embassy_net::DeviceCapabilities {
        let mut caps = embassy_net::DeviceCapabilities::default();
        caps.max_transmission_unit = 1514; // 1500 IP + 14 ethernet header
        caps.medium = embassy_net::Medium::Ethernet;
        caps
    }

    fn is_transmit_ready(&mut self) -> bool {
        true
    }

    fn transmit(&mut self, pkt: PacketBuf) {
        /*if TX_CHANNEL.try_send(pkt).is_err() {
            warn!("TX failed")
        }*/
        todo!()
    }

    fn receive<'a>(&mut self) -> Option<PacketBuf> {
        //RX_CHANNEL.try_recv().ok()
        todo!()
    }

    fn ethernet_address(&self) -> [u8; 6] {
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
    }
}

pub(crate) fn init() {}
