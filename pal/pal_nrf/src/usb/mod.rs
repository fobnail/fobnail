use super::hfosc;
use embassy::blocking_mutex::raw::ThreadModeRawMutex;
use embassy::channel::mpmc::Channel;
use embassy::channel::signal::Signal;
use embassy::executor::Spawner;
use embassy::time::{Duration, Ticker};
use embassy::util::{select, Either};
use embassy_net::{Packet, PacketBox, PacketBoxExt, PacketBuf};
use futures_util::StreamExt;
use hal::pac::USBD;
use hal::usbd::{UsbPeripheral, Usbd};
use usb_device::device::{UsbDeviceBuilder, UsbVidPid};
use usbd_ethernet::EthernetDriver;

const FOBNAIL_TOKEN_VID: u16 = 0x1234;
const FOBNAIL_TOKEN_PID: u16 = 0x4321;
const EEM_BUFFER_SIZE: u16 = 1500 * 2;

pub(crate) static TX_CHANNEL: Channel<ThreadModeRawMutex, PacketBuf, 8> = Channel::new();
pub(crate) static RX_CHANNEL: Channel<ThreadModeRawMutex, PacketBuf, 8> = Channel::new();
pub(crate) static SIGNAL: Signal<u8> = Signal::new();

#[embassy::task]
async fn usb_task(usbd: USBD) {
    let mut eth_rx_buf = [0u8; EEM_BUFFER_SIZE as usize];
    let mut eth_tx_buf = [0u8; EEM_BUFFER_SIZE as usize];

    let usb_periph = UsbPeripheral::new(usbd, hfosc());
    let usb_bus = Usbd::new(usb_periph);
    let mut eth = EthernetDriver::new(&usb_bus, 64, &mut eth_rx_buf, &mut eth_tx_buf);
    let mut usb_dev =
        UsbDeviceBuilder::new(&usb_bus, UsbVidPid(FOBNAIL_TOKEN_VID, FOBNAIL_TOKEN_PID))
            .manufacturer("Fobnail")
            .product("Fobnail")
            .serial_number("TEST")
            .device_class(0x00)
            .max_packet_size_0(64)
            .build();

    let mut timer = Ticker::every(Duration::from_millis(1));
    loop {
        match select(timer.next(), TX_CHANNEL.recv()).await {
            Either::First(_) => {
                while usb_dev.poll(&mut [&mut eth]) {}

                eth.read_packet(|buf| {
                    if let Some(mut packet) = PacketBox::new(Packet::new()) {
                        if packet.len() > buf.len() {
                            let n = buf.len();
                            packet[..n].copy_from_slice(buf);

                            SIGNAL.signal(0);
                            if RX_CHANNEL.try_send(packet.slice(0..n)).is_err() {
                                warn!("Failed to push packet into queue, packet lost");
                            }
                        } else {
                            warn!("Pool exhausted, packet lost");
                        }
                    } else {
                        warn!("Pool exhausted, packet lost");
                    }
                });
            }
            Either::Second(packet) => {
                eth.prepare_packet::<_, _, ()>(packet.len(), |buf| {
                    buf.copy_from_slice(&packet[..]);
                    Ok(())
                });
            }
        }
    }
}

pub fn init(spawner: Spawner, usbd: USBD) {
    spawner.must_spawn(usb_task(usbd));
}
