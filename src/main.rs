#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

#[cfg(target_os = "none")]
extern crate pal_nrf as pal;

#[cfg(target_os = "linux")]
extern crate pal_pc as pal;

#[macro_use]
extern crate log;

use embedded_io::asynch::{Read, Write};
use pal::embassy_net::tcp::TcpSocket;

#[pal::main]
async fn main() {
    info!("Hello from main");

    let stack = pal::net::stack();
    let mut rx_buffer = [0; 4096];
    let mut tx_buffer = [0; 4096];
    let mut buf = [0; 4096];

    loop {
        info!("waiting for connection");
        let mut socket = TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);
        if let Err(e) = socket.accept(1234).await {
            warn!("accept failed: {:?}", e);
            continue;
        }

        if let Some(remote) = socket.remote_endpoint() {
            info!("Received connection from {}:{}", remote.addr, remote.port);
        } else {
            info!("Received connection from <unknown>");
        }

        loop {
            let n = match socket.read(&mut buf).await {
                Ok(0) => {
                    warn!("read EOF");
                    break;
                }
                Ok(n) => n,
                Err(e) => {
                    warn!("read error: {:?}", e);
                    break;
                }
            };

            if let Ok(s) = core::str::from_utf8(&buf[..n]) {
                info!("ECHO: {}", s);
            } else {
                info!("ECHO: bytearray len {}", n);
            }

            if let Err(e) = socket.write_all(&buf[..n]).await {
                warn!("echo failed: {:?}", e);
            } else {
                info!("echo done");
            }
        }
    }
}
