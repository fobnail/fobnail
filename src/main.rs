#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

#[cfg(target_os = "none")]
extern crate pal_nrf as pal;

#[cfg(target_os = "linux")]
extern crate pal_pc as pal;

#[macro_use]
extern crate log;

#[pal::main]
async fn main() {
    info!("Hello from main");

    loop {
        pal::cpu_relax()
    }
}
