#![no_std]

#[macro_use]
extern crate log;

mod buffer;
mod eem;

pub use eem::EemDriver;
