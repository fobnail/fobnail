use core::cmp::min;
use core::ptr;

use usb_device::class_prelude::*;

pub struct Buffer<'a> {
    buf: &'a mut [u8],
    cursor: usize,
}

impl<'a> Buffer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, cursor: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        self.cursor
    }

    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    pub fn free(&self) -> usize {
        self.capacity() - self.len()
    }

    pub fn get_free(&mut self, len: usize) -> &mut [u8] {
        let t = &mut self.buf[self.cursor..self.cursor + len];
        self.cursor += len;
        t
    }

    pub fn peek(&self) -> &[u8] {
        &self.buf[..self.cursor]
    }

    pub fn peek_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.cursor]
    }

    pub fn discard_all(&mut self) {
        self.cursor = 0;
    }

    pub fn discard(&mut self, count: usize) {
        let count = min(count, self.len());
        if count == self.len() {
            // Optimization: avoid memory moving if we are discarding entire buffer
            self.cursor = 0;
        } else if count > 0 {
            let dst = self.buf.as_mut_ptr();
            let src = self.buf.as_ptr().wrapping_offset(count.try_into().unwrap());
            unsafe { ptr::copy(src, dst, self.len() - count) };
            self.cursor -= count;
        }
    }

    pub fn discard_back(&mut self, count: usize) {
        self.cursor -= count;
    }

    pub fn read_from_ep<'r, B>(&mut self, ep: &EndpointOut<'r, B>) -> usb_device::Result<usize>
    where
        B: UsbBus,
    {
        let n = ep.read(&mut self.buf[self.cursor..])?;
        self.cursor += n;
        Ok(n)
    }
}
