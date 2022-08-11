use core::cell::RefCell;

use alloc::sync::Arc;

/// Trussed does not follow APIs commonly used by rust crates so we must implement
/// them ourselves.
pub struct TrussedRng<'a, T>(pub Arc<RefCell<&'a mut T>>);

// FIXME: remove this workaround.
// Until we are running on a single thread (executor) this is safe. Using RNG
// from an interrupt handler could trigger RefCell asserts.
unsafe impl<T> Send for TrussedRng<'_, T> {}
// TODO: Sync requirement could be relaxed
unsafe impl<T> Sync for TrussedRng<'_, T> {}

// CoAP server requires RNG to be Clone + Send + Sync
impl<T> Clone for TrussedRng<'_, T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<'a, T> TrussedRng<'a, T> {
    pub fn new(trussed: &'a mut T) -> Self {
        Self(Arc::new(RefCell::new(trussed)))
    }
}

impl<T> trussed::service::RngCore for TrussedRng<'_, T>
where
    T: trussed::client::CryptoClient,
{
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf[..]);
        u32::from_ne_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf[..]);
        u64::from_ne_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest).unwrap()
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        let mut trussed = self.0.borrow_mut();
        // We assume random_bytes() never fails
        let random = trussed::syscall!(trussed.random_bytes(dest.len()));
        dest.copy_from_slice(&random.bytes);
        Ok(())
    }
}
