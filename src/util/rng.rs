use pal::embassy_util::{blocking_mutex::raw::RawMutex, mutex::Mutex};

/// Trussed does not follow APIs commonly used by rust crates so we must implement
/// them ourselves.
pub struct TrussedRng<M: RawMutex + 'static, T: 'static>(pub &'static Mutex<M, T>);

// CoAP server requires RNG to be Clone + Send + Sync
impl<M: RawMutex, T> Clone for TrussedRng<M, T> {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<M: RawMutex, T> TrussedRng<M, T> {
    pub fn new(trussed: &'static Mutex<M, T>) -> Self {
        Self(trussed)
    }
}

impl<M: RawMutex, T> trussed::service::RngCore for TrussedRng<M, T>
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
        loop {
            // FIXME: should not be blocking but until Trussed gains ability to
            // run concurrent jobs there is nothing we can do.
            if let Ok(mut trussed) = self.0.try_lock() {
                let random = trussed::syscall!(trussed.random_bytes(dest.len()));
                dest.copy_from_slice(&random.bytes);
                return Ok(());
            }
        }
    }
}
