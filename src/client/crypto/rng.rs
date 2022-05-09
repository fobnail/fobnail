/// Wrapper forwarding all requests to Trussed.
/// Will be gone when Trussed gains RSA support.
pub struct TrussedRng<'a, T>(pub &'a mut T);
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
        // We assume random_bytes() never fails
        let random = trussed::syscall!(self.0.random_bytes(dest.len()));
        dest.copy_from_slice(&random.bytes);
        Ok(())
    }
}
