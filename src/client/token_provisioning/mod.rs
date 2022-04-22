use core::cell::RefCell;

use smoltcp::socket::{SocketRef, UdpSocket};

use crate::coap::CoapClient;

/// Client which speaks to the Platform Owner in order to perform Fobnail Token
/// provisioning.
pub struct FobnailClient<'a> {
    coap_client: CoapClient<'a>,
    trussed: RefCell<&'a mut trussed::ClientImplementation<pal::trussed::Syscall>>,
}

impl<'a> FobnailClient<'a> {
    pub fn new(
        coap_client: CoapClient<'a>,
        trussed: &'a mut trussed::ClientImplementation<pal::trussed::Syscall>,
    ) -> Self {
        Self {
            coap_client,
            trussed: RefCell::new(trussed),
        }
    }

    /// Reclaim ownership of Trussed client.
    pub fn into_trussed(self) -> &'a mut trussed::ClientImplementation<pal::trussed::Syscall> {
        let Self { trussed, .. } = self;
        trussed.into_inner()
    }

    /// Checks whether provisioning is done.
    pub fn done(&self) -> bool {
        // TODO: implement this
        false
    }

    pub fn poll(&mut self, socket: SocketRef<'_, UdpSocket>) {
        self.coap_client.poll(socket);

        todo!("checkpoint");
    }
}
