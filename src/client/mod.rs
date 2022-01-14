use core::cell::RefCell;

use alloc::rc::Rc;
use smoltcp::socket::{SocketRef, UdpSocket};

use crate::coap::{CoapClient, Error};
use state::State;

mod state;

/// Client which speaks to Fobnail server located on attester
pub struct FobnailClient<'a> {
    state: Rc<RefCell<State>>,
    coap_client: CoapClient<'a>,
}

impl<'a> FobnailClient<'a> {
    pub fn new(coap_client: CoapClient<'a>) -> Self {
        Self {
            state: Rc::new(RefCell::new(State::default())),
            coap_client,
        }
    }

    pub fn poll(&mut self, socket: SocketRef<'_, UdpSocket>) {
        self.coap_client.poll(socket);

        let mut state = self.state.borrow_mut();

        match &mut *state {
            State::Init {
                ref mut request_pending,
            } => {
                if !*request_pending {
                    let mut request = coap_lite::CoapRequest::new();
                    request.set_path("/");
                    request.set_method(coap_lite::RequestType::Get);

                    *request_pending = true;
                    let state = Rc::clone(&self.state);
                    self.coap_client
                        .queue_request(request, move |result| match result {
                            Ok(_resp) => {
                                panic!("CHECKPOINT");
                            }
                            Err(Error::Timeout) => {
                                let mut state = state.borrow_mut();
                                let State::Init {
                                    ref mut request_pending,
                                } = &mut *state;
                                *request_pending = false;
                            }
                            Err(e) => {
                                error!("Communication with attester failed: {:#?}, retrying", e);

                                let mut state = state.borrow_mut();
                                let State::Init {
                                    ref mut request_pending,
                                } = &mut *state;
                                *request_pending = false;
                            }
                        });
                }
            }
        }
    }
}
