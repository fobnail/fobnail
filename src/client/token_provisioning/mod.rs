use core::cell::RefCell;

use crate::coap::{CoapClient, Error};
use alloc::rc::Rc;
use coap_lite::{Packet, RequestType};
use pal::timer::get_time_ms;
use smoltcp::socket::{SocketRef, UdpSocket};
use state::State;

use super::util::handle_server_error_response;

mod state;

/// Client which speaks to the Platform Owner in order to perform Fobnail Token
/// provisioning.
pub struct FobnailClient<'a> {
    state: Rc<RefCell<State>>,
    coap_client: CoapClient<'a>,
    trussed: RefCell<&'a mut trussed::ClientImplementation<pal::trussed::Syscall>>,
}

impl<'a> FobnailClient<'a> {
    pub fn new(
        coap_client: CoapClient<'a>,
        trussed: &'a mut trussed::ClientImplementation<pal::trussed::Syscall>,
    ) -> Self {
        Self {
            state: Rc::new(RefCell::new(State::default())),
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
        let state = &mut *(*self.state).borrow_mut();

        matches!(state, State::Done)
    }

    pub fn poll(&mut self, socket: SocketRef<'_, UdpSocket>) {
        self.coap_client.poll(socket);

        macro_rules! coap_request {
            ($method:expr, $ep:expr) => {{
                let mut request = coap_lite::CoapRequest::new();
                request.set_path($ep);
                request.set_method($method);
                let state = Rc::clone(&self.state);
                self.coap_client
                    .queue_request(request, move |result| Self::handle_response(result, state));
            }};

            ($method:expr, $ep:expr, $data:expr) => {{
                let mut request = coap_lite::CoapRequest::new();
                request.set_path($ep);
                request.set_method($method);

                let encoded = trussed::cbor_serialize_bytes::<_, 512>(&$data).unwrap();
                request.message.payload = encoded.to_vec();
                request
                    .message
                    .set_content_format(ContentFormat::ApplicationCBOR);

                let state = Rc::clone(&self.state);
                self.coap_client
                    .queue_request(request, move |result| Self::handle_response(result, state));
            }};
        }

        let state = &mut *(*self.state).borrow_mut();
        match state {
            State::Done => {
                unreachable!("Should not be polled in this state");
            }
            State::RequestPoCertChain { request_pending } => {
                if !*request_pending {
                    *request_pending = true;

                    coap_request!(RequestType::Fetch, "/cert_chain")
                }
            }
            State::SignalStatus { success } => {
                // TODO: signal status, probably should use different signaling
                // than when provisioning platform
                if *success {
                    *state = State::Done;
                } else {
                    *state = State::Idle {
                        timeout: Some(get_time_ms() as u64 + 5000),
                    };
                }
            }
            State::Idle { timeout } => {
                if let Some(timeout) = timeout {
                    if get_time_ms() as u64 > *timeout {
                        *state = State::default();
                    }
                }
            }
        }
    }

    fn handle_response(result: Result<Packet, Error>, state: Rc<RefCell<State>>) {
        let state = &mut *(*state).borrow_mut();

        match state {
            State::RequestPoCertChain { .. } => match result {
                Ok(resp) => {
                    Self::handle_server_response(resp, state);
                }
                Err(e) => {
                    error!(
                        "Communication with platform owner failed (state {}): {:#?}",
                        state, e
                    );
                    state.error();
                }
            },
            State::Done | State::Idle { .. } | State::SignalStatus { .. } => {
                // We don't send any requests during these states so we shouldn't
                // get responses.
                unreachable!(
                    "We shouldn't receive receive any response during this state ({})",
                    state
                )
            }
        }
    }

    fn handle_server_response(result: Packet, state: &mut State) {
        if handle_server_error_response(&result).is_err() {
            error!(
                "Failed to {}, server returned error {}, retrying in 5s",
                state, result.header.code
            );
            state.error();
            return;
        }

        todo!()
    }
}
