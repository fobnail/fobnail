use core::mem::size_of;

use alloc::{
    boxed::Box,
    collections::{BTreeMap, VecDeque},
    vec::Vec,
};
use coap_lite::{CoapRequest, MessageClass, MessageType, Packet};
pub use error::*;
use pal::timer::get_time_ms;
use smoltcp::{
    socket::{SocketRef, UdpSocket},
    wire::{IpAddress, IpEndpoint},
};

mod error;

/// Token is used as a unique request identifier.
type Token = u64;

struct ConfirmableRequest<'a> {
    token: Token,
    /// Handler called on request completion.
    callback: Box<dyn FnOnce(Result<Packet>) + 'a>,
    /// How long are we going to wait for a response.
    timeout_ms: u64,
    /// Time when request has been sent.
    send_time: u64,
    /// How many times we will resend the same packet. u16::MAX meanst infinite.
    retry_count: u16,
}

struct PendingRequest<'a> {
    packet: Vec<u8>,
    confirmable: Option<ConfirmableRequest<'a>>,
}

impl PendingRequest<'_> {
    /// Notify callback that request has completed, either successfuly or with
    /// error.
    pub fn complete(self, result: Result<Packet>) {
        let Self { confirmable, .. } = self;

        let ConfirmableRequest { callback, .. } =
            confirmable.expect("complete() called on non-confirmable request");

        (callback)(result);
    }
}

pub struct CoapClient<'a> {
    /// Server IP address and port.
    remote_endpoint: IpEndpoint,
    /// Requests queued for sending.
    queue: VecDeque<PendingRequest<'a>>,
    /// These requests have been sent, we are awaiting response.
    wait_queue: BTreeMap<Token, PendingRequest<'a>>,
    /// Token is a unique, opaque value that is sent back unchanded. We use it
    /// to match server's response to request.
    next_token: Token,
}
impl<'a> CoapClient<'a> {
    pub const COAP_DEFAULT_PORT: u16 = 5683;
    pub const DEFAULT_TIMEOUT: u64 = 1000; // 1 second

    /// Creates new client instance
    pub fn new(server_addr: IpAddress, port: u16) -> Self {
        let endpoint = IpEndpoint::new(server_addr, port);

        Self {
            remote_endpoint: endpoint,
            queue: VecDeque::with_capacity(16),
            wait_queue: BTreeMap::new(),
            next_token: 0,
        }
    }

    // TODO: document this
    pub fn queue_request<T>(&mut self, mut request: CoapRequest<()>, callback: T)
    where
        T: FnOnce(Result<Packet>) + 'a,
    {
        if self.queue.len() == self.queue.capacity() {
            warn!(
                "CoAP queue is full (current length {}), growing ...",
                self.queue.len()
            );
        }

        // TODO: maybe we should fill message ID
        let token = self.next_token;
        self.next_token += 1;
        // Assign a unique token so that we can match response to request.
        request.message.set_token(token.to_ne_bytes().to_vec());

        // TODO: handle error
        let packet = request.message.to_bytes().unwrap();

        self.queue.push_back(PendingRequest {
            packet,
            confirmable: Some(ConfirmableRequest {
                token,
                callback: Box::new(callback),
                // Will be filled in send_next_request
                send_time: 0,
                timeout_ms: Self::DEFAULT_TIMEOUT,
                retry_count: u16::MAX,
            }),
        });
    }

    pub fn poll(&mut self, mut socket: SocketRef<'_, UdpSocket>) {
        self.process_incoming(&mut socket);
        self.check_timeouts();
        while self.send_next_request(&mut socket) {}
    }

    fn process_incoming(&mut self, socket: &mut SocketRef<'_, UdpSocket>) {
        loop {
            match socket.recv() {
                Ok((packet, ep)) => {
                    if ep != self.remote_endpoint {
                        warn!(
                            "Ignoring packet from {} (expected from {})",
                            ep, self.remote_endpoint
                        );
                        continue;
                    }

                    match Packet::from_bytes(packet) {
                        Ok(packet) => match (packet.header.get_type(), packet.header.code) {
                            (
                                // ACK packets may be used for transmitting response (Piggybacked response)
                                // see RFC 7252 section 5.2.1
                                MessageType::Acknowledgement
                                | MessageType::Confirmable
                                | MessageType::NonConfirmable,
                                MessageClass::Response(_),
                            ) => {
                                if let Some(token) = TryInto::<[u8; size_of::<Token>()]>::try_into(
                                    packet.get_token().as_slice(),
                                )
                                .map(|x| Token::from_ne_bytes(x))
                                .ok()
                                {
                                    if let Some(request) = self.wait_queue.remove(&token) {
                                        self.process_response(request, packet);
                                    } else {
                                        warn!("Ignoring packet with unknown token {}", token);
                                    }
                                } else {
                                    warn!(
                                        "Ignoring packet with invalid token: token len={}, expected {}",
                                        packet.get_token().len(),
                                        size_of::<Token>()
                                    );
                                }
                            }
                            (MessageType::Acknowledgement, MessageClass::Empty) => {
                                // Ignore empty acknowledgement packets. These
                                // are used to signify that server has received
                                // request and is preparing response. We should
                                // receive response shortly.
                            }
                            (MessageType::Reset, c) => {
                                // TODO: implement

                                // Empty packets are used to reject message
                                // see RFC 7252 section 4.2

                                // Also may be used for pinging:
                                // Provoking a Reset message (e.g., by sending
                                // an Empty Confirmable message) is also useful
                                // as an inexpensive check of the liveness of an
                                // endpoint ("CoAP ping").
                                warn!("Got reset packet (class {:?}), ignoring ...", c);
                            }
                            (t, c) => {
                                // We process only response packets
                                warn!("Ignored incoming packet of type {:?} and class {:?}", t, c);
                            }
                        },
                        Err(e) => {
                            error!("Got invalid CoAP packet from {}: {}", ep, e)
                        }
                    }
                }
                Err(smoltcp::Error::Exhausted) => {
                    // No packets incoming
                    break;
                }
                Err(e) => error!("UDP recv error: {}", e),
            }
        }
    }

    fn send_next_request(&mut self, socket: &mut SocketRef<'_, UdpSocket>) -> bool {
        if let Some(request) = self.queue.get(0) {
            match socket.send_slice(&request.packet, self.remote_endpoint) {
                Ok(()) => {
                    let mut request = self.queue.pop_front().unwrap();
                    if let Some(confirmable) = request.confirmable.as_mut() {
                        let token = confirmable.token;
                        confirmable.send_time = get_time_ms() as u64;

                        if self.wait_queue.insert(token, request).is_some() {
                            // This should never happen
                            panic!("Duplicated token ({}) in CoAP client queue", token);
                        }
                    }

                    true
                }
                Err(smoltcp::Error::Exhausted) => {
                    // TX buffer is full, wait till next time
                    false
                }
                Err(e) => {
                    if let Some(confirmable) = request.confirmable.as_ref() {
                        error!("Failed to send packet ID {}: {}", confirmable.token, e);
                    } else {
                        error!("Failed to send packet (non-confirmable): {}", e);
                    }

                    false
                }
            }
        } else {
            // No more packets to send
            false
        }
    }

    fn process_response(&mut self, request: PendingRequest, response: Packet) {
        // coap-lite does not process options (it only parses them). We
        // must make sure response does not contain some unknown
        // critical option. In that case response must be rejected,
        // non-critical (elective) options may be safely ignored.
        // See RFC 7252 section 5.4.1
        //
        // From RFC 7252 section 5.4.6:
        // An Option is identified by an option number, which also provides some
        // additional semantics information, e.g., odd numbers indicate a
        // critical option, while even numbers indicate an elective option.
        //
        // Currently we don't support any of critical options

        let confirmable = request
            .confirmable
            .as_ref()
            .expect("process_response() called with a non-confirmable request");

        if let Some((&id, _)) = response.options().find(|(&id, _)| id % 2 != 0) {
            error!(
                "Unknown critical option ({}) encountered in response to {}",
                id, confirmable.token
            );

            // TODO: should we send reset packet?
            request.complete(Err(Error::ProtocolError));
        } else {
            // Server response may be a confirmable packet, in that case we need
            // to send ACK to stop server from retransmitting same packet over
            // and over again

            // Pass response to callback
            request.complete(Ok(response));
        }
    }

    fn check_timeouts(&mut self) {
        let now = get_time_ms() as u64;

        loop {
            let mut timed_out = None;

            for (&token, request) in self.wait_queue.iter() {
                // Packets stored in wait_queue are awaiting for response.
                // We expect no response to non-confirmable hence we never store
                // them in wait_queue.
                let confirmable = request
                    .confirmable
                    .as_ref()
                    .expect("non-confirmable request in wait queue");

                let deadline = confirmable.send_time + confirmable.timeout_ms;
                if now > deadline {
                    timed_out = Some(token);

                    // We cannot mutate map while iterating over it
                    break;
                }
            }

            if let Some(token) = timed_out.take() {
                let mut request = self.wait_queue.remove(&token).unwrap();
                let confirmable = request.confirmable.as_mut().expect("msg");
                // u16::MAX means infinite
                if confirmable.retry_count != u16::MAX {
                    confirmable.retry_count -= 1;
                }
                if confirmable.retry_count > 0 {
                    self.queue.push_back(request);
                } else {
                    request.complete(Err(Error::Timeout));
                }
            } else {
                // No more timed out requests
                break;
            }
        }
    }
}
