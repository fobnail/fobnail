use core::mem::size_of;

use alloc::{
    boxed::Box,
    collections::{BTreeMap, VecDeque},
    vec::Vec,
};
use coap_lite::{CoapRequest, Packet, RequestType};
use smoltcp::{
    socket::{SocketRef, UdpSocket},
    wire::{IpAddress, IpEndpoint},
};

#[derive(PartialEq, Eq)]
enum State {
    One { nr_unreachable_failures: u32 },
    Two,
}

type Token = u64;

struct PendingRequest {
    token: Token,
    packet: Vec<u8>,
    /// Handler called on request completion.
    callback: Box<dyn FnOnce()>,
}

pub struct CoapClient {
    state: State,
    /// Server IP address and port.
    remote_endpoint: IpEndpoint,
    /// Requests queued for sending.
    queue: VecDeque<PendingRequest>,
    /// These requests have been sent, we are awaiting response.
    wait_queue: BTreeMap<Token, PendingRequest>,
    /// Token is a unique, opaque value that is sent back unchanded. We use it
    /// to match server's response to request.
    next_token: Token,
}
impl CoapClient {
    pub const COAP_DEFAULT_PORT: u16 = 5683;

    /// Creates new client instance
    pub fn new(server_addr: IpAddress, port: u16) -> Self {
        let endpoint = IpEndpoint::new(server_addr, port);

        Self {
            state: State::One {
                nr_unreachable_failures: 0,
            },
            remote_endpoint: endpoint,
            queue: VecDeque::with_capacity(16),
            wait_queue: BTreeMap::new(),
            next_token: 0,
        }
    }

    // TODO: document this
    pub fn queue_request<T>(&mut self, mut request: CoapRequest<()>, callback: T)
    where
        T: FnOnce() + 'static,
    {
        if self.queue.len() == self.queue.capacity() {
            // TODO: return an error instead of panicking
            panic!("CoAP queue is full");
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
            token,
            callback: Box::new(callback),
        });
    }

    pub fn poll(&mut self, mut socket: SocketRef<'_, UdpSocket>) {
        self.process_incoming(&mut socket);
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
                        Ok(packet) => {
                            if let Some(token) = TryInto::<[u8; size_of::<Token>()]>::try_into(
                                packet.get_token().as_slice(),
                            )
                            .map(|x| Token::from_ne_bytes(x))
                            .ok()
                            {
                                if let Some(request) = self.wait_queue.remove(&token) {
                                    (request.callback)();
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
                    let token = request.token;
                    let request = self.queue.pop_front().unwrap();
                    if self.wait_queue.insert(token, request).is_some() {
                        // This should never happen
                        panic!("Duplicated token ({}) in CoAP client queue", token);
                    }

                    true
                }
                Err(smoltcp::Error::Exhausted) => {
                    // TX buffer is full, wait till next time
                    false
                }
                Err(e) => {
                    error!("Failed to send packet ID {}: {}", request.token, e);
                    false
                }
            }
        } else {
            // No more packets to send
            false
        }
    }
}
