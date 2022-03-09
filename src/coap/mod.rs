use core::mem::{size_of, swap};

use alloc::{
    boxed::Box,
    collections::{BTreeMap, LinkedList, VecDeque},
    vec::Vec,
};
use coap_lite::{CoapOption, CoapRequest, Header, MessageClass, MessageType, Packet};
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
    callback: Option<Box<dyn FnOnce(Result<Packet>) + 'a>>,
    /// How long are we going to wait for a response.
    timeout_ms: u64,
    /// Time when request has been sent.
    send_time: u64,
    /// How many times we will resend the same packet. u16::MAX meanst infinite.
    retry_count: u16,
    /// Buffer used for block-wise transfers
    buffered_payload: Vec<u8>,
    /// Next block we are expecting (if using block-wise transfers)
    next_block: u32,
    /// When using block-wise transfers contains header from the first response
    header: Option<Header>,
}

struct PendingRequest<'a> {
    packet: Vec<u8>,
    /// If using block-wise transfers this field has token of the request that
    /// initiated block-wise transfer.
    linked_request: Option<u64>,
    confirmable: Option<ConfirmableRequest<'a>>,
}

impl PendingRequest<'_> {
    /// Notify callback that request has completed, either successfuly or with
    /// error.
    pub fn complete(self, result: Result<Packet>) {
        let Self { confirmable, .. } = self;

        let ConfirmableRequest { callback, .. } =
            confirmable.expect("complete() called on non-confirmable request");

        if let Some(callback) = callback {
            (callback)(result);
        }
    }
}

pub struct CoapClient<'a> {
    /// Server IP address and port.
    remote_endpoint: IpEndpoint,
    /// Requests queued for sending.
    queue: VecDeque<PendingRequest<'a>>,
    /// These requests have been sent, we are awaiting response.
    wait_queue: BTreeMap<Token, PendingRequest<'a>>,
    /// These requests received the first block of response, we are waiting for
    /// other responses.
    blockwise_queue: BTreeMap<Token, PendingRequest<'a>>,
    /// Token is a unique, opaque value that is sent back unchanded. We use it
    /// to match server's response to request.
    next_token: Token,
    /// Message ID is used for deduplication purposes.
    next_msg_id: u16,
}
impl<'a> CoapClient<'a> {
    pub const COAP_DEFAULT_PORT: u16 = 5683;
    pub const DEFAULT_TIMEOUT: u64 = 1000; // 1 second
    /// Default block size when using blockwise transfers. Must be power-of-two.
    /// FIXME: when using 1024 block size network tends to lockup - processing
    /// of all packets fails with
    /// cannot process ingress packet: buffer space exhausted
    pub const DEFAULT_BLOCK_SIZE: u32 = 512;

    /// Creates new client instance
    pub fn new(server_addr: IpAddress, port: u16) -> Self {
        let endpoint = IpEndpoint::new(server_addr, port);

        Self {
            remote_endpoint: endpoint,
            queue: VecDeque::with_capacity(16),
            wait_queue: BTreeMap::new(),
            blockwise_queue: BTreeMap::new(),
            // From RFC 7252 section 4.4
            // It is strongly recommended that the initial
            // value of the variable (e.g., on startup) be randomized, in order
            // to make successful off-path attacks on the protocol less likely.
            // TODO: do we need this?
            next_token: 0,
            next_msg_id: 0,
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

        request.message.header.message_id = self.next_msg_id;
        // Use wrapping add to not panic on overflow.
        // From RFC 7252 section 4.4:
        // The same Message ID MUST NOT be reused (in communicating with the
        // same endpoint) within the EXCHANGE_LIFETIME (Section 4.8.2).
        //
        // We are not sending many requests so lets assume this won't happen.
        self.next_msg_id = self.next_msg_id.wrapping_add(1);

        let token = self.next_token;
        self.next_token += 1;
        // Assign a unique token so that we can match response to request.
        request.message.set_token(token.to_ne_bytes().to_vec());

        // Set default block size for blockwise transfers.
        let mut list = LinkedList::new();
        list.push_back(Self::encode_block12_option(Self::DEFAULT_BLOCK_SIZE, 0, false).unwrap());
        request.message.set_option(CoapOption::Block2, list);

        // TODO: handle error
        let packet = request.message.to_bytes().unwrap();

        self.queue.push_back(PendingRequest {
            packet,
            linked_request: None,
            confirmable: Some(ConfirmableRequest {
                token,
                callback: Some(Box::new(callback)),
                // Will be filled in send_next_request
                send_time: 0,
                timeout_ms: Self::DEFAULT_TIMEOUT,
                retry_count: u16::MAX,
                buffered_payload: Vec::new(),
                next_block: 0,
                header: None,
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
                                        if let Some(original_token) = request.linked_request {
                                            // If using block wise transfers call process_response on original request
                                            let original_request = self
                                                .blockwise_queue
                                                .remove(&original_token)
                                                .expect("Linked request not found");

                                            if let Some(request) =
                                                self.process_response(original_request, packet)
                                            {
                                                if self
                                                    .blockwise_queue
                                                    .insert(original_token, request)
                                                    .is_some()
                                                {
                                                    // This should never happen
                                                    panic!(
                                                        "Duplicated token ({}) in CoAP block-wise queue",
                                                        token
                                                    );
                                                }
                                            }
                                        } else {
                                            if let Some(request) =
                                                self.process_response(request, packet)
                                            {
                                                // We are still waiting for more blocks to come. Request for the next
                                                // block has been queued already, we need only to insert original
                                                // request into the proper queue.
                                                if self
                                                    .blockwise_queue
                                                    .insert(token, request)
                                                    .is_some()
                                                {
                                                    // This should never happen
                                                    panic!(
                                                        "Duplicated token ({}) in CoAP block-wise queue",
                                                        token
                                                    );
                                                }
                                            }
                                        }
                                    }

                                    // FIXME:
                                    // On nRF when we send packet before target host gets discovered smoltcp
                                    // doesn't return error, instead it buffers the packets till host finally
                                    // gets discovered (sending ARP requests every 3 seconds).
                                    // Request timeouts and CoapClient re-sends that request filling smoltcp
                                    // buffer.
                                    //
                                    // Because of this behavior one problem arises:
                                    // CoapClient keeps sending the same packet till outgoing buffer gets filled
                                    // Surprisingly this doesn't cause DoS and smoltcp is still able to send ARP
                                    // packets.
                                    // But when host gets discovered, packets are sent,
                                    // sending many duplicates of the same packet (limited by outgoing buffer size).
                                    // Duplicates should be detected and handled by server, and server shouldn't
                                    // process the same request multiple, but it may send the same response multiple
                                    // times.
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

    fn process_response<'r>(
        &mut self,
        mut request: PendingRequest<'r>,
        response: Packet,
    ) -> Option<PendingRequest<'r>> {
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
        // Currently we support block2 option only.

        let confirmable = request
            .confirmable
            .as_mut()
            .expect("process_response() called with a non-confirmable request");

        enum Action {
            Complete,
            Fail,
            RequestNextBlock { block_size: u32 },
        }
        let mut action = Action::Complete;

        for (opt, data) in response
            .options()
            .filter(|(id, _)| *id % 2 != 0)
            .map(|(id, x)| (CoapOption::from(*id), x))
        {
            match opt {
                CoapOption::Block2 => {
                    let mut buffer = Vec::new();
                    for x in data.iter() {
                        buffer.extend_from_slice(&x);
                    }

                    if let Some((block_size, block_number, more_blocks)) =
                        Self::decode_block12_option(&buffer)
                    {
                        if confirmable.next_block != block_number {
                            // This should not happen - we request the next block only after receiving previous
                            // one. All blocks should always come in order.
                            error!(
                                "Blocks came out of order: expected block {}, got {}",
                                confirmable.next_block, block_number
                            );
                            action = Action::Fail;
                        } else {
                            if more_blocks {
                                action = Action::RequestNextBlock { block_size };
                            } else {
                                action = Action::Complete;
                            }
                        }
                    } else {
                        error!("Could not decode BLOCK2 option");
                        action = Action::Fail;
                    }
                }
                _ => {
                    error!(
                        "Unknown critical option ({}) encountered in response to {}",
                        u16::from(opt),
                        confirmable.token
                    );

                    action = Action::Fail;
                }
            }
        }

        match action {
            Action::Complete => {
                // TODO: Server response may be a confirmable packet, in that case
                // we need to send ACK to stop server from retransmitting same
                // packet over and over again

                // Pass response to callback
                if confirmable.buffered_payload.is_empty() {
                    request.complete(Ok(response));
                } else {
                    confirmable
                        .buffered_payload
                        .extend_from_slice(&response.payload);
                    let mut response = Packet::default();
                    response.header = confirmable.header.take().unwrap();
                    swap(&mut response.payload, &mut confirmable.buffered_payload);
                    request.complete(Ok(response))
                }

                None
            }
            Action::RequestNextBlock { block_size, .. } => {
                // We must send a request to get the next block.
                // From RFC7959 section 2.4
                //
                // When a request is answered with a response carrying a Block2 Option
                // with the M bit set, the requester may retrieve additional blocks of
                // the resource representation by sending further requests with the same
                // options as the initial request and a Block2 Option giving the block
                // number and block size desired.  In a request, the client MUST set the
                // M bit of a Block2 Option to zero and the server MUST ignore it on
                // reception.

                confirmable.next_block += 1;

                let Packet {
                    header, payload, ..
                } = response;
                if confirmable.header.is_none() {
                    confirmable.header = Some(header);
                }

                if confirmable.buffered_payload.is_empty() {
                    // Optimization: avoid copy if possible
                    confirmable.buffered_payload = payload;
                } else {
                    confirmable.buffered_payload.extend_from_slice(&payload);
                }

                let next_block = confirmable.next_block;
                if let Err(e) = self.request_next_block(&request, block_size, next_block) {
                    error!("Failed to request next block");
                    // TODO: should we send reset packet?
                    request.complete(Err(e));
                    None
                } else {
                    Some(request)
                }
            }
            Action::Fail => {
                // TODO: should we send reset packet?
                request.complete(Err(Error::ProtocolError));

                None
            }
        }
    }

    fn decode_block12_option(data: &[u8]) -> Option<(u32, u32, bool)> {
        if data.len() == 0 {
            return None;
        }

        let last_byte = *data.last().unwrap();
        let szx = last_byte & 7;
        let block_size = 1u32 << (szx + 4);
        let more_blocks = last_byte & 8 == 8;

        let block_number = if data.len() == 1 {
            last_byte >> 4
        } else {
            error!("decoding block_number > 15 is not supported");
            return None;
        };

        Some((block_size, block_number as u32, more_blocks))
    }

    fn encode_block12_option(block_size: u32, block_number: u32, m: bool) -> Option<Vec<u8>> {
        assert!(block_size.is_power_of_two());

        // We depend here on int_log feature https://github.com/rust-lang/rust/issues/70887
        // Anyway we have to use nightly for liballoc so adding this doesn't change much
        // If needed we may easily roll our own log2() implementation.
        let szx = block_size.log2() - 4;
        if szx & !7 != 0 {
            panic!("CoAP block size too big")
        }

        let mut szx_m_num = szx as u8;
        if m {
            szx_m_num |= 8;
        }
        if block_number != 0 {
            if block_number > 15 {
                error!("block_number crossed maximum supported value");
                return None;
            }

            let b = block_number << 4;
            szx_m_num |= b as u8;
        }

        Some([szx_m_num].to_vec())
    }

    fn request_next_block(
        &mut self,
        original_request: &PendingRequest,
        block_size: u32,
        block_number: u32,
    ) -> Result<()> {
        let mut request = CoapRequest::<()>::new();
        // We send a request similar to the original one, but with the following
        // differences:
        // - new message_id and token
        // - Block2 option set.
        request.message = Packet::from_bytes(&original_request.packet).unwrap();

        request.message.header.message_id = self.next_msg_id;
        self.next_msg_id = self.next_msg_id.wrapping_add(1);
        let token = self.next_token;
        self.next_token += 1;
        // Assign a unique token so that we can match response to request.
        request.message.set_token(token.to_ne_bytes().to_vec());

        let mut list = LinkedList::new();
        list.push_back(
            Self::encode_block12_option(block_size, block_number, true)
                .ok_or(Error::ProtocolError)?,
        );
        request.message.set_option(CoapOption::Block2, list);

        let packet = request
            .message
            .to_bytes()
            .map_err(|_| Error::ProtocolError)?;

        let original_confirmable = original_request
            .confirmable
            .as_ref()
            .expect("Tried to initiate block-wise transfer on non-confirmable request");

        self.queue.push_back(PendingRequest {
            packet,
            linked_request: Some(original_confirmable.token),
            confirmable: Some(ConfirmableRequest {
                token,
                callback: None,
                // Will be filled in send_next_request
                send_time: 0,
                timeout_ms: original_confirmable.timeout_ms,
                retry_count: original_confirmable.retry_count,
                buffered_payload: Vec::new(),
                next_block: 0,
                header: None,
            }),
        });

        Ok(())
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
                    if let Some(token) = request.linked_request {
                        let original = self
                            .blockwise_queue
                            .remove(&token)
                            .expect("Linked request not found");
                        original.complete(Err(Error::Timeout));
                    }
                    request.complete(Err(Error::Timeout));
                }
            } else {
                // No more timed out requests
                break;
            }
        }
    }
}
