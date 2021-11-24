use core::{cmp::min, ops::Range};

use super::buffer::Buffer;
use usb_device::class_prelude::*;

const EEM_CMD_ECHO: u8 = 0;
const EEM_CMD_ECHO_RESP: u8 = 1;
const EEM_CMD_SUSPEND_HINT: u8 = 2;
const EEM_CMD_RESPONSE_HINT: u8 = 3;
const EEM_CMD_RESPONSE_COMPLETE_HINT: u8 = 4;
const EEM_CMD_TICKLE: u8 = 5;

pub const EEM_HEADER_SIZE: usize = 2;

#[derive(PartialEq, Eq)]
enum TxState {
    /// No packets to send.
    Idle,

    /// Transmission is frozen due to TX buffer being full.
    Frozen,

    /// Transmission is in progress (link must be UP for transmission to
    /// actually occur).
    InProgress,
}

#[derive(PartialEq, Eq)]
enum LinkStatus {
    Down,
    Up,
}

pub struct EemDriver<'a, B>
where
    B: UsbBus,
{
    interface: InterfaceNumber,
    ep_in: EndpointIn<'a, B>,
    ep_out: EndpointOut<'a, B>,
    max_packet_size: u16,
    str_interface_name: StringIndex,
    rx_buf: Buffer<'a>,
    tx_buf: Buffer<'a>,
    tx_state: TxState,
    link_status: LinkStatus,
}

impl<'a, B> EemDriver<'a, B>
where
    B: UsbBus,
{
    pub fn new(
        alloc: &'a UsbBusAllocator<B>,
        max_packet_size: u16,
        rx_buf: &'a mut [u8],
        tx_buf: &'a mut [u8],
    ) -> Self {
        Self {
            interface: alloc.interface(),
            ep_in: alloc.bulk(max_packet_size),
            ep_out: alloc.bulk(max_packet_size),
            max_packet_size,
            str_interface_name: alloc.string(),
            rx_buf: Buffer::new(rx_buf),
            tx_buf: Buffer::new(tx_buf),
            tx_state: TxState::Idle,
            link_status: LinkStatus::Down,
        }
    }

    fn tx_state_freeze(&mut self) {
        self.tx_state = TxState::Frozen;
    }

    fn tx_state_unfreeze(&mut self) {
        if self.tx_state == TxState::Frozen {
            // If transmit buffer is not empty then resume transfers
            if !self.tx_buf.is_empty() {
                self.tx_state = TxState::InProgress;
                self.do_tx();
            } else {
                self.tx_state = TxState::Idle;
            }
        }
    }

    fn tx_state_resume(&mut self) {
        if self.tx_state == TxState::Idle {
            self.tx_state = TxState::InProgress;
        }
    }

    /// Handles EEM command packets.
    ///
    /// If the first packet in the queue is an EEM command packet this method
    /// handles, and removes it from the queue.
    ///
    /// EEM data packets ale left intact (see `read_packet`)
    ///
    /// # Return value
    ///
    /// This method returns `true` if command packet got handled and removed
    /// from the queue, false otherwise.
    fn handle_command_packet(&mut self) -> bool {
        let buf = self.rx_buf.peek();
        if let Some(header) = buf.get(..EEM_HEADER_SIZE) {
            let header = u16::from_le_bytes(header.try_into().unwrap());

            // 16-th bit (bmType) determines packet type, if bit is set then
            // packet is a command packet, otherwise it is a data packet
            let is_command_packet = header & (1 << 15) != 0;

            if is_command_packet {
                let command = ((header >> 11) & 7) as u8;
                let n = match command {
                    EEM_CMD_ECHO => Self::handle_echo_command(header, buf, &mut self.tx_buf),
                    EEM_CMD_ECHO_RESP => Self::handle_echo_resp_command(header, buf),
                    EEM_CMD_TICKLE
                    | EEM_CMD_SUSPEND_HINT
                    | EEM_CMD_RESPONSE_HINT
                    | EEM_CMD_RESPONSE_COMPLETE_HINT => {
                        // Ignore these commands
                        EEM_HEADER_SIZE
                    }
                    _ => {
                        // TODO: we need to somehow handle errors instead of
                        // panicking (stall?)
                        panic!("unsupported command {}", command);
                    }
                };

                // if n > 0 then packet got handled
                if n > 0 {
                    self.rx_buf.discard(n);
                    self.tx_state_resume();
                    self.do_tx();

                    return true;
                }
            }
        }

        false
    }

    fn handle_echo_command(header: u16, buf: &[u8], tx_buf: &mut Buffer) -> usize {
        let payload_len = header & 0x7ff;
        if buf.len() >= payload_len as usize + EEM_HEADER_SIZE as usize {
            let tx_buf = tx_buf.get_free(payload_len as usize + EEM_HEADER_SIZE);
            tx_buf[EEM_HEADER_SIZE..]
                .copy_from_slice(&buf[EEM_HEADER_SIZE..EEM_HEADER_SIZE + payload_len as usize]);
            let header: u16 = (1 << 15) | ((EEM_CMD_ECHO_RESP as u16) << 11) | payload_len;
            let header_bytes = header.to_le_bytes();
            tx_buf[0] = header_bytes[0];
            tx_buf[1] = header_bytes[1];

            payload_len as usize + EEM_HEADER_SIZE
        } else {
            0
        }
    }

    fn handle_echo_resp_command(header: u16, buf: &[u8]) -> usize {
        let payload_len = header & 0x7ff;
        if buf.len() >= payload_len as usize + EEM_HEADER_SIZE as usize {
            // Ignore any contents

            payload_len as usize + EEM_HEADER_SIZE
        } else {
            0
        }
    }

    fn get_packet_range(&self) -> Option<Range<usize>> {
        let buf = self.rx_buf.peek();
        if let Some(header) = buf.get(..EEM_HEADER_SIZE) {
            let header = u16::from_le_bytes(header.try_into().unwrap());

            let is_command_packet = header & (1 << 15) != 0;
            // Command packets are handled by `handle_command_packet` and
            // (usually) immediatelly removed from the buffer, except when
            // packet is split across USB frames

            // TODO: remove this assertion
            assert!(!is_command_packet);

            let ethernet_frame_length = header & 0x3fff;
            if buf.len() >= EEM_HEADER_SIZE + ethernet_frame_length as usize {
                return Some(EEM_HEADER_SIZE..EEM_HEADER_SIZE + ethernet_frame_length as usize);
            }
        }

        None
    }

    /// Returns `true` if there is an Ethernet frame available, `false`
    /// otherwise.
    pub fn incoming_packet(&self) -> bool {
        self.get_packet_range().is_some()
    }

    /// This method reads a single Ethernet frame and calls the given closure
    /// `f` with the raw packet as argument.
    ///
    /// If there is no packet ready to be read `None` is returned.
    ///
    pub fn read_packet<F, R>(&mut self, f: F) -> Option<R>
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let range = self.get_packet_range()?;
        let packet = &mut self.rx_buf.peek_mut()[range];
        let packet_len = packet.len();

        let result = f(packet);

        self.rx_buf.discard(packet_len + EEM_HEADER_SIZE);

        Some(result)
    }

    /// Queues a single Ethernet frame of given length.
    ///
    /// This method allocates `len` bytes in the TX buffer and calls the given
    /// closure `f` with mutable slice to the buffer as argument.
    ///
    /// Packet is queued only if the closure returns a non-error value. If there
    /// is not enough space in the TX buffer `None` is returned, otherwise
    /// return value of closure is propagated to the caller.
    pub fn prepare_packet<F, T, E>(
        &mut self,
        mut len: usize,
        f: F,
    ) -> Option<::core::result::Result<T, E>>
    where
        F: FnOnce(&mut [u8]) -> ::core::result::Result<T, E>,
    {
        const CRC_LEN: usize = 4;

        len += CRC_LEN;

        assert_eq!(len & 0x3fff, len);
        let eem_header: u16 = len as u16;

        let r = if self.tx_buf.free() >= len + EEM_HEADER_SIZE {
            let eem_header_bytes = eem_header.to_le_bytes();
            let buf = self.tx_buf.get_free(len + EEM_HEADER_SIZE);
            buf[0] = eem_header_bytes[0];
            buf[1] = eem_header_bytes[1];

            // CRC takes last 4 bytes
            let crc = &mut buf[EEM_HEADER_SIZE + len - CRC_LEN..];
            // Use sentinel instead of a real CRC
            // see CDC EEM specification section 5.1.2.1
            crc.copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

            let r = f(&mut buf[EEM_HEADER_SIZE..EEM_HEADER_SIZE + len - CRC_LEN]);
            if r.is_err() {
                // If callback returned an error, don't queue the packet
                self.tx_buf.discard_back(len + EEM_HEADER_SIZE);
            } else {
                self.tx_state_resume();
            }

            Some(r)
        } else {
            None
        };

        self.do_tx();
        r
    }

    /// Transfers as much data as possible to the host.
    fn do_tx(&mut self) {
        if self.link_status == LinkStatus::Down {
            return;
        }

        if self.tx_state == TxState::InProgress {
            let len = self.tx_buf.len();
            if len != 0 {
                let mut left = len;
                let mut total_written = 0;

                while left > 0 {
                    let n = min(self.max_packet_size as usize, left);

                    match self
                        .ep_in
                        .write(&self.tx_buf.peek()[total_written..total_written + n])
                    {
                        Ok(w) => {
                            total_written += w;
                            left -= w;
                        }
                        Err(UsbError::WouldBlock) => {
                            // Freeze data transfers till previous transfers are
                            // complete
                            self.tx_state_freeze();
                            break;
                        }
                        Err(e) => {
                            error!("TX failed: {:?}", e);
                        }
                    }
                }

                if total_written > 0 {
                    self.tx_buf.discard(total_written);
                    trace!("wrote {} bytes", total_written);

                    if self.tx_buf.is_empty() && self.tx_state != TxState::Frozen {
                        // TODO: we should send a short packet here (if last
                        // packet wasn't short)
                        //
                        // Probably we should also periodically send a short
                        // packet (every N Ethernet frames) to ensure host
                        // receives these packets right in time
                        self.tx_state = TxState::Idle;
                    }
                }
            }
        }
    }
}

impl<B> UsbClass<B> for EemDriver<'_, B>
where
    B: UsbBus,
{
    fn get_configuration_descriptors(
        &self,
        writer: &mut DescriptorWriter,
    ) -> usb_device::Result<()> {
        // See CDC EEM specification section 3.2 - Class-Specific Codes for EEM Devices
        writer.interface_alt(
            self.interface,
            0,
            0x02,
            0x0C,
            0x07,
            Some(self.str_interface_name),
        )?;
        writer.endpoint(&self.ep_in)?;
        writer.endpoint(&self.ep_out)?;
        Ok(())
    }

    fn get_string(&self, index: StringIndex, lang_id: u16) -> Option<&str> {
        let _ = (index, lang_id);

        if lang_id == 0x409 {
            if index == self.str_interface_name {
                return Some("Virtual Ethernet interface");
            }
        }

        None
    }

    fn reset(&mut self) {
        self.rx_buf.discard_all();
        self.tx_buf.discard_all();
        self.tx_state = TxState::Idle;
        self.link_status = LinkStatus::Down;
    }

    fn poll(&mut self) {
        // FIXME: host passing too big EEM packets can crash Fobnail:
        // if EEM packet length exceeds rx_buf length, buffer will fill
        // triggering assertion below
        // To fix this driver must discard packets exceeding MTU

        // assert!(self.rx_buf.free() >= self.max_packet_size as usize);

        match self.rx_buf.read_from_ep(&self.ep_out) {
            Ok(0) | Err(UsbError::WouldBlock) => {}
            Err(UsbError::BufferOverflow) => {}
            Err(e) => {
                error!("USB error: {:?}", e)
            }
            Ok(_) => {
                // Set link status to UP on first packet coming from host
                self.link_status = LinkStatus::Up;

                while self.handle_command_packet() {}
            }
        };

        self.do_tx();
    }

    fn endpoint_in_complete(&mut self, addr: EndpointAddress) {
        if addr == self.ep_in.address() {
            self.tx_state_unfreeze();
        }
    }
}
