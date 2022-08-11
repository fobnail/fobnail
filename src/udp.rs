use core::{
    fmt::Debug,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use alloc::{boxed::Box, vec::Vec};

use coap_lite::Packet;
use coap_server::transport::{BoxedFramedBinding, FramedBinding, Transport, TransportError};
use futures_lite::future::FutureExt;
use futures_util::{Sink, Stream};
use pal::embassy_net::{udp::UdpSocket, IpAddress};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Endpoint {
    ip: IpAddress,
    port: u16,
}

impl Debug for Endpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}

pub struct UdpTransport<'a> {
    // FIXME: socket should be 'a not 'static
    socket: UdpSocket<'static>,
    port: u16,
    phantom: PhantomData<&'a ()>,
}

// FIXME: temporary workaround
unsafe impl Send for UdpTransport<'_> {}

impl<'a> UdpTransport<'a> {
    pub fn new(socket: UdpSocket<'static>, port: u16) -> Self {
        Self {
            socket,
            port,
            phantom: PhantomData,
        }
    }
}

impl<'a> Transport for UdpTransport<'a> {
    type Endpoint = Endpoint;

    fn bind<'async_trait>(
        self,
    ) -> core::pin::Pin<
        Box<
            dyn core::future::Future<
                    Output = Result<BoxedFramedBinding<Self::Endpoint>, TransportError>,
                > + core::marker::Send
                + 'async_trait,
        >,
    >
    where
        Self: 'async_trait,
    {
        let Self {
            mut socket, port, ..
        } = self;

        socket.bind(port).unwrap();
        // FIXME: fetch MTU from driver
        let binding = UdpBinding::new(socket, 1500);
        let binding: BoxedFramedBinding<Self::Endpoint> = Box::pin(binding);

        Box::pin(async move { Ok(binding) })
    }
}

#[pin_project]
struct UdpBinding<'a> {
    #[pin]
    socket: UdpSocket<'a>,
    packet: Vec<u8>,
    target: Option<Endpoint>,
    mtu: u32,
    recv_buf: Vec<u8>,
}

impl<'a> UdpBinding<'a> {
    pub fn new(socket: UdpSocket<'a>, mtu: u32) -> Self {
        let mut recv_buf = Vec::new();
        recv_buf.resize(mtu as usize, 0);

        Self {
            socket,
            packet: Vec::new(),
            target: None,
            mtu,
            recv_buf,
        }
    }
}

// FIXME: temporary workaround
unsafe impl Send for UdpBinding<'_> {}

#[async_trait]
impl FramedBinding<Endpoint> for UdpBinding<'_> {
    fn mtu(&self) -> Option<u32> {
        Some(self.mtu)
    }
}

impl Stream for UdpBinding<'_> {
    type Item = Result<(Packet, Endpoint), (TransportError, Option<Endpoint>)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Self {
            socket, recv_buf, ..
        } = &mut *self;

        if !socket.may_recv() {
            // Wake immediately
            // FIXME: instead we should register waker.
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        let n;
        let ep;

        {
            let fut = socket.recv_from(&mut recv_buf[..]);
            futures_util::pin_mut!(fut);

            match fut.poll(cx) {
                Poll::Ready(Ok((x_n, x_ep))) => {
                    n = x_n;
                    ep = x_ep;
                }
                Poll::Ready(Err(e)) => {
                    error!("CoAP UDP error: {:?}", e);
                    return Poll::Pending;
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        match Packet::from_bytes(&recv_buf[..n]) {
            Ok(p) => Poll::Ready(Some(Ok((
                p,
                Endpoint {
                    ip: ep.addr,
                    port: ep.port,
                },
            )))),
            Err(e) => {
                error!("malformed CoAP packet: {}", e);
                Poll::Pending
            }
        }
    }
}

impl Sink<(Packet, Endpoint)> for UdpBinding<'_> {
    type Error = TransportError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.project().socket.may_send() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: (Packet, Endpoint)) -> Result<(), Self::Error> {
        // TODO: error handling
        let buffer = item.0.to_bytes().unwrap();
        self.packet = buffer;
        self.target = Some(item.1);
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let Self {
            packet,
            target,
            socket,
            ..
        } = &mut *self;

        {
            let target_u = target.unwrap();
            let fut = socket.send_to(&packet, (target_u.ip, target_u.port));
            futures_util::pin_mut!(fut);
            match fut.poll(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(_)) => {
                    panic!("TODO: error handling");
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        packet.clear();
        *target = None;
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.socket.close();
        Poll::Ready(Ok(()))
    }
}
