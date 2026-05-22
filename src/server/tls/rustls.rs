//! Rustls-based TLS acceptor for the TDS server.

#![cfg(feature = "server-rustls")]

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_rustls::server::TlsStream as RustlsTlsStream;
use async_rustls::TlsAcceptor as AsyncRustlsAcceptor;
use futures_util::io::{AsyncRead, AsyncWrite};

use crate::server::backend::NetStream;
use crate::server::tls::{NetStreamCompat, TlsAccept, TlsStream};
use crate::tds::tls::TlsPreloginWrapper;
use crate::Error;

/// Rustls-based TLS acceptor for server-side TDS connections.
#[derive(Clone)]
pub struct RustlsAcceptor {
    inner: AsyncRustlsAcceptor,
}

impl RustlsAcceptor {
    pub fn new(mut config: Arc<async_rustls::rustls::ServerConfig>) -> Self {
        // TLS 1.3 tickets are post-handshake messages that don't fit TDS prelogin framing.
        Arc::make_mut(&mut config).send_tls13_tickets = 0;
        Self {
            inner: AsyncRustlsAcceptor::from(config),
        }
    }
}

impl From<Arc<async_rustls::rustls::ServerConfig>> for RustlsAcceptor {
    fn from(config: Arc<async_rustls::rustls::ServerConfig>) -> Self {
        Self::new(config)
    }
}

impl TlsAccept for RustlsAcceptor {
    type Stream<S: NetStream> = RustlsStream<S>;

    async fn accept<S: NetStream>(&self, stream: S) -> Result<Self::Stream<S>, Error> {
        let peer_addr = stream.peer_addr().unwrap_or_else(|_| placeholder_addr());
        let local_addr = stream.local_addr().unwrap_or_else(|_| placeholder_addr());

        let wrapper = TlsPreloginWrapper::new(NetStreamCompat::new(stream));
        let mut tls_stream = self.inner.accept(wrapper).await?;
        tls_stream.get_mut().0.handshake_complete();

        Ok(RustlsStream::new(tls_stream, peer_addr, local_addr))
    }
}

/// TLS stream wrapper that keeps address metadata.
pub struct RustlsStream<S: NetStream> {
    inner: RustlsTlsStream<TlsPreloginWrapper<NetStreamCompat<S>>>,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
}

impl<S: NetStream> RustlsStream<S> {
    fn new(
        inner: RustlsTlsStream<TlsPreloginWrapper<NetStreamCompat<S>>>,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> Self {
        Self {
            inner,
            peer_addr,
            local_addr,
        }
    }
}

impl<S: NetStream> TlsStream<S> for RustlsStream<S> {
    fn into_raw(self) -> Result<S, Error> {
        let (wrapper, _session) = self.inner.into_inner();
        let io = wrapper
            .into_inner()
            .ok_or_else(|| Error::Protocol("tls stream missing raw io".into()))?;
        Ok(io.into_inner())
    }
}

impl<S: NetStream> NetStream for RustlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }

    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.peer_addr)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

fn placeholder_addr() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 0))
}
