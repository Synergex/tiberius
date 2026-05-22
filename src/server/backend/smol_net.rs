//! Portable async-net backend for the TDS server.

use async_net::{TcpListener, TcpStream};
use futures_lite::io::{AsyncRead, AsyncWrite};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::server::backend::{NetBackend, NetListener, NetStream};
use crate::Error;

/// Portable async-net based network backend.
pub struct SmolNetBackend;

impl NetBackend for SmolNetBackend {
    type Listener = SmolListener;
    type Stream = SmolStream;

    fn bind(addr: &str) -> impl std::future::Future<Output = Result<Self::Listener, Error>> + Send {
        async move {
            let listener = TcpListener::bind(addr).await?;
            Ok(SmolListener(listener))
        }
    }
}

/// TCP listener wrapper for async-net.
pub struct SmolListener(TcpListener);

impl NetListener for SmolListener {
    type Stream = SmolStream;

    fn accept(
        &self,
    ) -> impl std::future::Future<Output = Result<(Self::Stream, SocketAddr), Error>> + Send {
        async move {
            let (stream, addr) = self.0.accept().await?;
            Ok((SmolStream::new(stream), addr))
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.0.local_addr()
    }
}

/// TCP stream wrapper for async-net.
pub struct SmolStream(TcpStream);

impl SmolStream {
    /// Create a SmolStream from a raw async-net TcpStream.
    pub fn new(stream: TcpStream) -> Self {
        Self(stream)
    }

    /// Get a reference to the inner stream.
    pub fn inner(&self) -> &TcpStream {
        &self.0
    }

    /// Get a mutable reference to the inner stream.
    pub fn inner_mut(&mut self) -> &mut TcpStream {
        &mut self.0
    }

    /// Consume this wrapper and return the inner stream.
    pub fn into_inner(self) -> TcpStream {
        self.0
    }
}

impl NetStream for SmolStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }

    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_close(cx)
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.0.peer_addr()
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.0.local_addr()
    }
}
