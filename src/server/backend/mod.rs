//! Network backend abstraction for the TDS server.
//!
//! This mirrors the pgwire-smol `backend` module and keeps the server
//! runtime-agnostic.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::Error;

#[cfg(feature = "server-smol")]
pub mod smol_net;

#[cfg(feature = "server-smol")]
pub use smol_net::SmolNetBackend as DefaultBackend;

/// Network backend abstraction for compile-time selectable implementations.
pub trait NetBackend: Send + Sync + 'static {
    /// The listener type that accepts incoming connections.
    type Listener: NetListener<Stream = Self::Stream>;

    /// The stream type representing a single TCP connection.
    type Stream: NetStream;

    /// Bind to an address and create a listener.
    fn bind(addr: &str) -> impl Future<Output = Result<Self::Listener, Error>> + Send;
}

/// Trait for connection listeners.
pub trait NetListener: Send + Sync {
    /// The stream type produced by this listener.
    type Stream: NetStream;

    /// Accept a new connection.
    fn accept(&self) -> impl Future<Output = Result<(Self::Stream, SocketAddr), Error>> + Send;

    /// Returns the local address this listener is bound to.
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

/// Trait for network streams (TCP connections).
///
/// Mirrors `futures::AsyncRead + AsyncWrite` but is defined locally to
/// avoid tying the server to a specific async runtime.
pub trait NetStream: Send + Sync + Unpin + 'static {
    /// Attempt to read data from the stream.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>>;

    /// Attempt to write data to the stream.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>>;

    /// Attempt to flush the stream.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>>;

    /// Attempt to close the stream.
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>>;

    /// Returns the remote address of this connection.
    fn peer_addr(&self) -> io::Result<SocketAddr>;

    /// Returns the local address of this connection.
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

/// Helper trait for reading from a NetStream using async/await.
pub trait NetStreamExt: NetStream {
    /// Read data from the stream.
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> ReadFuture<'a, Self>
    where
        Self: Sized,
    {
        ReadFuture { stream: self, buf }
    }

    /// Write data to the stream.
    fn write<'a>(&'a mut self, buf: &'a [u8]) -> WriteFuture<'a, Self>
    where
        Self: Sized,
    {
        WriteFuture { stream: self, buf }
    }

    /// Flush the stream.
    fn flush(&mut self) -> FlushFuture<'_, Self>
    where
        Self: Sized,
    {
        FlushFuture { stream: self }
    }

    /// Close the stream.
    fn close(&mut self) -> CloseFuture<'_, Self>
    where
        Self: Sized,
    {
        CloseFuture { stream: self }
    }
}

impl<T: NetStream> NetStreamExt for T {}

/// Future for reading from a NetStream.
pub struct ReadFuture<'a, S: NetStream> {
    stream: &'a mut S,
    buf: &'a mut [u8],
}

impl<S: NetStream> Future for ReadFuture<'_, S> {
    type Output = io::Result<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        Pin::new(&mut *this.stream).poll_read(cx, this.buf)
    }
}

/// Future for writing to a NetStream.
pub struct WriteFuture<'a, S: NetStream> {
    stream: &'a mut S,
    buf: &'a [u8],
}

impl<S: NetStream> Future for WriteFuture<'_, S> {
    type Output = io::Result<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        Pin::new(&mut *this.stream).poll_write(cx, this.buf)
    }
}

/// Future for flushing a NetStream.
pub struct FlushFuture<'a, S: NetStream> {
    stream: &'a mut S,
}

impl<S: NetStream> Future for FlushFuture<'_, S> {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut *self.stream).poll_flush(cx)
    }
}

/// Future for closing a NetStream.
pub struct CloseFuture<'a, S: NetStream> {
    stream: &'a mut S,
}

impl<S: NetStream> Future for CloseFuture<'_, S> {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut *self.stream).poll_close(cx)
    }
}
