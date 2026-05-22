//! TLS support for the TDS server.
//!
//! This mirrors pgwire-smol's TLS abstraction but keeps the server runtime-agnostic.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

#[cfg(feature = "server-rustls")]
use futures_util::io::{AsyncRead, AsyncWrite};

use crate::server::backend::NetStream;
use crate::Error;

#[cfg(feature = "server-rustls")]
pub mod rustls;

#[cfg(feature = "server-rustls")]
pub use rustls::RustlsAcceptor;

/// TLS stream behavior that allows downgrading back to the raw stream.
pub trait TlsStream<S: NetStream>: NetStream {
    /// Consume the TLS stream and return the underlying raw stream.
    fn into_raw(self) -> Result<S, Error>;
}

/// Adapter that exposes a NetStream as a futures AsyncRead/AsyncWrite stream.
#[cfg(feature = "server-rustls")]
pub(crate) struct NetStreamCompat<S> {
    inner: S,
}

#[cfg(feature = "server-rustls")]
impl<S> NetStreamCompat<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

#[cfg(feature = "server-rustls")]
impl<S: NetStream> AsyncRead for NetStreamCompat<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(feature = "server-rustls")]
impl<S: NetStream> AsyncWrite for NetStreamCompat<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

/// Stream wrapper that can switch between raw and TLS connections.
pub(crate) enum MaybeTlsStream<S, T> {
    Raw(S),
    Tls(T),
    Poisoned,
}

impl<S, T> MaybeTlsStream<S, T> {
    pub fn new_raw(stream: S) -> Self {
        Self::Raw(stream)
    }

    pub fn take_raw(&mut self) -> Option<S> {
        match std::mem::replace(self, Self::Poisoned) {
            Self::Raw(stream) => Some(stream),
            other => {
                *self = other;
                None
            }
        }
    }

    pub fn take_tls(&mut self) -> Option<T> {
        match std::mem::replace(self, Self::Poisoned) {
            Self::Tls(stream) => Some(stream),
            other => {
                *self = other;
                None
            }
        }
    }

    pub fn set_raw(&mut self, stream: S) {
        *self = Self::Raw(stream);
    }

    pub fn set_tls(&mut self, stream: T) {
        *self = Self::Tls(stream);
    }
}

impl<S, T> MaybeTlsStream<S, T>
where
    S: NetStream,
    T: TlsStream<S>,
{
    pub fn downgrade(&mut self) -> Result<(), Error> {
        let tls = self
            .take_tls()
            .ok_or_else(|| Error::Protocol("tls downgrade requires a tls stream".into()))?;
        let raw = tls.into_raw()?;
        self.set_raw(raw);
        Ok(())
    }
}

/// Trait for TLS acceptors that can upgrade a plain connection to TLS.
pub trait TlsAccept: Send + Sync + Clone + 'static {
    /// The TLS stream type produced after a successful handshake.
    type Stream<S: NetStream>: TlsStream<S>;

    /// Perform a TLS handshake on the given stream.
    fn accept<S: NetStream>(
        &self,
        stream: S,
    ) -> impl Future<Output = Result<Self::Stream<S>, Error>> + Send;
}

/// Marker type indicating TLS is not configured.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoTls;

impl TlsAccept for NoTls {
    type Stream<S: NetStream> = NoTlsStream;

    async fn accept<S: NetStream>(&self, _stream: S) -> Result<Self::Stream<S>, Error> {
        Err(crate::Error::Protocol("TLS not supported".into()))
    }
}

/// Placeholder stream type for NoTls.
pub struct NoTlsStream(());

impl NetStream for NoTlsStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "NoTlsStream should never be constructed",
        )))
    }

    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "NoTlsStream should never be constructed",
        )))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "NoTlsStream should never be constructed",
        )))
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "NoTlsStream should never be constructed",
        )))
    }

    fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "NoTlsStream should never be constructed",
        ))
    }

    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "NoTlsStream should never be constructed",
        ))
    }
}

impl<S: NetStream> TlsStream<S> for NoTlsStream {
    fn into_raw(self) -> Result<S, Error> {
        Err(crate::Error::Protocol(
            "NoTlsStream cannot be downgraded".into(),
        ))
    }
}

impl<S: NetStream, T: NetStream> NetStream for MaybeTlsStream<S, T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Raw(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Poisoned => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "stream is in invalid state",
            ))),
        }
    }

    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Raw(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Poisoned => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "stream is in invalid state",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Raw(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
            Self::Poisoned => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "stream is in invalid state",
            ))),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Raw(stream) => Pin::new(stream).poll_close(cx),
            Self::Tls(stream) => Pin::new(stream).poll_close(cx),
            Self::Poisoned => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "stream is in invalid state",
            ))),
        }
    }

    fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        match self {
            Self::Raw(stream) => stream.peer_addr(),
            Self::Tls(stream) => stream.peer_addr(),
            Self::Poisoned => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "stream is in invalid state",
            )),
        }
    }

    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        match self {
            Self::Raw(stream) => stream.local_addr(),
            Self::Tls(stream) => stream.local_addr(),
            Self::Poisoned => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "stream is in invalid state",
            )),
        }
    }
}
