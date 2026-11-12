#[cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]
use super::tls_stream::TlsStream;
use crate::tds::{
    codec::{Decode, Encode, PacketHeader, PacketStatus, PacketType},
    HEADER_BYTES,
};
use bytes::BytesMut;
use futures_util::io::{AsyncRead, AsyncWrite};
use futures_util::ready;
use std::{
    cmp, io,
    pin::Pin,
    task::{self, Poll},
};
use tracing::{event, Level};

/// A wrapper to handle either TLS or bare connections.
pub(crate) enum MaybeTlsStream<S: AsyncRead + AsyncWrite + Unpin + Send> {
    Raw(S),
    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    Tls(TlsStream<TlsPreloginWrapper<S>>),
}

#[cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]
impl<S: AsyncRead + AsyncWrite + Unpin + Send> MaybeTlsStream<S> {
    pub fn into_inner(self) -> S {
        match self {
            Self::Raw(s) => s,
            #[cfg(any(
                feature = "rustls",
                feature = "native-tls",
                feature = "vendored-openssl"
            ))]
            Self::Tls(mut tls) => tls.get_mut().stream.take().unwrap(),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for MaybeTlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Raw(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(any(
                feature = "rustls",
                feature = "native-tls",
                feature = "vendored-openssl"
            ))]
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for MaybeTlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Raw(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(any(
                feature = "rustls",
                feature = "native-tls",
                feature = "vendored-openssl"
            ))]
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Raw(s) => Pin::new(s).poll_flush(cx),
            #[cfg(any(
                feature = "rustls",
                feature = "native-tls",
                feature = "vendored-openssl"
            ))]
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Raw(s) => Pin::new(s).poll_close(cx),
            #[cfg(any(
                feature = "rustls",
                feature = "native-tls",
                feature = "vendored-openssl"
            ))]
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_close(cx),
        }
    }
}

/// On TLS handshake, the server expects to get and sends back normal TDS
/// packets. To use a common TLS library, we must implement a wrapper for
/// packet handling on this stage.
///
/// What it does is it interferes on handshake for TDS packet handling,
/// and when complete, just passes the calls to the underlying connection.
pub(crate) struct TlsPreloginWrapper<S> {
    stream: Option<S>,
    pending_handshake: bool,

    header_buf: [u8; HEADER_BYTES],
    header_pos: usize,
    read_remaining: usize,

    wr_buf: Vec<u8>,
    wr_pos: usize,
    pending_len: usize,
    packet_id: u8,
}

#[cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]
impl<S> TlsPreloginWrapper<S> {
    pub fn new(stream: S) -> Self {
        TlsPreloginWrapper {
            stream: Some(stream),
            pending_handshake: true,

            header_buf: [0u8; HEADER_BYTES],
            header_pos: 0,
            read_remaining: 0,
            wr_buf: Vec::new(),
            wr_pos: 0,
            pending_len: 0,
            packet_id: 1,
        }
    }

    /// TDS 8 carries the TLS handshake directly, without TDS packet headers.
    pub fn tls_first(stream: S) -> Self {
        let mut wrapper = Self::new(stream);
        wrapper.pending_handshake = false;
        wrapper
    }

    pub fn handshake_complete(&mut self) {
        self.pending_handshake = false;
        debug_assert!(
            self.pending_len == 0,
            "pending TLS handshake data not flushed"
        );
        self.wr_buf.clear();
        self.wr_pos = 0;
        self.pending_len = 0;
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for TlsPreloginWrapper<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        // Normal operation does not need any extra treatment, we handle packets
        // in the codec.
        if !self.pending_handshake {
            return Pin::new(&mut self.stream.as_mut().unwrap()).poll_read(cx, buf);
        }

        let inner = self.get_mut();

        // Read the headers separately and do not send them to the Tls
        // connection handling.
        if !inner.header_buf[inner.header_pos..].is_empty() {
            while !inner.header_buf[inner.header_pos..].is_empty() {
                let read = ready!(Pin::new(inner.stream.as_mut().unwrap())
                    .poll_read(cx, &mut inner.header_buf[inner.header_pos..]))?;

                if read == 0 {
                    return Poll::Ready(Ok(0));
                }

                inner.header_pos += read;
            }

            let header = PacketHeader::decode(&mut BytesMut::from(&inner.header_buf[..]))
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

            // Reject malformed peers with an I/O error, rather than panicking
            // or underflowing.
            if header.r#type() != PacketType::PreLogin || header.length() as usize <= HEADER_BYTES {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid TDS TLS handshake packet",
                )));
            }

            inner.read_remaining = header.length() as usize - HEADER_BYTES;

            event!(
                Level::TRACE,
                "Reading packet of {} bytes",
                inner.read_remaining,
            );
        }

        let max_read = cmp::min(inner.read_remaining, buf.len());

        // TLS connector gets whatever we have after the header.
        let read = ready!(
            Pin::new(&mut inner.stream.as_mut().unwrap()).poll_read(cx, &mut buf[..max_read])
        )?;

        inner.read_remaining -= read;

        // All data is read, after this we're expecting a new header.
        if inner.read_remaining == 0 {
            inner.header_pos = 0;
        }

        Poll::Ready(Ok(read))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for TlsPreloginWrapper<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Normal operation does not need any extra treatment, we handle
        // packets in the codec.
        if !self.pending_handshake {
            return Pin::new(&mut self.stream.as_mut().unwrap()).poll_write(cx, buf);
        }

        let inner = self.get_mut();
        if inner.pending_len == 0 {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }

            inner.wr_buf.clear();
            inner.wr_buf.resize(HEADER_BYTES, 0);
            let id = inner.packet_id;
            inner.packet_id = inner.packet_id.wrapping_add(1);
            if inner.packet_id == 0 {
                inner.packet_id = 1;
            }
            let mut header = PacketHeader::new(HEADER_BYTES + buf.len(), id);
            header.set_type(PacketType::PreLogin);
            header.set_status(PacketStatus::EndOfMessage);
            header
                .encode(&mut &mut inner.wr_buf[0..HEADER_BYTES])
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "Could not encode header.")
                })?;
            inner.wr_buf.extend_from_slice(buf);
            inner.pending_len = buf.len();
            inner.wr_pos = 0;
        }

        while inner.wr_pos < inner.wr_buf.len() {
            let written = ready!(Pin::new(inner.stream.as_mut().unwrap())
                .poll_write(cx, &inner.wr_buf[inner.wr_pos..]))?;
            if written == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write data",
                )));
            }
            inner.wr_pos += written;
        }

        let len = inner.pending_len;
        inner.pending_len = 0;
        inner.wr_pos = 0;
        inner.wr_buf.clear();

        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        let inner = self.get_mut();

        if inner.pending_handshake && inner.pending_len > 0 {
            while inner.wr_pos < inner.wr_buf.len() {
                event!(
                    Level::TRACE,
                    "Writing a packet of {} bytes",
                    inner.wr_buf.len() - inner.wr_pos,
                );

                let written = ready!(
                    Pin::new(&mut inner.stream.as_mut().unwrap())
                        .poll_write(cx, &inner.wr_buf[inner.wr_pos..])
                )?;

                if written == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write data",
                    )));
                }

                inner.wr_pos += written;
            }

            inner.pending_len = 0;
            inner.wr_pos = 0;
            inner.wr_buf.clear();
        }

        Pin::new(&mut inner.stream.as_mut().unwrap()).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream.as_mut().unwrap()).poll_close(cx)
    }
}

#[cfg(all(test, feature = "native-tls"))]
mod tests {
    use super::TlsPreloginWrapper;
    use crate::{AuthMethod, Client, Config, EncryptionLevel};
    use futures_util::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Cursor};
    use std::time::Duration;
    use tokio_util::compat::TokioAsyncReadCompatExt;

    async fn read_packet<S: AsyncRead + Unpin>(stream: &mut S) -> (u8, Vec<u8>) {
        let mut header = [0; 8];
        stream.read_exact(&mut header).await.unwrap();
        let length = u16::from_be_bytes([header[2], header[3]]) as usize;
        assert!(length >= 8);
        let mut payload = vec![0; length - 8];
        stream.read_exact(&mut payload).await.unwrap();
        (header[0], payload)
    }

    async fn write_packet<S: AsyncWrite + Unpin>(stream: &mut S, payload: &[u8]) {
        let length = (payload.len() + 8) as u16;
        let [high, low] = length.to_be_bytes();
        stream
            .write_all(&[4, 1, high, low, 0, 0, 1, 0])
            .await
            .unwrap();
        stream.write_all(payload).await.unwrap();
        stream.flush().await.unwrap();
    }

    async fn prelogin_response<S: AsyncWrite + Unpin>(stream: &mut S, encryption: u8) {
        write_packet(
            stream,
            &[
                0, 0, 11, 0, 6, 1, 0, 17, 0, 1, 255, 16, 0, 0, 0, 0, 0, encryption,
            ],
        )
        .await;
    }

    async fn login_and_query_response<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) {
        // LOGINACK deliberately uses TDS 7.4 even for TLS-first sessions:
        // TDS 8 is established by the transport, not a new LOGIN7 version.
        write_packet(
            stream,
            &[
                0xad, 10, 0, 1, 0x74, 0, 0, 4, 0, 16, 0, 0, 0, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0,
            ],
        )
        .await;
        assert_eq!(read_packet(stream).await.0, 1);
        write_packet(stream, &[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).await;
    }

    #[tokio::test]
    async fn tls_session_lifecycle() {
        tokio::time::timeout(Duration::from_secs(30), async {
            // Optional: login-only, and server-upgraded full-session TLS.
            // Mandatory: full-session TLS.
            // Strict: OFF/NOT_SUP in PRELOGIN must not downgrade TLS.
            for (strict, requested, offered, encrypted) in [
                (false, EncryptionLevel::Off, 0, false),
                (false, EncryptionLevel::Off, 1, true),
                (false, EncryptionLevel::Off, 3, true),
                (false, EncryptionLevel::Required, 1, true),
                (true, EncryptionLevel::Required, 0, true),
                (true, EncryptionLevel::Required, 2, true),
            ] {
                let (client, server) = tokio::io::duplex(65536);
                let peer = tokio::spawn(async move {
                    let mut server = server.compat();
                    if !strict {
                        assert_eq!(read_packet(&mut server).await.0, 0x12);
                        prelogin_response(&mut server, offered).await;
                    }
                    let wrapper = if strict {
                        TlsPreloginWrapper::tls_first(server)
                    } else {
                        TlsPreloginWrapper::new(server)
                    };
                    let acceptor = async_native_tls::TlsAcceptor::new(
                        Cursor::new(include_bytes!("../../tests/security-fixtures/server.p12")),
                        "",
                    )
                    .await
                    .unwrap();
                    let mut tls = acceptor.accept(wrapper).await.unwrap();
                    tls.get_mut().handshake_complete();
                    if strict {
                        assert_eq!(read_packet(&mut tls).await.0, 0x12);
                        prelogin_response(&mut tls, offered).await;
                    }
                    assert_eq!(read_packet(&mut tls).await.0, 0x10);
                    if !encrypted {
                        // Login-only TLS ends immediately after LOGIN7;
                        // the login response and query must be plaintext.
                        let mut raw = tls.get_mut().stream.take().unwrap();
                        drop(tls);
                        login_and_query_response(&mut raw).await;
                    } else {
                        // Successfully decoding the later batch through TLS
                        // proves the session did not silently unwrap it.
                        login_and_query_response(&mut tls).await;
                    }
                });

                let mut config = Config::new();
                config.host("sql.test");
                config.encryption(requested);
                config.strict_encryption(strict);
                config.trust_cert_ca(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/security-fixtures/ca.pem"
                ));
                config.authentication(AuthMethod::sql_server(
                    "wire-test-user",
                    "wire-test-password",
                ));
                let mut client = Client::connect(config, client.compat()).await.unwrap();
                assert_eq!(client.is_encrypted(), encrypted);
                client
                    .simple_query("SELECT 1")
                    .await
                    .unwrap()
                    .into_results()
                    .await
                    .unwrap();
                assert_eq!(client.is_encrypted(), encrypted);
                peer.await.unwrap();
            }
        })
        .await
        .unwrap();
    }
}
