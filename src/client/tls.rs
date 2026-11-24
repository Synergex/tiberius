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

    /// Room for a packet header, then the handshake bytes written since the
    /// last flush.
    wr_buf: Vec<u8>,
    /// Whether `wr_buf` holds an encoded packet that is still being sent.
    sending: bool,
    /// How much of that packet is already sent.
    wr_pos: usize,
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
            wr_buf: vec![0u8; HEADER_BYTES],
            sending: false,
            wr_pos: 0,
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
            !self.sending && self.wr_buf.len() == HEADER_BYTES,
            "pending TLS handshake data not flushed"
        );
        self.wr_buf = Vec::new();
        self.sending = false;
        self.wr_pos = 0;
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> TlsPreloginWrapper<S> {
    /// Sends the handshake bytes written since the last flush as one PRELOGIN
    /// packet. A TLS library may write a handshake flight in several calls
    /// (rustls writes each record on its own), but SQL Server reads every
    /// end-of-message packet as a whole flight and drops the connection when
    /// a flight arrives split across several.
    // Without a TLS feature nothing constructs the wrapper.
    #[cfg_attr(
        not(any(
            feature = "rustls",
            feature = "native-tls",
            feature = "vendored-openssl"
        )),
        allow(dead_code)
    )]
    fn poll_send_packet(&mut self, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        if !self.sending {
            if self.wr_buf.len() == HEADER_BYTES {
                return Poll::Ready(Ok(()));
            }

            let id = self.packet_id;
            self.packet_id = self.packet_id.wrapping_add(1).max(1);

            let mut header = PacketHeader::new(self.wr_buf.len(), id);
            header.set_type(PacketType::PreLogin);
            header.set_status(PacketStatus::EndOfMessage);
            header
                .encode(&mut &mut self.wr_buf[0..HEADER_BYTES])
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "Could not encode header.")
                })?;

            self.sending = true;
            self.wr_pos = 0;

            event!(
                Level::TRACE,
                "Writing a packet of {} bytes",
                self.wr_buf.len()
            );
        }

        while self.wr_pos < self.wr_buf.len() {
            let written =
                ready!(Pin::new(self.stream.as_mut().unwrap())
                    .poll_write(cx, &self.wr_buf[self.wr_pos..]))?;

            if written == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write data",
                )));
            }

            self.wr_pos += written;
        }

        self.wr_buf.truncate(HEADER_BYTES);
        self.sending = false;
        self.wr_pos = 0;

        Poll::Ready(Ok(()))
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

        // A packet on its way already has its length in the header, so it
        // goes out before more bytes join the buffer.
        if inner.sending {
            ready!(inner.poll_send_packet(cx))?;
        }

        // The bytes wait for the flush that ends the flight.
        inner.wr_buf.extend_from_slice(buf);

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        let inner = self.get_mut();

        if inner.pending_handshake {
            ready!(inner.poll_send_packet(cx))?;
        }

        Pin::new(&mut inner.stream.as_mut().unwrap()).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream.as_mut().unwrap()).poll_close(cx)
    }
}

#[cfg(all(
    test,
    any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    )
))]
mod tests {
    use super::*;
    use futures_util::io::AsyncWriteExt;
    use std::task::{Context, Waker};

    /// Records what reaches the wire. Accepts at most `max_write` bytes per
    /// call and, with `stall`, returns `Pending` before every write.
    struct Wire {
        written: Vec<u8>,
        max_write: usize,
        stall: bool,
        stalled: bool,
    }

    impl Wire {
        fn new(max_write: usize, stall: bool) -> Self {
            Wire {
                written: Vec::new(),
                max_write,
                stall,
                stalled: false,
            }
        }
    }

    impl AsyncRead for Wire {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut task::Context<'_>,
            _: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(0))
        }
    }

    impl AsyncWrite for Wire {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut task::Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if this.stall && !this.stalled {
                this.stalled = true;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            this.stalled = false;
            let count = buf.len().min(this.max_write);
            this.written.extend_from_slice(&buf[..count]);
            Poll::Ready(Ok(count))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut task::Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _: &mut task::Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn prelogin_packet(id: u8, payload: &[u8]) -> Vec<u8> {
        let length = (HEADER_BYTES + payload.len()) as u16;
        let mut packet = vec![PacketType::PreLogin as u8, PacketStatus::EndOfMessage as u8];
        packet.extend(length.to_be_bytes());
        packet.extend([0, 0, id, 0]);
        packet.extend(payload);
        packet
    }

    fn written(wrapper: &TlsPreloginWrapper<Wire>) -> &[u8] {
        &wrapper.stream.as_ref().unwrap().written
    }

    #[tokio::test]
    async fn a_flight_written_in_pieces_goes_out_as_one_packet() {
        let mut wrapper = TlsPreloginWrapper::new(Wire::new(usize::MAX, false));

        // Like rustls: one write per TLS record, then a flush.
        for record in [&b"key exchange"[..], b"change cipher", b"finished"] {
            wrapper.write_all(record).await.unwrap();
        }
        assert!(written(&wrapper).is_empty());
        wrapper.flush().await.unwrap();

        wrapper.write_all(b"second flight").await.unwrap();
        wrapper.flush().await.unwrap();

        let mut expected = prelogin_packet(1, b"key exchangechange cipherfinished");
        expected.extend(prelogin_packet(2, b"second flight"));
        assert_eq!(written(&wrapper), &expected[..]);
    }

    #[tokio::test]
    async fn a_flush_with_nothing_buffered_sends_nothing() {
        let mut wrapper = TlsPreloginWrapper::new(Wire::new(usize::MAX, false));
        wrapper.flush().await.unwrap();
        assert!(written(&wrapper).is_empty());
    }

    #[test]
    fn a_half_sent_packet_goes_out_before_new_bytes_join_the_buffer() {
        let mut cx = Context::from_waker(Waker::noop());
        let mut wrapper = TlsPreloginWrapper::new(Wire::new(3, true));

        assert!(matches!(
            Pin::new(&mut wrapper).poll_write(&mut cx, b"first"),
            Poll::Ready(Ok(5))
        ));

        // The flush stalls after the wire took 3 bytes of the packet.
        let mut flushed = Pin::new(&mut wrapper).poll_flush(&mut cx);
        while written(&wrapper).len() < 3 {
            assert!(flushed.is_pending());
            flushed = Pin::new(&mut wrapper).poll_flush(&mut cx);
        }
        assert!(flushed.is_pending());

        let accepted = loop {
            match Pin::new(&mut wrapper).poll_write(&mut cx, b"second") {
                Poll::Ready(result) => break result.unwrap(),
                Poll::Pending => continue,
            }
        };
        assert_eq!(accepted, 6);
        while Pin::new(&mut wrapper).poll_flush(&mut cx).is_pending() {}

        let mut expected = prelogin_packet(1, b"first");
        expected.extend(prelogin_packet(2, b"second"));
        assert_eq!(written(&wrapper), &expected[..]);
    }

    #[tokio::test]
    async fn writes_after_the_handshake_pass_through_unchanged() {
        let mut wrapper = TlsPreloginWrapper::new(Wire::new(usize::MAX, false));
        wrapper.handshake_complete();
        wrapper.write_all(b"tds packet").await.unwrap();
        assert_eq!(written(&wrapper), b"tds packet");
    }
}

#[cfg(all(test, feature = "native-tls"))]
pub(crate) mod session_tests {
    use super::TlsPreloginWrapper;
    use crate::{AuthMethod, Client, Config, EncryptionLevel};
    use async_rustls::rustls;
    use futures_util::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use std::{sync::Arc, time::Duration};
    use tokio_util::compat::TokioAsyncReadCompatExt;

    /// The test server's TLS setup. It is rustls, not native-tls: on Windows,
    /// native-tls leaves every imported key in the user's key store.
    pub(crate) fn peer_config() -> Arc<rustls::ServerConfig> {
        let chain = [
            &include_bytes!("../../tests/security-fixtures/server.pem")[..],
            include_bytes!("../../tests/security-fixtures/ca.pem"),
        ]
        .into_iter()
        .flat_map(|mut pem| rustls_pemfile::certs(&mut pem).unwrap())
        .map(rustls::Certificate)
        .collect();
        let key = rustls_pemfile::pkcs8_private_keys(
            &mut &include_bytes!("../../tests/security-fixtures/server.key")[..],
        )
        .unwrap()
        .remove(0);
        let config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(chain, rustls::PrivateKey(key))
            .unwrap();
        Arc::new(config)
    }

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

    // async-rustls is deprecated only as renamed to futures-rustls; the
    // server-rustls feature already depends on it.
    #[allow(deprecated)]
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
                    let acceptor = async_rustls::TlsAcceptor::from(peer_config());
                    let mut tls = acceptor.accept(wrapper).await.unwrap();
                    tls.get_mut().0.handshake_complete();
                    if strict {
                        assert_eq!(read_packet(&mut tls).await.0, 0x12);
                        prelogin_response(&mut tls, offered).await;
                    }
                    assert_eq!(read_packet(&mut tls).await.0, 0x10);
                    if !encrypted {
                        // Login-only TLS ends immediately after LOGIN7;
                        // the login response and query must be plaintext.
                        let mut raw = tls.get_mut().0.stream.take().unwrap();
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
