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

/// A wrapper to handle TDS prelogin packet framing during TLS handshakes.
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

    pub fn handshake_complete(&mut self) {
        self.pending_handshake = false;
        debug_assert!(self.pending_len == 0, "pending TLS handshake data not flushed");
        self.wr_buf.clear();
        self.wr_pos = 0;
        self.pending_len = 0;
    }

    pub fn take_stream(&mut self) -> Option<S> {
        self.stream.take()
    }

    pub fn into_inner(self) -> Option<S> {
        self.stream
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

            // We only get pre-login packets in the handshake process.
            assert_eq!(header.r#type(), PacketType::PreLogin);

            // And we know from this point on how much data we should expect
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
