//! TDS connection abstraction.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{BufMut, BytesMut};
use futures_util::future::poll_fn;
use futures_util::sink::Sink;
use futures_util::stream::Stream;

use crate::server::backend::{NetStream, NetStreamExt};
use crate::server::codec::TdsCodec;
use crate::server::handler::{ConnectionMetadata, TdsConnectionContext};
use crate::server::messages::{
    AllHeaders, BackendToken, TdsBackendMessage, TdsFrontendMessage, TransactionDescriptor,
};
use crate::server::state::TdsConnectionState;
use crate::tds::codec::{
    DoneStatus, Encode, FeatureLevel, Packet, PacketHeader, PacketStatus, PacketType, TokenDone,
    TokenEnvChange,
};
use std::sync::Arc;
use crate::tds::Context as TdsContext;
use crate::Error;
use crate::EncryptionLevel;

/// Buffer size for read/write operations.
const BUFFER_SIZE: usize = 8192;

/// Maximum size for the read buffer to prevent unbounded memory growth.
/// 16 MB should accommodate any reasonable TDS message plus overhead.
const MAX_READ_BUFFER_SIZE: usize = 16 * 1024 * 1024;

// Packet status bit for attention acknowledgement (server-to-client).
const STATUS_ATTENTION_ACK: u8 = 0x02;

/// A TDS connection over any NetStream backend.
pub struct TdsConnection<S: NetStream> {
    stream: S,
    codec: TdsCodec,
    metadata: ConnectionMetadata,
    state: TdsConnectionState,
    context: TdsContext,
    read_buf: BytesMut,
    write_buf: BytesMut,
    needs_flush: bool,
    is_secure: bool,
    encryption: EncryptionLevel,
    pending_messages: VecDeque<TdsFrontendMessage>,
    attention_ack_pending: bool,
    reset_connection_pending: bool,
    message_in_progress: bool,
    socket_addr: SocketAddr,
    last_request_headers: AllHeaders,
}

impl<S: NetStream> TdsConnection<S> {
    /// Create a new connection wrapping the given stream.
    pub fn new(stream: S) -> Self {
        let socket_addr = stream
            .peer_addr()
            .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));

        Self {
            stream,
            codec: TdsCodec::new(),
            metadata: ConnectionMetadata::default(),
            state: TdsConnectionState::AwaitingPrelogin,
            context: TdsContext::new(),
            read_buf: BytesMut::with_capacity(BUFFER_SIZE),
            write_buf: BytesMut::with_capacity(BUFFER_SIZE),
            needs_flush: false,
            is_secure: false,
            encryption: EncryptionLevel::NotSupported,
            pending_messages: VecDeque::new(),
            attention_ack_pending: false,
            reset_connection_pending: false,
            message_in_progress: false,
            socket_addr,
            last_request_headers: AllHeaders::default(),
        }
    }

    /// Get a reference to the codec.
    pub fn codec(&self) -> &TdsCodec {
        &self.codec
    }

    /// Get a mutable reference to the codec.
    pub fn codec_mut(&mut self) -> &mut TdsCodec {
        &mut self.codec
    }

    /// Get the underlying stream.
    pub fn stream(&self) -> &S {
        &self.stream
    }

    /// Get a mutable reference to the underlying stream.
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Mark the connection as secure (TLS enabled).
    pub fn set_secure(&mut self, secure: bool) {
        self.is_secure = secure;
    }

    /// True if an attention/cancel has been observed and not yet acknowledged.
    pub fn attention_pending(&self) -> bool {
        self.state == TdsConnectionState::AttentionPending
    }

    /// Clear the attention/cancel state, transitioning to ReadyForQuery.
    /// Only changes state if currently in AttentionPending.
    pub fn clear_attention(&mut self) {
        if self.state == TdsConnectionState::AttentionPending {
            self.state = TdsConnectionState::ReadyForQuery;
        }
    }

    /// Mark an attention/cancel as pending by transitioning to AttentionPending state.
    pub fn mark_attention(&mut self) {
        self.state = TdsConnectionState::AttentionPending;
    }

    /// Mark a reset connection request as pending.
    pub fn mark_reset_connection(&mut self, skip_tran: bool) {
        self.reset_connection_pending = true;
        if !skip_tran {
            self.context.set_transaction_descriptor([0; 8]);
        }
    }

    pub(crate) fn set_last_request_headers(&mut self, headers: AllHeaders) {
        self.last_request_headers = headers;
    }

    /// Poll for attention messages while inside a handler.
    pub async fn poll_attention(&mut self) -> Result<bool, Error> {
        if self.attention_pending() {
            return Ok(true);
        }

        if let Some(pos) = self
            .pending_messages
            .iter()
            .position(|msg| matches!(msg, TdsFrontendMessage::Attention))
        {
            self.pending_messages.remove(pos);
            self.mark_attention();
            return Ok(true);
        }

        if let Some(msg) = self.try_decode()? {
            return if matches!(msg, TdsFrontendMessage::Attention) {
                self.mark_attention();
                Ok(true)
            } else {
                self.pending_messages.push_back(msg);
                Ok(false)
            };
        }

        let read = poll_fn(|cx| match self.poll_read_buf(cx) {
            Poll::Ready(res) => Poll::Ready(Some(res)),
            Poll::Pending => Poll::Ready(None),
        })
        .await;

        match read {
            Some(Ok(0)) => Ok(false),
            Some(Ok(_)) => match self.try_decode()? {
                Some(msg) => {
                    if matches!(msg, TdsFrontendMessage::Attention) {
                        self.mark_attention();
                        Ok(true)
                    } else {
                        self.pending_messages.push_back(msg);
                        Ok(false)
                    }
                }
                None => Ok(false),
            },
            Some(Err(err)) => Err(err.into()),
            None => Ok(false),
        }
    }

    /// Get the negotiated encryption level.
    pub fn encryption(&self) -> EncryptionLevel {
        self.encryption
    }

    /// Set the negotiated encryption level.
    pub fn set_encryption(&mut self, encryption: EncryptionLevel) {
        self.encryption = encryption;
    }

    /// Write raw bytes to the connection.
    pub async fn write_raw(&mut self, data: &[u8]) -> io::Result<()> {
        let mut written = 0;
        while written < data.len() {
            let n = self.stream.write(&data[written..]).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write data",
                ));
            }
            written += n;
        }
        self.stream.flush().await
    }

    /// Try to read more data into the buffer.
    fn poll_read_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        // Check if buffer would exceed maximum size
        if self.read_buf.len() >= MAX_READ_BUFFER_SIZE {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "read buffer exceeded maximum size",
            )));
        }

        if self.read_buf.capacity() - self.read_buf.len() < 1024 {
            // Only reserve up to the maximum
            let reserve_amount = std::cmp::min(
                BUFFER_SIZE,
                MAX_READ_BUFFER_SIZE.saturating_sub(self.read_buf.len()),
            );
            if reserve_amount > 0 {
                self.read_buf.reserve(reserve_amount);
            }
        }

        let mut tmp = [0u8; BUFFER_SIZE];
        match Pin::new(&mut self.stream).poll_read(cx, &mut tmp) {
            Poll::Ready(Ok(0)) => Poll::Ready(Ok(0)),
            Poll::Ready(Ok(n)) => {
                self.read_buf.extend_from_slice(&tmp[..n]);
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Try to flush the write buffer.
    fn poll_flush_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.write_buf.is_empty() {
            match Pin::new(&mut self.stream).poll_write(cx, &self.write_buf) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write data",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    let _ = self.write_buf.split_to(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if self.needs_flush {
            match Pin::new(&mut self.stream).poll_flush(cx) {
                Poll::Ready(Ok(())) => {
                    self.needs_flush = false;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }

    /// Decode a message from the read buffer.
    fn try_decode(&mut self) -> Result<Option<TdsFrontendMessage>, Error> {
        self.codec.decode(&mut self.read_buf, self.state)
    }

    /// Encode a message into the write buffer.
    fn do_encode(&mut self, msg: TdsBackendMessage) -> Result<(), Error> {
        match msg {
            TdsBackendMessage::Prelogin(message) => {
                let mut payload = BytesMut::new();
                message.encode(&mut payload)?;
                let packet_type = match self.metadata.custom.get("prelogin_packet_type").map(String::as_str)
                {
                    Some("tabular") => PacketType::TabularResult,
                    _ => PacketType::PreLogin,
                };
                self.write_payload_as_packets(packet_type, payload, true)?;
                Ok(())
            }
            TdsBackendMessage::Token(token) => {
                self.encode_tokens(std::iter::once(token), true)?;
                Ok(())
            }
            TdsBackendMessage::TokenPartial(token) => {
                self.encode_tokens(std::iter::once(token), false)?;
                Ok(())
            }
            TdsBackendMessage::Tokens(tokens) => {
                self.encode_tokens(tokens.into_iter(), true)?;
                Ok(())
            }
            TdsBackendMessage::TokenBytes(payload) => {
                self.write_payload_as_packets(PacketType::TabularResult, payload, true)?;
                Ok(())
            }
            TdsBackendMessage::TokenBytesPartial(payload) => {
                self.write_payload_as_packets(PacketType::TabularResult, payload, false)?;
                Ok(())
            }
            TdsBackendMessage::Packet(packet) => self.codec.encode(TdsBackendMessage::Packet(packet), &mut self.write_buf),
        }
    }

    fn encode_tokens<I>(&mut self, tokens: I, end_of_message: bool) -> Result<(), Error>
    where
        I: IntoIterator<Item = BackendToken>,
    {
        let mut payload = BytesMut::new();
        if self.reset_connection_pending {
            self.reset_connection_pending = false;
            self.encode_token(
                BackendToken::EnvChange(crate::tds::codec::TokenEnvChange::ResetConnection),
                &mut payload,
            )?;
        }
        for token in tokens {
            self.encode_token(token, &mut payload)?;
        }
        self.write_payload_as_packets(PacketType::TabularResult, payload, end_of_message)?;
        Ok(())
    }

    fn encode_done_token(
        &mut self,
        token: TokenDone,
        ty: crate::tds::codec::TokenType,
        payload: &mut BytesMut,
        count_bytes: u8,
    ) -> Result<(), Error> {
        let mut token = token;
        let mut ty = ty;

        if self.attention_pending() {
            token = token.with_added_status(DoneStatus::Attention.into());
            ty = crate::tds::codec::TokenType::Done;
        }

        if token.status().contains(DoneStatus::Attention) {
            self.attention_ack_pending = true;
            // clear_attention() handles state transition to ReadyForQuery
            self.clear_attention();
        }

        token.encode_with_type_and_count_bytes(payload, ty, count_bytes)
    }

    fn encode_token(&mut self, token: BackendToken, payload: &mut BytesMut) -> Result<(), Error> {
        let done_row_count_bytes = self.context.version().done_row_count_bytes();
        match token {
            _ if self.attention_pending() => match token {
                BackendToken::EnvChange(token) => match token {
                    TokenEnvChange::ResetConnection => token.encode(payload),
                    _ => Ok(()),
                },
                BackendToken::Done(token) => self.encode_done_token(
                    token,
                    crate::tds::codec::TokenType::Done,
                    payload,
                    done_row_count_bytes,
                ),
                BackendToken::DoneProc(token) => self.encode_done_token(
                    token,
                    crate::tds::codec::TokenType::DoneProc,
                    payload,
                    done_row_count_bytes,
                ),
                BackendToken::DoneInProc(token) => self.encode_done_token(
                    token,
                    crate::tds::codec::TokenType::DoneInProc,
                    payload,
                    done_row_count_bytes,
                ),
                _ => Ok(()),
            },
            BackendToken::LoginAck(token) => token.encode(payload),
            BackendToken::EnvChange(token) => token.encode(payload),
            BackendToken::Info(token) => token.encode(payload),
            BackendToken::Error(token) => token.encode(payload),
            BackendToken::FeatureExtAck(token) => token.encode(payload),
            BackendToken::ColName(token) => token.encode(payload),
            BackendToken::TabName(token) => token.encode(payload),
            BackendToken::ColInfo(token) => token.encode(payload),
            BackendToken::ColMetaData(token) => {
                self.context.set_last_meta(Arc::new(token.clone()));
                token.encode(payload)
            }
            BackendToken::AltMetaData(token) => {
                self.context.set_alt_meta(Arc::new(token.clone()));
                token.encode(payload)
            }
            BackendToken::Row(token) => {
                let meta = self
                    .context
                    .last_meta()
                    .ok_or_else(|| Error::Protocol("missing column metadata".into()))?;
                token.encode_with_columns(payload, &meta.columns)
            }
            BackendToken::NbcRow(token) => {
                let meta = self
                    .context
                    .last_meta()
                    .ok_or_else(|| Error::Protocol("missing column metadata".into()))?;
                token.encode_nbc_with_columns(payload, &meta.columns)
            }
            BackendToken::AltRow(token) => {
                let meta = self
                    .context
                    .alt_meta(token.id)
                    .ok_or_else(|| Error::Protocol("missing alt metadata".into()))?;
                token.encode_with_columns(payload, &meta.columns)
            }
            BackendToken::Order(token) => token.encode(payload),
            BackendToken::Done(token) => {
                self.encode_done_token(
                    token,
                    crate::tds::codec::TokenType::Done,
                    payload,
                    done_row_count_bytes,
                )
            }
            BackendToken::DoneProc(token) => {
                self.encode_done_token(
                    token,
                    crate::tds::codec::TokenType::DoneProc,
                    payload,
                    done_row_count_bytes,
                )
            }
            BackendToken::DoneInProc(token) => {
                self.encode_done_token(
                    token,
                    crate::tds::codec::TokenType::DoneInProc,
                    payload,
                    done_row_count_bytes,
                )
            }
            BackendToken::ReturnStatus(status) => {
                payload.put_u8(crate::tds::codec::TokenType::ReturnStatus as u8);
                payload.put_u32_le(status);
                Ok(())
            }
            BackendToken::ReturnValue(token) => token.encode(payload),
            BackendToken::SessionState(token) => token.encode(payload),
            BackendToken::FedAuthInfo(token) => token.encode(payload),
            BackendToken::Sspi(token) => token.encode(payload),
        }
    }

    fn write_payload_as_packets(
        &mut self,
        ty: PacketType,
        mut payload: BytesMut,
        end_of_message: bool,
    ) -> Result<(), Error> {
        if !self.message_in_progress {
            self.context.reset_packet_id();
        }
        let packet_size = (self.context.packet_size() as usize)
            .saturating_sub(crate::tds::codec::HEADER_BYTES);

        if packet_size == 0 {
            return Err(Error::Protocol("invalid packet size".into()));
        }

        while !payload.is_empty() {
            let writable = std::cmp::min(payload.len(), packet_size);
            let split_payload = payload.split_to(writable);
            let id = self.context.next_packet_id();
            let mut header = PacketHeader::new(0, id);
            header.set_type(ty);
            if payload.is_empty() && end_of_message {
                header.set_status(PacketStatus::EndOfMessage);
                if self.attention_ack_pending {
                    header.set_status_bits(STATUS_ATTENTION_ACK);
                    self.attention_ack_pending = false;
                }
            } else {
                header.set_status(PacketStatus::NormalMessage);
            }

            let packet = Packet::new(header, split_payload);
            self.codec
                .encode(TdsBackendMessage::Packet(packet), &mut self.write_buf)?;
        }

        self.message_in_progress = !end_of_message;
        self.needs_flush = true;
        Ok(())
    }
}

impl<S: NetStream> TdsConnectionContext for TdsConnection<S> {
    fn socket_addr(&self) -> SocketAddr {
        self.socket_addr
    }

    fn is_secure(&self) -> bool {
        self.is_secure
    }

    fn state(&self) -> TdsConnectionState {
        self.state
    }

    fn set_state(&mut self, state: TdsConnectionState) {
        self.state = state;
    }

    fn connection_metadata(&self) -> &ConnectionMetadata {
        &self.metadata
    }

    fn connection_metadata_mut(&mut self) -> &mut ConnectionMetadata {
        &mut self.metadata
    }

    fn next_packet_id(&mut self) -> u8 {
        self.context.next_packet_id()
    }

    fn packet_size(&self) -> u32 {
        self.context.packet_size()
    }

    fn set_packet_size(&mut self, size: u32) {
        self.context.set_packet_size(size);
    }

    fn tds_version(&self) -> FeatureLevel {
        self.context.version()
    }

    fn set_tds_version(&mut self, version: FeatureLevel) {
        self.context.set_version(version);
    }

    fn transaction_descriptor(&self) -> TransactionDescriptor {
        TransactionDescriptor::new(self.context.transaction_descriptor())
    }

    fn set_transaction_descriptor(&mut self, desc: TransactionDescriptor) {
        self.context.set_transaction_descriptor(desc.into_bytes());
    }

    fn last_request_headers(&self) -> &AllHeaders {
        &self.last_request_headers
    }

    fn encryption(&self) -> EncryptionLevel {
        self.encryption
    }

    fn set_encryption(&mut self, encryption: EncryptionLevel) {
        self.encryption = encryption;
    }

    fn attention_pending(&self) -> bool {
        self.attention_pending()
    }

    fn clear_attention(&mut self) {
        TdsConnection::clear_attention(self);
    }

    fn poll_attention<'a>(&'a mut self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, Error>> + Send + 'a>>
    where
        Self: Sized,
    {
        Box::pin(async move { TdsConnection::poll_attention(self).await })
    }
}

impl<S: NetStream> Stream for TdsConnection<S> {
    type Item = Result<TdsFrontendMessage, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        if let Some(msg) = this.pending_messages.pop_front() {
            return Poll::Ready(Some(Ok(msg)));
        }

        match this.try_decode() {
            Ok(Some(msg)) => return Poll::Ready(Some(Ok(msg))),
            Ok(None) => {}
            Err(e) => return Poll::Ready(Some(Err(e))),
        }

        match this.poll_read_buf(cx) {
            Poll::Ready(Ok(0)) => Poll::Ready(None),
            Poll::Ready(Ok(_)) => match this.try_decode() {
                Ok(Some(msg)) => Poll::Ready(Some(Ok(msg))),
                Ok(None) => Poll::Pending,
                Err(e) => Poll::Ready(Some(Err(e))),
            },
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e.into()))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: NetStream> Sink<TdsBackendMessage> for TdsConnection<S> {
    type Error = Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: TdsBackendMessage) -> Result<(), Self::Error> {
        let this = self.get_mut();
        this.do_encode(item)?;
        this.needs_flush = true;
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut()
            .poll_flush_buf(cx)
            .map_err(Into::into)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        match this.poll_flush_buf(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.stream)
                .poll_close(cx)
                .map_err(Into::into),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}
