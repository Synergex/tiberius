#[cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]
use crate::client::{tls::TlsPreloginWrapper, tls_stream::create_tls_stream};
use crate::{
    client::{tls::MaybeTlsStream, AuthMethod, CancelSignal, CancellationState, Config},
    tds::{
        codec::{
            self, Encode, LoginMessage, Packet, PacketCodec, PacketHeader, PacketStatus,
            PreloginMessage, TokenDone,
        },
        stream::TokenStream,
        Context, HEADER_BYTES,
    },
    EncryptionLevel, SqlReadBytes,
};
use asynchronous_codec::Framed;
use bytes::{Buf, BytesMut};
#[cfg(any(windows, feature = "integrated-auth-gssapi"))]
use codec::TokenSspi;
use futures_util::future::{select, Either};
use futures_util::io::{AsyncRead, AsyncWrite};
use futures_util::ready;
use futures_util::sink::SinkExt;
use futures_util::stream::{Stream, TryStream, TryStreamExt};
#[cfg(all(unix, feature = "integrated-auth-gssapi"))]
use libgssapi::{
    context::{ClientCtx, CtxFlags},
    credential::{Cred, CredUsage},
    name::Name,
    oid::{OidSet, GSS_MECH_KRB5, GSS_NT_KRB5_PRINCIPAL},
};
use pretty_hex::*;
#[cfg(all(unix, feature = "integrated-auth-gssapi"))]
use std::ops::Deref;
use std::sync::Arc;
use std::{cmp, fmt::Debug, io, pin::Pin, task};
use task::Poll;
use tracing::{event, Level};
#[cfg(all(windows, feature = "winauth"))]
use winauth::{windows::NtlmSspiBuilder, NextBytes};

/// A `Connection` is an abstraction between the [`Client`] and the server. It
/// can be used as a `Stream` to fetch [`Packet`]s from and to `send` packets
/// splitting them to the negotiated limit automatically.
///
/// `Connection` is not meant to use directly, but as an abstraction layer for
/// the numerous `Stream`s for easy packet handling.
///
/// [`Client`]: struct.Encode.html
/// [`Packet`]: ../protocol/codec/struct.Packet.html
pub(crate) struct Connection<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    transport: Framed<MaybeTlsStream<S>, PacketCodec>,
    flushed: bool,
    /// Set while decoding the tail of a fully received response, so a token
    /// that runs past the buffered bytes fails instead of waiting on the
    /// network for data the server will never send.
    buffered_only: bool,
    /// Set while a token is decoded, so it stays set when one fails or is
    /// dropped part-way and the rest of the stream has no token boundary to
    /// resume from. Every later request fails.
    mid_token: bool,
    /// Set for good when a fatal server error ends the session or the
    /// buffered tail of a response fails to drain. Every later request fails.
    broken: bool,
    /// Set once an attention is queued and until its acknowledgment is read,
    /// so a drain dropped before then is finished by the next one rather than
    /// leaving the acknowledgment for the next request to read as its own.
    attention_pending: bool,
    context: Context,
    buf: BytesMut,
    cancellation: Arc<CancellationState>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> Debug for Connection<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("transport", &"Framed<..>")
            .field("flushed", &self.flushed)
            .field("context", &self.context)
            .field("buf", &self.buf.as_ref().hex_dump())
            .finish()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> Connection<S> {
    /// Creates a new connection
    pub(crate) async fn connect(config: Config, tcp_stream: S) -> crate::Result<Connection<S>> {
        let context = {
            let mut context = Context::new();
            context.set_spn(config.get_host(), config.get_port());
            context
        };

        let transport = Framed::new(MaybeTlsStream::Raw(tcp_stream), PacketCodec);

        let mut connection = Self {
            transport,
            context,
            flushed: false,
            buffered_only: false,
            mid_token: false,
            broken: false,
            attention_pending: false,
            buf: BytesMut::new(),
            cancellation: Arc::new(CancellationState::new()),
        };

        let fed_auth_required = matches!(config.auth, AuthMethod::AADToken(_));

        let prelogin = connection
            .prelogin(config.encryption, fed_auth_required)
            .await?;

        let encryption = prelogin.negotiated_encryption(config.encryption);

        let connection = connection.tls_handshake(&config, encryption).await?;

        let mut connection = connection
            .login(
                config.auth,
                encryption,
                config.database,
                config.host,
                config.application_name,
                config.readonly,
                prelogin,
            )
            .await?;

        connection.flush_done().await?;

        Ok(connection)
    }

    /// Flush the incoming token stream until receiving `DONE` token.
    async fn flush_done(&mut self) -> crate::Result<TokenDone> {
        TokenStream::new(self).flush_done().await
    }

    #[cfg(any(windows, feature = "integrated-auth-gssapi"))]
    /// Flush the incoming token stream until receiving `SSPI` token.
    async fn flush_sspi(&mut self) -> crate::Result<TokenSspi> {
        TokenStream::new(self).flush_sspi().await
    }

    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    fn post_login_encryption(mut self, encryption: EncryptionLevel) -> Self {
        if let EncryptionLevel::Off = encryption {
            event!(
                name: "tiberius.tls_off",
                Level::WARN,
                "Turning TLS off after a login. All traffic from here on is not encrypted.",
            );

            let Self { transport, .. } = self;
            let tcp = transport.into_inner().into_inner();
            self.transport = Framed::new(MaybeTlsStream::Raw(tcp), PacketCodec);
        }

        self
    }

    #[cfg(not(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    )))]
    fn post_login_encryption(self, _: EncryptionLevel) -> Self {
        self
    }

    /// Send an item to the wire. Header should define the item type and item should implement
    /// [`Encode`], defining the byte structure for the wire.
    ///
    /// The `send` will split the packet into multiple packets if bigger than
    /// the negotiated packet size, and handle flushing to the wire in an optimal way.
    ///
    /// [`Encode`]: ../protocol/codec/trait.Encode.html
    pub async fn send<E>(&mut self, mut header: PacketHeader, item: E) -> crate::Result<()>
    where
        E: Sized + Encode<BytesMut>,
    {
        self.flushed = false;
        let packet_size = (self.context.packet_size() as usize) - HEADER_BYTES;

        let mut payload = BytesMut::new();
        item.encode(&mut payload)?;

        while !payload.is_empty() {
            let writable = cmp::min(payload.len(), packet_size);
            let split_payload = payload.split_to(writable);

            if payload.is_empty() {
                header.set_status(PacketStatus::EndOfMessage);
            } else {
                header.set_status(PacketStatus::NormalMessage);
            }

            event!(
                Level::TRACE,
                "Sending a packet ({} bytes)",
                split_payload.len() + HEADER_BYTES,
            );

            self.write_to_wire(header, split_payload).await?;
        }

        self.flush_sink().await?;

        Ok(())
    }

    /// Sends a packet of data to the database.
    ///
    /// # Warning
    ///
    /// Please be sure the packet size doesn't exceed the largest allowed size
    /// dictaded by the server.
    pub(crate) async fn write_to_wire(
        &mut self,
        header: PacketHeader,
        data: BytesMut,
    ) -> crate::Result<()> {
        self.flushed = false;

        let packet = Packet::new(header, data);
        self.transport.send(packet).await?;

        Ok(())
    }

    /// Sends all pending packages to the wire.
    pub(crate) async fn flush_sink(&mut self) -> crate::Result<()> {
        self.transport.flush().await
    }

    /// Send an attention signal to the server to cancel the current operation.
    pub(crate) async fn send_attention(&mut self) -> crate::Result<()> {
        let id = self.context.next_packet_id();
        let header = PacketHeader::attention(id);
        self.flushed = false;
        self.transport
            .feed(Packet::new(header, BytesMut::new()))
            .await?;
        self.attention_pending = true;
        self.flush_sink().await
    }

    /// Records that the acknowledgment of the pending attention was read.
    pub(crate) fn attention_acknowledged(&mut self) {
        self.attention_pending = false;
    }

    /// Returns a [`CancellationToken`] that can request cancellation of
    /// in-flight queries from another task.
    pub(crate) fn cancellation_token(&self) -> super::CancellationToken {
        super::CancellationToken::new(self.cancellation.clone())
    }

    /// Returns `true` if a cancellation has been requested via the token.
    pub(crate) fn is_cancellation_requested(&self) -> bool {
        self.cancellation.is_requested()
    }

    /// Clears the cancellation request flag.
    pub(crate) fn clear_cancellation_request(&self) {
        self.cancellation.clear();
    }

    /// Marks a token as decoding until [`token_decoded`](Self::token_decoded),
    /// so one that fails or is dropped part-way leaves the connection
    /// unusable. Call once its type byte is read.
    pub(crate) fn decoding_token(&mut self) {
        self.mid_token = true;
    }

    pub(crate) fn token_decoded(&mut self) {
        self.mid_token = false;
    }

    /// Breaks the connection for good when `error` is fatal, since the server
    /// ends the session after one. Every reader of response tokens calls this
    /// for each server error it decodes.
    pub(crate) fn note_server_error(&mut self, error: &codec::TokenError) {
        self.broken |= error.class() >= crate::error::FATAL_SEVERITY;
    }

    /// Fails once a token stopped part-way or the connection broke.
    fn usable(&self) -> crate::Result<()> {
        if self.mid_token || self.broken {
            return Err(crate::Error::Protocol(
                "a response stopped part-way through a token, could not be decoded or \
                 ended the session, so the connection cannot be used"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Reads the next token-type byte, racing the read against cancellation.
    ///
    /// While no attention has yet been sent, a packet-less statement produces
    /// no bytes, so a bare `read_u8().await` would park indefinitely and never
    /// observe a `cancel()`. Racing the read against [`CancelSignal`] lets
    /// `cancel()` wake this task; on cancellation we send the TDS attention
    /// signal here and return `Ok(None)`, leaving the caller to drain the rest
    /// of the response to the server's `Done+Attention` acknowledgment.
    ///
    /// Returns `Ok(Some(byte))` if a byte was read, or `Ok(None)` if
    /// cancellation won (the attention signal has been sent). Any abandoned
    /// read has consumed no bytes — a single-byte read parks before touching
    /// the buffer — so nothing is lost.
    pub(crate) async fn read_u8_or_cancel(&mut self) -> crate::Result<Option<u8>> {
        // A buffered-only read is of a response that has already ended: an
        // attention would have nothing to cancel, and its acknowledgment could
        // not be in the buffer. Leave the cancellation for the next request.
        if self.buffered_only {
            return Ok(Some(self.read_u8().await?));
        }

        // Check the flag up front. `select` polls the read first and returns
        // immediately if it is ready, so without this a cancellation requested
        // before entry would be ignored whenever the next byte is already
        // buffered (the read would keep winning the race). This makes the
        // helper self-contained so every caller gets the fast path.
        if self.is_cancellation_requested() {
            self.clear_cancellation_request();
            self.send_attention().await?;
            return Ok(None);
        }

        let signal = CancelSignal::new(self.cancellation.clone());

        // Both raced futures (one of which borrows the connection) are dropped
        // at the end of this statement, freeing the connection to write below.
        let maybe_byte = match select(self.read_u8(), signal).await {
            Either::Left((res, _cancel)) => Some(res?),
            Either::Right(((), _read)) => None,
        };

        match maybe_byte {
            Some(byte) => Ok(Some(byte)),
            None => {
                self.clear_cancellation_request();
                self.send_attention().await?;
                Ok(None)
            }
        }
    }

    /// Cleans the packet stream from previous use by sending a TDS attention
    /// signal and draining the response. This is significantly faster than
    /// reading all remaining result data for large result sets.
    ///
    /// It is important to use the whole stream before using the connection
    /// again. Flushing the stream makes sure we don't have any old data
    /// causing undefined behaviour after previous queries.
    pub async fn flush_stream(&mut self) -> crate::Result<()> {
        self.clear_cancellation_request();
        self.usable()?;

        if self.flushed && self.buf.is_empty() && !self.attention_pending {
            return Ok(());
        }

        event!(
            name: "tiberius.attention_flush",
            Level::WARN,
            "Flushing unhandled stream via attention signal. Please consume your streams!",
        );

        if self.flushed && !self.attention_pending {
            // Server already finished sending all data (EOM seen), so the rest
            // of the response is buffered. Decode it rather than discard it: a
            // transaction it began or ended changes the descriptor every later
            // request must carry, and SQL Server rejects a stale one.
            if !self.drain_buffered_tokens().await {
                // A token could not be decoded, so the session state it
                // carried is lost.
                self.broken = true;
            }
            return self.usable();
        }

        // Server still has data to send, or owes the acknowledgment of an
        // attention sent before a drain was dropped. Send attention to cancel
        // quickly, unless one is already on its way.
        if self.attention_pending {
            self.flush_sink().await?;
        } else {
            self.send_attention().await?;
        }

        // Drain at the token level until the server's attention
        // acknowledgment (Done+Attention) arrives. We use
        // `new_with_attention` so the stream knows not to terminate on a
        // natural EOF — the attention ack may arrive as a separate message
        // after the original query response ends.
        let ts = TokenStream::new_with_attention(self);
        ts.flush_to_attention().await?;

        self.usable()
    }

    /// Decodes the buffered tokens of a fully received response without
    /// reading the network. Returns whether all of them decoded.
    async fn drain_buffered_tokens(&mut self) -> bool {
        self.buffered_only = true;
        let mut tokens = TokenStream::new(self).try_unfold();
        let decoded = loop {
            match tokens.try_next().await {
                Ok(Some(_)) => (),
                // The token stream raises its first server error again at the end.
                Ok(None) | Err(crate::Error::Server(_)) => break true,
                Err(_) => break false,
            }
        };
        drop(tokens);
        self.buffered_only = false;
        decoded && self.buf.is_empty()
    }

    /// True if the underlying stream has no more data and is consumed
    /// completely.
    pub fn is_eof(&self) -> bool {
        self.flushed && self.buf.is_empty()
    }

    /// A message sent by the client to set up context for login. The server
    /// responds to a client PRELOGIN message with a message of packet header
    /// type 0x04 and with the packet data containing a PRELOGIN structure.
    ///
    /// This message stream is also used to wrap the TLS handshake payload if
    /// encryption is needed. In this scenario, where PRELOGIN message is
    /// transporting the TLS handshake payload, the packet data is simply the
    /// raw bytes of the TLS handshake payload.
    async fn prelogin(
        &mut self,
        encryption: EncryptionLevel,
        fed_auth_required: bool,
    ) -> crate::Result<PreloginMessage> {
        let mut msg = PreloginMessage::new();
        msg.encryption = encryption;
        msg.fed_auth_required = fed_auth_required;

        let id = self.context.next_packet_id();
        self.send(PacketHeader::pre_login(id), msg).await?;

        let response: PreloginMessage = codec::collect_from(self).await?;
        // threadid (should be empty when sent from server to client)
        debug_assert_eq!(response.thread_id, 0);
        Ok(response)
    }

    /// Defines the login record rules with SQL Server. Authentication with
    /// connection options.
    #[allow(clippy::too_many_arguments)]
    async fn login<'a>(
        mut self,
        auth: AuthMethod,
        encryption: EncryptionLevel,
        db: Option<String>,
        server_name: Option<String>,
        application_name: Option<String>,
        readonly: bool,
        prelogin: PreloginMessage,
    ) -> crate::Result<Self> {
        let mut login_message = LoginMessage::new();

        if let Some(db) = db {
            login_message.db_name(db);
        }

        if let Some(server_name) = server_name {
            login_message.server_name(server_name);
        }

        if let Some(app_name) = application_name {
            login_message.app_name(app_name);
        }

        login_message.readonly(readonly);

        match auth {
            #[cfg(all(windows, feature = "winauth"))]
            AuthMethod::Integrated => {
                let mut client = NtlmSspiBuilder::new()
                    .target_spn(self.context.spn())
                    .build()?;

                login_message.integrated_security(client.next_bytes(None)?);

                let id = self.context.next_packet_id();
                self.send(PacketHeader::login(id), login_message).await?;

                self = self.post_login_encryption(encryption);

                let sspi_bytes = self.flush_sspi().await?;

                match client.next_bytes(Some(sspi_bytes.as_ref()))? {
                    Some(sspi_response) => {
                        event!(Level::TRACE, sspi_response_len = sspi_response.len());

                        let id = self.context.next_packet_id();
                        let header = PacketHeader::login(id);

                        let token = TokenSspi::new(sspi_response);
                        self.send(header, token).await?;
                    }
                    None => unreachable!(),
                }
            }
            #[cfg(all(unix, feature = "integrated-auth-gssapi"))]
            AuthMethod::Integrated => {
                let mut s = OidSet::new()?;
                s.add(&GSS_MECH_KRB5)?;

                let client_cred = Cred::acquire(None, None, CredUsage::Initiate, Some(&s))?;

                let mut ctx = ClientCtx::new(
                    Some(client_cred),
                    Name::new(self.context.spn().as_bytes(), Some(&GSS_NT_KRB5_PRINCIPAL))?,
                    CtxFlags::GSS_C_MUTUAL_FLAG | CtxFlags::GSS_C_SEQUENCE_FLAG,
                    None,
                );

                let init_token = ctx.step(None, None)?;

                login_message.integrated_security(Some(Vec::from(init_token.unwrap().deref())));

                let id = self.context.next_packet_id();
                self.send(PacketHeader::login(id), login_message).await?;

                self = self.post_login_encryption(encryption);

                let auth_bytes = self.flush_sspi().await?;

                let next_token = match ctx.step(Some(auth_bytes.as_ref()), None)? {
                    Some(response) => {
                        event!(Level::TRACE, response_len = response.len());
                        TokenSspi::new(Vec::from(response.deref()))
                    }
                    None => {
                        event!(Level::TRACE, response_len = 0);
                        TokenSspi::new(Vec::new())
                    }
                };

                let id = self.context.next_packet_id();
                let header = PacketHeader::login(id);

                self.send(header, next_token).await?;
            }
            #[cfg(all(windows, feature = "winauth"))]
            AuthMethod::Windows(auth) => {
                let spn = self.context.spn().to_string();
                let builder = winauth::NtlmV2ClientBuilder::new().target_spn(spn);
                let mut client = builder.build(auth.domain, auth.user, auth.password);

                login_message.integrated_security(client.next_bytes(None)?);

                let id = self.context.next_packet_id();
                self.send(PacketHeader::login(id), login_message).await?;

                self = self.post_login_encryption(encryption);

                let sspi_bytes = self.flush_sspi().await?;

                match client.next_bytes(Some(sspi_bytes.as_ref()))? {
                    Some(sspi_response) => {
                        event!(Level::TRACE, sspi_response_len = sspi_response.len());

                        let id = self.context.next_packet_id();
                        let header = PacketHeader::login(id);

                        let token = TokenSspi::new(sspi_response);
                        self.send(header, token).await?;
                    }
                    None => unreachable!(),
                }
            }
            AuthMethod::None => {
                let id = self.context.next_packet_id();
                self.send(PacketHeader::login(id), login_message).await?;
                self = self.post_login_encryption(encryption);
            }
            AuthMethod::SqlServer(auth) => {
                login_message.user_name(auth.user());
                login_message.password(auth.password());

                let id = self.context.next_packet_id();
                self.send(PacketHeader::login(id), login_message).await?;
                self = self.post_login_encryption(encryption);
            }
            AuthMethod::AADToken(token) => {
                login_message.aad_token(token, prelogin.fed_auth_required, prelogin.nonce);
                let id = self.context.next_packet_id();
                self.send(PacketHeader::login(id), login_message).await?;
                self = self.post_login_encryption(encryption);
            }
        }

        Ok(self)
    }

    /// Implements the TLS handshake with the SQL Server.
    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    async fn tls_handshake(
        self,
        config: &Config,
        encryption: EncryptionLevel,
    ) -> crate::Result<Self> {
        if encryption != EncryptionLevel::NotSupported {
            event!(Level::INFO, "Performing a TLS handshake");

            let Self {
                transport,
                context,
                cancellation,
                ..
            } = self;
            let mut stream = match transport.into_inner() {
                MaybeTlsStream::Raw(tcp) => {
                    create_tls_stream(config, TlsPreloginWrapper::new(tcp)).await?
                }
                _ => unreachable!(),
            };

            stream.get_mut().handshake_complete();
            event!(Level::INFO, "TLS handshake successful");

            let transport = Framed::new(MaybeTlsStream::Tls(stream), PacketCodec);

            Ok(Self {
                transport,
                context,
                flushed: false,
                buffered_only: false,
                mid_token: false,
                broken: false,
                attention_pending: false,
                buf: BytesMut::new(),
                cancellation,
            })
        } else {
            event!(
                Level::WARN,
                "TLS encryption is not enabled. All traffic including the login credentials are not encrypted."
            );

            Ok(self)
        }
    }

    /// Implements the TLS handshake with the SQL Server.
    #[cfg(not(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    )))]
    async fn tls_handshake(self, _: &Config, _: EncryptionLevel) -> crate::Result<Self> {
        event!(
            Level::WARN,
            "TLS encryption is not enabled. All traffic including the login credentials are not encrypted."
        );

        Ok(self)
    }

    pub(crate) async fn close(mut self) -> crate::Result<()> {
        self.transport.close().await
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> Stream for Connection<S> {
    type Item = crate::Result<Packet>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        match ready!(this.transport.try_poll_next_unpin(cx)) {
            Some(Ok(packet)) => {
                this.flushed = packet.is_last();
                let spid = packet.header().spid();
                if spid != 0 {
                    this.context.set_spid(spid);
                }
                Poll::Ready(Some(Ok(packet)))
            }
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> futures_util::io::AsyncRead for Connection<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.get_mut();
        let size = buf.len();

        if this.buf.len() < size {
            if this.buffered_only {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "token runs past the buffered response",
                )));
            }
            while let Some(item) = ready!(Pin::new(&mut this).try_poll_next(cx)) {
                match item {
                    Ok(packet) => {
                        let (_, payload) = packet.into_parts();
                        this.buf.extend_from_slice(&payload);

                        if this.buf.len() >= size {
                            break;
                        }
                    }
                    Err(e) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            e.to_string(),
                        )))
                    }
                }
            }

            // Got EOF before having all the data.
            if this.buf.len() < size {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "No more packets in the wire",
                )));
            }
        }

        buf.copy_from_slice(&this.buf[..size]);
        this.buf.advance(size);
        Poll::Ready(Ok(size))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> SqlReadBytes for Connection<S> {
    /// Hex dump of the current buffer.
    fn debug_buffer(&self) {
        dbg!(self.buf.as_ref().hex_dump());
    }

    /// The current execution context.
    fn context(&self) -> &Context {
        &self.context
    }

    /// A mutable reference to the current execution context.
    fn context_mut(&mut self) -> &mut Context {
        &mut self.context
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tds::codec::{DoneStatus, PacketType, TokenEnvChange, TokenError};
    use crate::tds::stream::ReceivedToken;
    use futures_util::{FutureExt, StreamExt};
    use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

    type Duplex = Compat<tokio::io::DuplexStream>;

    /// A connection to an in-memory server, and the server's end of it.
    fn duplex(flushed: bool) -> (Connection<Duplex>, Framed<Duplex, PacketCodec>) {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let connection = Connection {
            transport: Framed::new(MaybeTlsStream::Raw(client_io.compat()), PacketCodec),
            flushed,
            buffered_only: false,
            mid_token: false,
            broken: false,
            attention_pending: false,
            context: Context::new(),
            buf: BytesMut::new(),
            cancellation: Arc::new(CancellationState::new()),
        };
        (connection, Framed::new(server_io.compat(), PacketCodec))
    }

    /// Sends `payload` from the server in one packet, the last of its
    /// message when `last`.
    async fn respond(server: &mut Framed<Duplex, PacketCodec>, payload: BytesMut, last: bool) {
        let mut header = PacketHeader::new(0, 1);
        header.set_type(PacketType::TabularResult);
        header.set_status(if last {
            PacketStatus::EndOfMessage
        } else {
            PacketStatus::NormalMessage
        });
        server.send(Packet::new(header, payload)).await.unwrap();
    }

    fn encoded(done: TokenDone) -> BytesMut {
        let mut bytes = BytesMut::new();
        done.encode(&mut bytes).unwrap();
        bytes
    }

    fn attention_ack() -> BytesMut {
        encoded(TokenDone::with_status(DoneStatus::Attention.into(), 0))
    }

    fn buffered(bytes: &[u8]) -> Connection<futures_util::io::Cursor<Vec<u8>>> {
        Connection {
            transport: Framed::new(
                MaybeTlsStream::Raw(futures_util::io::Cursor::new(Vec::new())),
                PacketCodec,
            ),
            flushed: true,
            buffered_only: false,
            mid_token: false,
            broken: false,
            attention_pending: false,
            context: Context::new(),
            buf: BytesMut::from(bytes),
            cancellation: Arc::new(CancellationState::new()),
        }
    }

    #[tokio::test]
    async fn a_token_that_fails_to_decode_is_a_protocol_error() {
        // ENVCHANGE database change whose new name is an unpaired surrogate.
        let mut connection = buffered(&[0xe3, 5, 0, 1, 1, 0x00, 0xd8, 0, 0xfd]);
        let mut tokens = TokenStream::new(&mut connection).try_unfold();
        let error = tokens.try_next().await.unwrap_err();
        assert!(matches!(error, crate::Error::Protocol(_)), "{error:?}");
        assert!(!error.leaves_connection_usable());
    }

    #[tokio::test]
    async fn commit_fails_after_an_undecodable_buffered_tail() {
        let mut client = crate::Client {
            connection: buffered(&[0xe3, 0, 0]),
        };
        let result = client.commit_transaction().await;
        assert!(
            matches!(result, Err(crate::Error::Protocol(_))),
            "{result:?}"
        );
    }

    /// A buffered response holding a fatal error, then `rest`.
    fn fatal_error_then(rest: BytesMut) -> Connection<futures_util::io::Cursor<Vec<u8>>> {
        let mut bytes = BytesMut::new();
        TokenError::new(50001, 1, 20, "fatal", "srv", "", 1)
            .encode(&mut bytes)
            .unwrap();
        bytes.extend_from_slice(&rest);
        buffered(&bytes)
    }

    #[tokio::test]
    async fn commit_fails_after_a_fatal_error_in_the_buffered_tail() {
        let mut client = crate::Client {
            connection: fatal_error_then(encoded(TokenDone::default())),
        };
        let result = client.commit_transaction().await;
        assert!(
            matches!(result, Err(crate::Error::Protocol(_))),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn requests_fail_after_a_request_reads_a_fatal_error() {
        let mut client = crate::Client {
            connection: fatal_error_then(encoded(TokenDone::default())),
        };
        let mut tokens = TokenStream::new(&mut client.connection).try_unfold();
        while tokens.try_next().await.is_ok_and(|token| token.is_some()) {}
        drop(tokens);
        assert!(client.connection.is_eof());
        assert_broken(&mut client).await;
    }

    #[tokio::test]
    async fn requests_fail_after_a_metadata_only_fetch_reads_a_fatal_error() {
        let mut client = crate::Client {
            connection: fatal_error_then(encoded(TokenDone::default())),
        };
        let error = crate::client::rpc_response::collect_metadata_only_rpc(&mut client.connection)
            .await
            .unwrap_err();
        assert_eq!(error.code(), Some(50001));
        assert_broken(&mut client).await;
    }

    #[tokio::test]
    async fn a_nonfatal_error_in_the_buffered_tail_keeps_the_connection() {
        let mut bytes = BytesMut::new();
        TokenError::new(2627, 1, 14, "duplicate", "srv", "", 1)
            .encode(&mut bytes)
            .unwrap();
        TokenDone::default().encode(&mut bytes).unwrap();
        let mut client = crate::Client {
            connection: buffered(&bytes),
        };
        assert!(matches!(
            client.commit_transaction().await,
            Ok(crate::TransactionEnd::NoTransaction)
        ));
    }

    /// Ends a transaction the server reports in a buffered response tail
    /// made of `changes`, then asks the client to commit and to roll back.
    async fn end_after(changes: Vec<TokenEnvChange>) -> [crate::TransactionEnd; 2] {
        let mut bytes = BytesMut::new();
        for change in changes {
            change.encode(&mut bytes).unwrap();
        }
        TokenDone::default().encode(&mut bytes).unwrap();
        let mut client = crate::Client {
            connection: buffered(&bytes),
        };
        [
            client.commit_transaction().await.unwrap(),
            client.rollback_transaction().await.unwrap(),
        ]
    }

    const DESC: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    #[tokio::test]
    async fn a_server_rollback_is_reported_until_another_transaction_begins() {
        use crate::TransactionEnd::AlreadyRolledBack;
        let rollback = TokenEnvChange::RollbackTransaction {
            new: Vec::new(),
            old: DESC.to_vec(),
        };
        let ends = end_after(vec![TokenEnvChange::BeginTransaction(DESC), rollback]).await;
        assert_eq!(ends, [AlreadyRolledBack, AlreadyRolledBack]);
    }

    #[tokio::test]
    async fn a_tsql_commit_is_reported() {
        use crate::TransactionEnd::AlreadyCommitted;
        let commit = TokenEnvChange::CommitTransaction {
            new: Vec::new(),
            old: DESC.to_vec(),
        };
        let ends = end_after(vec![TokenEnvChange::BeginTransaction(DESC), commit]).await;
        assert_eq!(ends, [AlreadyCommitted, AlreadyCommitted]);
    }

    #[tokio::test]
    async fn a_connection_reset_forgets_how_the_last_transaction_ended() {
        use crate::TransactionEnd::NoTransaction;
        let rollback = TokenEnvChange::RollbackTransaction {
            new: Vec::new(),
            old: DESC.to_vec(),
        };
        let ends = end_after(vec![
            TokenEnvChange::BeginTransaction(DESC),
            rollback,
            TokenEnvChange::ResetConnection,
        ])
        .await;
        assert_eq!(ends, [NoTransaction, NoTransaction]);
    }

    #[tokio::test]
    async fn a_begin_forgets_how_the_last_transaction_ended() {
        let mut bytes = BytesMut::new();
        TokenEnvChange::RollbackTransaction {
            new: Vec::new(),
            old: DESC.to_vec(),
        }
        .encode(&mut bytes)
        .unwrap();
        TokenEnvChange::BeginTransaction(DESC)
            .encode(&mut bytes)
            .unwrap();
        TokenDone::default().encode(&mut bytes).unwrap();
        let mut connection = buffered(&bytes);
        let mut tokens = TokenStream::new(&mut connection).try_unfold();
        while tokens.try_next().await.unwrap().is_some() {}
        drop(tokens);
        assert_eq!(connection.context().transaction_descriptor(), DESC);
        assert_eq!(connection.context().transaction_end(), None);
    }

    /// Drops a commit call once it has sent its request, has the server end
    /// the transaction with `change`, and returns what the retry reports.
    async fn retry_after_a_dropped_commit(change: TokenEnvChange) -> crate::TransactionEnd {
        let (connection, mut server) = duplex(true);
        let mut client = crate::Client { connection };
        client
            .connection
            .context_mut()
            .set_transaction_descriptor(DESC);
        assert!(client.commit_transaction().now_or_never().is_none());

        let request = server.next().await.unwrap().unwrap();
        assert!(matches!(
            request.header().r#type(),
            PacketType::TransactionManagerReq
        ));
        // The commit's response, then the ack of the retry's attention.
        let mut response = BytesMut::new();
        change.encode(&mut response).unwrap();
        TokenDone::default().encode(&mut response).unwrap();
        respond(&mut server, response, true).await;
        respond(&mut server, attention_ack(), true).await;

        client.commit_transaction().await.unwrap()
    }

    #[tokio::test]
    async fn a_retry_reports_how_a_dropped_commit_ended() {
        let commit = TokenEnvChange::CommitTransaction {
            new: Vec::new(),
            old: DESC.to_vec(),
        };
        assert_eq!(
            retry_after_a_dropped_commit(commit).await,
            crate::TransactionEnd::AlreadyCommitted
        );
        let rollback = TokenEnvChange::RollbackTransaction {
            new: Vec::new(),
            old: DESC.to_vec(),
        };
        assert_eq!(
            retry_after_a_dropped_commit(rollback).await,
            crate::TransactionEnd::AlreadyRolledBack
        );
    }

    #[tokio::test]
    async fn a_metadata_only_fetch_records_a_transaction_it_begins() {
        use crate::tds::codec::{BaseMetaDataColumn, MetaDataColumn, TokenColMetaData};
        let mut bytes = BytesMut::new();
        TokenEnvChange::BeginTransaction(DESC)
            .encode(&mut bytes)
            .unwrap();
        TokenColMetaData {
            columns: vec![MetaDataColumn {
                base: BaseMetaDataColumn {
                    user_type: 0,
                    flags: enumflags2::BitFlags::empty(),
                    ty: crate::TypeInfo::FixedLen(crate::FixedLenType::Int4),
                    table_name: None,
                },
                col_name: "v".into(),
            }],
        }
        .encode(&mut bytes)
        .unwrap();
        TokenDone::default().encode(&mut bytes).unwrap();
        let mut connection = buffered(&bytes);
        let columns = crate::client::rpc_response::collect_metadata_only_rpc(&mut connection)
            .await
            .unwrap();
        assert_eq!(columns.len(), 1);
        assert_eq!(connection.context().transaction_descriptor(), DESC);
    }

    #[tokio::test]
    async fn a_metadata_only_fetch_records_a_server_rollback() {
        let mut bytes = BytesMut::new();
        TokenError::new(8134, 1, 16, "divide by zero", "srv", "", 1)
            .encode(&mut bytes)
            .unwrap();
        TokenEnvChange::RollbackTransaction {
            new: Vec::new(),
            old: DESC.to_vec(),
        }
        .encode(&mut bytes)
        .unwrap();
        TokenDone::default().encode(&mut bytes).unwrap();
        let mut client = crate::Client {
            connection: buffered(&bytes),
        };
        client
            .connection
            .context_mut()
            .set_transaction_descriptor(DESC);
        let error = crate::client::rpc_response::collect_metadata_only_rpc(&mut client.connection)
            .await
            .unwrap_err();
        assert_eq!(error.code(), Some(8134));
        assert_eq!(
            client.commit_transaction().await.unwrap(),
            crate::TransactionEnd::AlreadyRolledBack
        );
    }

    /// Asserts that requests, and a commit, keep failing with a protocol
    /// error.
    async fn assert_broken(client: &mut crate::Client<futures_util::io::Cursor<Vec<u8>>>) {
        for _ in 0..2 {
            let (_, error) = client
                .execute_declared_until_error("SELECT 1", "", &[])
                .await;
            let error = error.expect("the request must fail");
            assert!(matches!(error, crate::Error::Protocol(_)), "{error:?}");
            assert!(!error.leaves_connection_usable());
        }
        assert!(matches!(
            client.commit_transaction().await,
            Err(crate::Error::Protocol(_))
        ));
    }

    #[tokio::test]
    async fn requests_fail_after_an_undecodable_buffered_tail() {
        let mut client = crate::Client {
            connection: buffered(&[0xe3, 0, 0]),
        };
        assert_broken(&mut client).await;
    }

    #[tokio::test]
    async fn requests_fail_after_a_token_fails_part_way() {
        let mut bytes = BytesMut::from(&[0xe3, 0, 0][..]);
        TokenDone::default().encode(&mut bytes).unwrap();
        let mut client = crate::Client {
            connection: buffered(&bytes),
        };
        let mut tokens = TokenStream::new(&mut client.connection).try_unfold();
        assert!(tokens.try_next().await.is_err());
        drop(tokens);
        assert_broken(&mut client).await;
    }

    #[tokio::test]
    async fn a_token_dropped_part_way_breaks_the_connection() {
        let (mut connection, mut server) = duplex(false);
        // Half of a DONE token, with more of the message to come.
        respond(
            &mut server,
            encoded(TokenDone::default()).split_to(5),
            false,
        )
        .await;

        let mut tokens = TokenStream::new(&mut connection).try_unfold();
        assert!(tokens.try_next().now_or_never().is_none());
        drop(tokens);
        assert!(matches!(
            connection.flush_stream().now_or_never(),
            Some(Err(crate::Error::Protocol(_)))
        ));
    }

    #[tokio::test]
    async fn a_cancellation_that_reads_a_fatal_error_reports_it() {
        // Asked to cancel, the client sends an attention, and the server
        // acknowledges it after the fatal error.
        let mut connection = fatal_error_then(attention_ack());
        connection.cancellation_token().cancel();
        let error = TokenStream::new(&mut connection)
            .try_unfold()
            .try_next()
            .await
            .unwrap_err();
        assert_eq!(error.code(), Some(50001), "{error:?}");
        assert!(!error.leaves_connection_usable());

        let mut connection = fatal_error_then(attention_ack());
        connection.cancellation_token().cancel();
        let error = crate::client::rpc_response::collect_metadata_only_rpc(&mut connection)
            .await
            .unwrap_err();
        assert_eq!(error.code(), Some(50001), "{error:?}");
        assert!(!error.leaves_connection_usable());
    }

    #[tokio::test]
    async fn a_cancellation_during_a_buffered_drain_is_left_for_the_next_request() {
        let mut connection = buffered(&encoded(TokenDone::default()));
        // Requested after `flush_stream` cleared the flag, as the drain runs.
        connection.cancellation_token().cancel();
        assert!(connection.drain_buffered_tokens().await);
        assert!(!connection.attention_pending);
        assert!(connection.is_cancellation_requested());
        connection.usable().unwrap();
    }

    #[tokio::test]
    async fn a_retry_reads_the_ack_a_dropped_flush_left_pending() {
        let (mut connection, mut server) = duplex(false);
        // The end of the response the flush abandons; its ack comes later.
        respond(&mut server, encoded(TokenDone::default()), true).await;
        assert!(connection.flush_stream().now_or_never().is_none());
        assert!(connection.is_eof());
        respond(&mut server, attention_ack(), true).await;
        connection.flush_stream().await.unwrap();

        // The next request, and its response.
        let id = connection.context_mut().next_packet_id();
        connection
            .write_to_wire(PacketHeader::batch(id), BytesMut::new())
            .await
            .unwrap();
        respond(&mut server, encoded(TokenDone::with_rows(7)), true).await;
        let mut tokens = TokenStream::new(&mut connection).try_unfold();
        let token = tokens.try_next().await.unwrap();
        assert!(
            matches!(&token, Some(ReceivedToken::Done(done)) if done.rows() == 7),
            "{token:?}"
        );
    }

    #[tokio::test]
    async fn a_retry_waits_for_the_ack_instead_of_sending_another_attention() {
        let (mut connection, mut server) = duplex(false);
        assert!(connection.flush_stream().now_or_never().is_none());
        respond(&mut server, attention_ack(), true).await;
        connection.flush_stream().await.unwrap();

        let attention = server.next().await.unwrap().unwrap();
        assert!(matches!(
            attention.header().r#type(),
            PacketType::AttentionSignal
        ));
        assert!(server.next().now_or_never().is_none());
    }

    #[tokio::test]
    async fn a_later_fatal_error_keeps_the_first_code_and_ends_the_connection() {
        let mut bytes = BytesMut::new();
        TokenError::new(16917, 1, 16, "cursor is not open", "srv", "", 1)
            .encode(&mut bytes)
            .unwrap();
        TokenError::new(50002, 1, 20, "fatal", "srv", "", 1)
            .encode(&mut bytes)
            .unwrap();
        TokenDone::default().encode(&mut bytes).unwrap();
        let mut connection = buffered(&bytes);
        let error = crate::client::rpc_response::collect_rpc_outputs(&mut connection)
            .await
            .unwrap_err();
        assert_eq!(error.code(), Some(16917));
        assert!(!error.leaves_connection_usable(), "{error:?}");
    }
}
