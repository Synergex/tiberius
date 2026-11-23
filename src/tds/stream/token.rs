use crate::tds::codec::TokenSspi;
use crate::{
    client::Connection,
    tds::codec::{
        DoneStatus, TokenAltMetaData, TokenAltRow, TokenColInfo, TokenColMetaData, TokenColName,
        TokenDone, TokenEnvChange, TokenError, TokenFeatureExtAck, TokenFedAuthInfo, TokenInfo,
        TokenLoginAck, TokenOrder, TokenReturnValue, TokenRow, TokenSessionState, TokenTabName,
    },
    Error, SqlReadBytes, TokenType,
};
use futures_util::{
    io::{AsyncRead, AsyncWrite},
    stream::{BoxStream, TryStreamExt},
};
use std::{convert::TryFrom, sync::Arc};
use tracing::{event, Level};

#[derive(Debug)]
#[allow(dead_code)]
pub enum ReceivedToken {
    NewResultset(Arc<TokenColMetaData<'static>>),
    Row(TokenRow<'static>),
    AltMetaData(Arc<TokenAltMetaData<'static>>),
    AltRow(TokenAltRow<'static>),
    Done(TokenDone),
    DoneInProc(TokenDone),
    DoneProc(TokenDone),
    ReturnStatus(u32),
    // Boxed: an inline return value would make every row token 304 bytes.
    ReturnValue(Box<TokenReturnValue>),
    Order(TokenOrder),
    ColName(TokenColName),
    TabName(TokenTabName),
    ColInfo(TokenColInfo),
    EnvChange(TokenEnvChange),
    Info(TokenInfo),
    LoginAck(TokenLoginAck),
    Sspi(TokenSspi),
    FeatureExtAck(TokenFeatureExtAck),
    SessionState(TokenSessionState),
    FedAuthInfo(TokenFedAuthInfo),
    Error(TokenError),
}

pub(crate) struct TokenStream<'a, S: AsyncRead + AsyncWrite + Unpin + Send> {
    conn: &'a mut Connection<S>,
    last_error: Option<Error>,
    attention_sent: bool,
    canceled: bool,
    /// No request reads the rest of the response, so of the errors in it,
    /// only one that ended the session is kept.
    unread: bool,
}

impl<'a, S> TokenStream<'a, S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    pub(crate) fn new(conn: &'a mut Connection<S>) -> Self {
        Self {
            conn,
            last_error: None,
            attention_sent: false,
            canceled: false,
            unread: false,
        }
    }

    /// Create a token stream that drains the rest of a response no request
    /// reads. Its only error is a fatal server error, which ended the
    /// session, or a failure to read or decode the response.
    pub(crate) fn new_unread(conn: &'a mut Connection<S>) -> Self {
        Self {
            unread: true,
            ..Self::new(conn)
        }
    }

    /// Create a token stream that knows an attention signal has already been
    /// sent externally. This prevents the stream from terminating on a
    /// natural EOF before the server's attention acknowledgment arrives.
    pub(crate) fn new_with_attention(conn: &'a mut Connection<S>) -> Self {
        Self {
            attention_sent: true,
            ..Self::new_unread(conn)
        }
    }

    pub(crate) async fn flush_done(self) -> crate::Result<TokenDone> {
        let mut stream = self.try_unfold();
        let mut last_error = None;
        let mut routing = None;

        loop {
            match stream.try_next().await? {
                Some(ReceivedToken::Error(error)) => {
                    if last_error.is_none() {
                        last_error = Some(error);
                    }
                }
                Some(ReceivedToken::Done(token)) => match (last_error, routing) {
                    (Some(error), _) => return Err(Error::Server(error)),
                    (_, Some(routing)) => return Err(routing),
                    (_, _) => return Ok(token),
                },
                Some(ReceivedToken::EnvChange(TokenEnvChange::Routing { host, port })) => {
                    routing = Some(Error::Routing { host, port });
                }
                Some(_) => (),
                None => return Err(crate::Error::Protocol("Never got DONE token.".into())),
            }
        }
    }

    /// Drain the token stream until a DONE token with the Attention flag is
    /// received. Used after sending an attention signal to quickly flush the
    /// remaining result data.
    pub(crate) async fn flush_to_attention(self) -> crate::Result<()> {
        let mut stream = self.try_unfold();

        loop {
            match stream.try_next().await? {
                Some(ReceivedToken::Done(ref done))
                | Some(ReceivedToken::DoneProc(ref done))
                | Some(ReceivedToken::DoneInProc(ref done))
                    if done.status().contains(DoneStatus::Attention) =>
                {
                    return Ok(());
                }
                Some(_) => continue,
                // Stream ended naturally — the server may have finished
                // before it saw our attention. The orphaned attention ack
                // (if any) will be consumed by the next flush_stream() call.
                None => return Ok(()),
            }
        }
    }

    #[cfg(any(windows, feature = "integrated-auth-gssapi"))]
    pub(crate) async fn flush_sspi(self) -> crate::Result<TokenSspi> {
        let mut stream = self.try_unfold();
        let mut last_error = None;

        loop {
            match stream.try_next().await? {
                Some(ReceivedToken::Error(error)) => {
                    if last_error.is_none() {
                        last_error = Some(error);
                    }
                }
                Some(ReceivedToken::Sspi(token)) => return Ok(token),
                Some(_) => (),
                None => match last_error {
                    Some(err) => return Err(crate::Error::Server(err)),
                    None => return Err(crate::Error::Protocol("Never got SSPI token.".into())),
                },
            }
        }
    }

    async fn get_col_metadata(&mut self) -> crate::Result<ReceivedToken> {
        let meta = Arc::new(TokenColMetaData::decode(self.conn).await?);
        self.conn.context_mut().set_last_meta(meta.clone());

        event!(Level::TRACE, ?meta);

        Ok(ReceivedToken::NewResultset(meta))
    }

    async fn get_alt_metadata(&mut self) -> crate::Result<ReceivedToken> {
        let meta = Arc::new(TokenAltMetaData::decode(self.conn).await?);
        self.conn.context_mut().set_alt_meta(meta.clone());
        event!(Level::TRACE, ?meta);
        Ok(ReceivedToken::AltMetaData(meta))
    }

    async fn get_alt_row(&mut self) -> crate::Result<ReceivedToken> {
        let row = TokenAltRow::decode(self.conn).await?;
        event!(Level::TRACE, message = ?row);
        Ok(ReceivedToken::AltRow(row))
    }

    async fn get_row(&mut self) -> crate::Result<ReceivedToken> {
        let return_value = TokenRow::decode(self.conn).await?;

        event!(Level::TRACE, message = ?return_value);
        Ok(ReceivedToken::Row(return_value))
    }

    async fn get_nbc_row(&mut self) -> crate::Result<ReceivedToken> {
        let return_value = TokenRow::decode_nbc(self.conn).await?;

        event!(Level::TRACE, message = ?return_value);
        Ok(ReceivedToken::Row(return_value))
    }

    async fn get_return_value(&mut self) -> crate::Result<ReceivedToken> {
        let return_value = TokenReturnValue::decode(self.conn).await?;
        event!(Level::TRACE, message = ?return_value);
        Ok(ReceivedToken::ReturnValue(Box::new(return_value)))
    }

    async fn get_return_status(&mut self) -> crate::Result<ReceivedToken> {
        let status = self.conn.read_u32_le().await?;
        Ok(ReceivedToken::ReturnStatus(status))
    }

    async fn get_error(&mut self) -> crate::Result<ReceivedToken> {
        let err = TokenError::decode(self.conn).await?;
        self.conn.note_server_error(&err);

        if !self.unread || err.class() >= crate::error::FATAL_SEVERITY {
            self.last_error =
                Error::add_server_error(self.last_error.take(), Error::Server(err.clone()));
        }

        event!(
            name: "tiberius.error",
            Level::ERROR,
            number = err.code,
            class = err.class,
            state = err.state,
            line = err.line,
            procedure = %err.procedure,
            message = %err.message
        );
        Ok(ReceivedToken::Error(err))
    }

    async fn get_order(&mut self) -> crate::Result<ReceivedToken> {
        let order = TokenOrder::decode(self.conn).await?;
        event!(Level::TRACE, message = ?order);
        Ok(ReceivedToken::Order(order))
    }

    async fn get_col_info(&mut self) -> crate::Result<ReceivedToken> {
        let info = TokenColInfo::decode(self.conn).await?;
        event!(Level::TRACE, message = ?info);
        Ok(ReceivedToken::ColInfo(info))
    }

    async fn get_col_name(&mut self) -> crate::Result<ReceivedToken> {
        let names = TokenColName::decode(self.conn).await?;
        event!(Level::TRACE, message = ?names);
        Ok(ReceivedToken::ColName(names))
    }

    async fn get_tab_name(&mut self) -> crate::Result<ReceivedToken> {
        let names = TokenTabName::decode(self.conn).await?;
        event!(Level::TRACE, message = ?names);
        Ok(ReceivedToken::TabName(names))
    }

    async fn get_done_value(&mut self) -> crate::Result<ReceivedToken> {
        let done = TokenDone::decode(self.conn).await?;
        event!(Level::TRACE, "{}", done);
        Ok(ReceivedToken::Done(done))
    }

    async fn get_done_proc_value(&mut self) -> crate::Result<ReceivedToken> {
        let done = TokenDone::decode(self.conn).await?;
        event!(Level::TRACE, "{}", done);
        Ok(ReceivedToken::DoneProc(done))
    }

    async fn get_done_in_proc_value(&mut self) -> crate::Result<ReceivedToken> {
        let done = TokenDone::decode(self.conn).await?;
        event!(Level::TRACE, "{}", done);
        Ok(ReceivedToken::DoneInProc(done))
    }

    async fn get_env_change(&mut self) -> crate::Result<ReceivedToken> {
        let change = TokenEnvChange::decode(self.conn).await?;
        self.conn.context_mut().apply_env_change(&change);
        event!(Level::INFO, "{}", change);

        Ok(ReceivedToken::EnvChange(change))
    }

    async fn get_info(&mut self) -> crate::Result<ReceivedToken> {
        let info = TokenInfo::decode(self.conn).await?;
        event!(
            name: "tiberius.info",
            Level::INFO,
            number = info.number,
            class = info.class,
            state = info.state,
            message = %info.message
        );
        Ok(ReceivedToken::Info(info))
    }

    async fn get_login_ack(&mut self) -> crate::Result<ReceivedToken> {
        let ack = TokenLoginAck::decode(self.conn).await?;
        self.conn.context_mut().set_version(ack.tds_version);
        // ProgVersion bytes are major, minor, build high, build low.
        let [major, minor, build_high, build_low] = ack.version.to_le_bytes();
        let build = u16::from_be_bytes([build_high, build_low]);
        self.conn
            .context_mut()
            .set_server_version(format!("{major}.{minor}.{build}"));
        event!(Level::INFO, "{} version {}", ack.prog_name, ack.version);
        Ok(ReceivedToken::LoginAck(ack))
    }

    async fn get_feature_ext_ack(&mut self) -> crate::Result<ReceivedToken> {
        let ack = TokenFeatureExtAck::decode(self.conn).await?;
        event!(
            Level::INFO,
            "FeatureExtAck with {} features",
            ack.features.len()
        );
        Ok(ReceivedToken::FeatureExtAck(ack))
    }

    async fn get_session_state(&mut self) -> crate::Result<ReceivedToken> {
        let state = TokenSessionState::decode(self.conn).await?;
        event!(Level::TRACE, message = ?state);
        Ok(ReceivedToken::SessionState(state))
    }

    async fn get_fed_auth_info(&mut self) -> crate::Result<ReceivedToken> {
        let info = TokenFedAuthInfo::decode(self.conn).await?;
        event!(Level::TRACE, message = ?info);
        Ok(ReceivedToken::FedAuthInfo(info))
    }

    async fn get_sspi(&mut self) -> crate::Result<ReceivedToken> {
        let sspi = TokenSspi::decode_async(self.conn).await?;
        event!(Level::TRACE, "SSPI response");
        Ok(ReceivedToken::Sspi(sspi))
    }

    /// Reads the next token, or `None` once the response ends: at its end,
    /// or at the acknowledgment of an attention.
    async fn next_token(&mut self) -> crate::Result<Option<ReceivedToken>> {
        loop {
            // Only check for EOF when we're NOT waiting for an attention
            // acknowledgment. After sending attention, the server will
            // always send a Done+Attention response, even if the original
            // query response has already ended (EOM seen). Skipping the
            // EOF check ensures we keep reading until that ack arrives.
            if !self.attention_sent && self.conn.is_eof() {
                return Ok(None);
            }

            // Read the next token-type byte. While we have not yet sent an
            // attention signal, use the cancellable read: a packet-less
            // statement (e.g. `WAITFOR DELAY`) produces no bytes until it
            // completes, so a bare `read_u8().await` would park here and
            // never observe a `cancel()`. `read_u8_or_cancel` checks the
            // cancellation flag up front and otherwise races the read
            // against a waker-backed signal; on cancellation it sends the
            // attention and we switch to the drain path. Once draining, a
            // plain read suffices — the Done+Attention ack is incoming.
            let ty_byte = if self.attention_sent {
                self.conn.read_u8().await?
            } else {
                match self.conn.read_u8_or_cancel().await? {
                    Some(byte) => byte,
                    None => {
                        self.attention_sent = true;
                        self.canceled = true;
                        self.unread = true;
                        continue;
                    }
                }
            };

            self.conn.decoding_token();
            let ty = TokenType::try_from(ty_byte)
                .map_err(|_| Error::Protocol(format!("invalid token type {:x}", ty_byte).into()))?;

            let token = match ty {
                TokenType::ReturnStatus => self.get_return_status().await,
                TokenType::AltMetaData => self.get_alt_metadata().await,
                TokenType::ColMetaData => self.get_col_metadata().await,
                TokenType::ColName => self.get_col_name().await,
                TokenType::Row => self.get_row().await,
                TokenType::NbcRow => self.get_nbc_row().await,
                TokenType::AltRow => self.get_alt_row().await,
                TokenType::Done => self.get_done_value().await,
                TokenType::DoneProc => self.get_done_proc_value().await,
                TokenType::DoneInProc => self.get_done_in_proc_value().await,
                TokenType::ReturnValue => self.get_return_value().await,
                TokenType::Error => self.get_error().await,
                TokenType::Order => self.get_order().await,
                TokenType::TabName => self.get_tab_name().await,
                TokenType::ColInfo => self.get_col_info().await,
                TokenType::EnvChange => self.get_env_change().await,
                TokenType::SessionState => self.get_session_state().await,
                TokenType::Info => self.get_info().await,
                TokenType::LoginAck => self.get_login_ack().await,
                TokenType::Sspi => self.get_sspi().await,
                TokenType::FeatureExtAck => self.get_feature_ext_ack().await,
                TokenType::FedAuthInfo => self.get_fed_auth_info().await,
            }
            .map_err(Error::into_decode_failure)?;
            self.conn.token_decoded();

            // When draining after attention, skip all tokens until we see
            // Done+Attention, then terminate the stream.
            if self.attention_sent {
                match &token {
                    ReceivedToken::Done(done)
                    | ReceivedToken::DoneProc(done)
                    | ReceivedToken::DoneInProc(done)
                        if done.status().contains(DoneStatus::Attention) =>
                    {
                        self.conn.attention_acknowledged();
                        return Ok(None);
                    }
                    _ => continue,
                }
            }

            return Ok(Some(token));
        }
    }

    /// The error the stream ends with once the response ended, or once `cut`
    /// cut it short: the response's first server error, kept together with
    /// `cut` or with the cancellation that ended the response.
    fn final_error(&mut self, cut: Option<Error>) -> Option<Error> {
        let cut = cut.or_else(|| self.canceled.then_some(Error::Canceled));
        match cut {
            Some(cut) => Some(Error::cut_short(self.last_error.take(), cut)),
            None => self.last_error.take(),
        }
    }

    pub fn try_unfold(self) -> BoxStream<'a, crate::Result<ReceivedToken>> {
        let stream = futures_util::stream::try_unfold(self, |mut this| async move {
            match this.next_token().await {
                Ok(Some(token)) => Ok(Some((token, this))),
                ended => match this.final_error(ended.err()) {
                    Some(error) => Err(error),
                    None => Ok(None),
                },
            }
        });

        Box::pin(stream)
    }
}
