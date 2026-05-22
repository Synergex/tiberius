//! Server entrypoint for the TDS server.

use std::time::{Duration, Instant};

use futures_util::stream::StreamExt;
use futures_util::SinkExt;

use crate::server::backend::NetStream;
use crate::server::connection::TdsConnection;
use crate::server::handler::{
    AttentionHandler, AuthHandler, BulkLoadHandler, ErrorHandler, RpcHandler, SqlBatchHandler,
    TdsConnectionContext, TdsServerHandlers,
};
use crate::server::messages::{AllHeaders, BackendToken, TdsBackendMessage, TdsFrontendMessage};
use crate::server::state::TdsConnectionState;
use crate::server::tls::{MaybeTlsStream, NoTls, TlsAccept};
use crate::tds::codec::{DoneStatus, TokenDone};
use crate::Error;
use crate::EncryptionLevel;

/// Default startup timeout (60 seconds).
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);

type ServerStream<S, T> = MaybeTlsStream<S, <T as TlsAccept>::Stream<S>>;

/// Process a TDS connection over any NetStream backend.
pub async fn process_connection<S, T, H>(
    stream: S,
    tls_acceptor: Option<T>,
    handlers: &H,
) -> Result<(), Error>
where
    S: NetStream,
    T: TlsAccept,
    H: TdsServerHandlers,
{
    let stream = MaybeTlsStream::new_raw(stream);
    let mut conn: TdsConnection<ServerStream<S, T>> = TdsConnection::new(stream);

    let startup_deadline = Instant::now() + STARTUP_TIMEOUT;
    let auth_handler = handlers.auth_handler();
    let sql_batch_handler = handlers.sql_batch_handler();
    let rpc_handler = handlers.rpc_handler();
    let bulk_load_handler = handlers.bulk_load_handler();
    let attention_handler = handlers.attention_handler();
    let error_handler = handlers.error_handler();

    loop {
        // Check for closed state
        if conn.state() == TdsConnectionState::Closed {
            return Ok(());
        }

        if matches!(
            conn.state(),
            TdsConnectionState::AwaitingPrelogin
                | TdsConnectionState::AwaitingLogin
                | TdsConnectionState::AuthenticationInProgress
        ) {
            if Instant::now() > startup_deadline {
                return Err(Error::Protocol("startup timeout exceeded".into()));
            }
        }

        let msg = match conn.next().await {
            Some(Ok(msg)) => msg,
            Some(Err(e)) => {
                let mut err = Error::Protocol(e.to_string().into());
                error_handler.on_error(&conn, &mut err);
                return Err(e);
            }
            None => return Ok(()),
        };

        let result = dispatch_message(
            &mut conn,
            msg,
            auth_handler,
            sql_batch_handler,
            rpc_handler,
            bulk_load_handler,
            attention_handler,
            &tls_acceptor,
        )
        .await;

        if let Err(e) = result {
            let mut err = Error::Protocol(e.to_string().into());
            error_handler.on_error(&conn, &mut err);
            return Err(e);
        }
    }
}

async fn dispatch_message<S, T, AH, SH, RH, BH, AT>(
    conn: &mut TdsConnection<ServerStream<S, T>>,
    msg: TdsFrontendMessage,
    auth_handler: &AH,
    sql_batch_handler: &SH,
    rpc_handler: &RH,
    bulk_load_handler: &BH,
    attention_handler: &AT,
    tls_acceptor: &Option<T>,
) -> Result<(), Error>
where
    S: NetStream,
    T: TlsAccept,
    AH: AuthHandler,
    SH: SqlBatchHandler,
    RH: RpcHandler,
    BH: BulkLoadHandler,
    AT: AttentionHandler,
{
    let current_state = conn.state();
    match (current_state, msg) {
        (TdsConnectionState::AwaitingPrelogin, TdsFrontendMessage::Prelogin(message)) => {
            auth_handler.on_prelogin(conn, message).await?;
            maybe_upgrade_tls(conn, tls_acceptor).await
        }
        (TdsConnectionState::AwaitingLogin, TdsFrontendMessage::Login(message)) => {
            maybe_downgrade_tls::<S, T>(conn)?;
            auth_handler.on_login(conn, message).await
        }
        (TdsConnectionState::AuthenticationInProgress, TdsFrontendMessage::Sspi(token)) => {
            auth_handler.on_sspi(conn, token).await
        }
        (TdsConnectionState::ReadyForQuery, TdsFrontendMessage::SqlBatch(message)) => {
            conn.set_state(TdsConnectionState::QueryInProgress);
            conn.clear_attention();
            apply_request_headers::<S, T>(conn, &message.headers, message.request_flags);
            let result = sql_batch_handler.on_sql_batch(conn, message).await;
            if result.is_ok() {
                finish_attention_if_needed::<S, T>(conn).await?;
            }
            // Return to ReadyForQuery if not in AttentionPending (attention clears itself)
            if conn.state() == TdsConnectionState::QueryInProgress {
                conn.set_state(TdsConnectionState::ReadyForQuery);
            }
            result
        }
        (TdsConnectionState::ReadyForQuery, TdsFrontendMessage::Rpc(message)) => {
            conn.set_state(TdsConnectionState::QueryInProgress);
            conn.clear_attention();
            apply_request_headers::<S, T>(conn, &message.headers, message.request_flags);
            let result = rpc_handler.on_rpc(conn, message).await;
            if result.is_ok() {
                finish_attention_if_needed::<S, T>(conn).await?;
            }
            // Return to ReadyForQuery if not in AttentionPending
            if conn.state() == TdsConnectionState::QueryInProgress {
                conn.set_state(TdsConnectionState::ReadyForQuery);
            }
            result
        }
        (TdsConnectionState::BulkLoadInProgress, TdsFrontendMessage::BulkLoad(payload)) => {
            conn.clear_attention();
            let result = bulk_load_handler.on_bulk_load(conn, payload).await;
            if result.is_ok() {
                finish_attention_if_needed::<S, T>(conn).await?;
            }
            result
        }
        // Reject attention during authentication phases
        (
            TdsConnectionState::AwaitingPrelogin
            | TdsConnectionState::AwaitingLogin
            | TdsConnectionState::AuthenticationInProgress,
            TdsFrontendMessage::Attention,
        ) => Err(Error::Protocol(
            "attention signal not allowed during authentication".into(),
        )),
        // Handle attention in other states
        (_, TdsFrontendMessage::Attention) => {
            conn.mark_attention();
            attention_handler.on_attention(conn).await?;
            if conn.attention_pending() {
                let done = TokenDone::with_status(DoneStatus::Attention.into(), 0);
                conn.send(TdsBackendMessage::Token(BackendToken::Done(done)))
                    .await?;
                conn.clear_attention();
            }
            Ok(())
        }
        (_, msg) => Err(Error::Protocol(
            format!(
                "unexpected message {} for connection state {}",
                msg.message_type_name(),
                current_state
            )
            .into(),
        )),
    }
}

async fn finish_attention_if_needed<S, T>(
    conn: &mut TdsConnection<ServerStream<S, T>>,
) -> Result<(), Error>
where
    S: NetStream,
    T: TlsAccept,
{
    if conn.attention_pending() {
        let done = TokenDone::with_status(DoneStatus::Attention.into(), 0);
        conn.send(TdsBackendMessage::Token(BackendToken::Done(done)))
            .await?;
    }
    Ok(())
}

fn apply_request_headers<S, T>(
    conn: &mut TdsConnection<ServerStream<S, T>>,
    headers: &AllHeaders,
    request_flags: crate::server::messages::RequestFlags,
)
where
    S: NetStream,
    T: TlsAccept,
{
    conn.set_last_request_headers(headers.clone());
    if let Some(tx) = headers.transaction_descriptor.as_ref() {
        conn.set_transaction_descriptor(tx.descriptor);
    }
    if request_flags.reset_connection || request_flags.reset_connection_skip_tran {
        conn.mark_reset_connection(request_flags.reset_connection_skip_tran);
    }
}

async fn maybe_upgrade_tls<S, T>(
    conn: &mut TdsConnection<ServerStream<S, T>>,
    tls_acceptor: &Option<T>,
) -> Result<(), Error>
where
    S: NetStream,
    T: TlsAccept,
{
    match conn.encryption() {
        EncryptionLevel::NotSupported => Ok(()),
        _ => {
            let Some(acceptor) = tls_acceptor.as_ref() else {
                return Err(Error::Protocol("TLS requested but no acceptor configured".into()));
            };

            if conn.is_secure() {
                return Ok(());
            }

            let raw = conn
                .stream_mut()
                .take_raw()
                .ok_or_else(|| Error::Protocol("TLS upgrade requires a raw stream".into()))?;
            let tls_stream = acceptor.accept(raw).await?;
            conn.stream_mut().set_tls(tls_stream);
            conn.set_secure(true);
            Ok(())
        }
    }
}

fn maybe_downgrade_tls<S, T>(conn: &mut TdsConnection<ServerStream<S, T>>) -> Result<(), Error>
where
    S: NetStream,
    T: TlsAccept,
{
    if conn.encryption() == EncryptionLevel::Off && conn.is_secure() {
        conn.stream_mut().downgrade()?;
        conn.set_secure(false);
    }

    Ok(())
}

/// Helper for callers that do not support TLS.
pub async fn process_connection_no_tls<S, H>(stream: S, handlers: &H) -> Result<(), Error>
where
    S: NetStream,
    H: TdsServerHandlers,
{
    let tls: Option<NoTls> = None;
    process_connection(stream, tls, handlers).await
}
