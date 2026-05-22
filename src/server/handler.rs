//! Handler traits for the TDS server.
//!
//! This module provides the traits that handlers must implement to process
//! TDS protocol messages. Handlers are the core abstraction for building
//! custom TDS servers - they receive parsed protocol messages and produce
//! responses.
//!
//! # Key Types
//!
//! - [`TdsClient`]: Combined trait for client connections (use this in handler bounds)
//! - [`TdsConnectionContext`]: Access to connection state, metadata, and configuration
//! - [`TdsServerHandlers`]: Bundle of all handlers required by a server
//!
//! # Handler Traits
//!
//! | Trait | Purpose | Required |
//! |-------|---------|----------|
//! | [`AuthHandler`] | Prelogin and login handshake | Yes |
//! | [`SqlBatchHandler`] | Simple SQL query execution | Yes |
//! | [`RpcHandler`] | Stored procedure / parameterized queries | Yes* |
//! | [`BulkLoadHandler`] | Bulk data import | Yes* |
//! | [`AttentionHandler`] | Query cancellation | Yes* |
//! | [`ErrorHandler`] | Error interception and logging | Yes* |
//!
//! *Default implementations provided: [`RejectRpc`], [`RejectBulkLoad`], [`NoOpAttention`], [`NoOpError`]
//!
//! # Attention Handling
//!
//! Clients can send an attention signal to cancel in-flight operations. Handlers
//! should periodically check `client.attention_pending()` during long operations
//! and abort early if an attention is detected. The server framework automatically
//! sends the appropriate DONE token with the Attention flag.
//!
//! # Example
//!
//! ```ignore
//! use tiberius::server::{
//!     AuthHandler, SqlBatchHandler, RpcHandler, TdsClient, TdsServerHandlers,
//!     RejectRpc, RejectBulkLoad, NoOpAttention, NoOpError, BoxFuture,
//! };
//!
//! struct MyHandlers {
//!     auth: MyAuthHandler,
//!     sql_batch: MySqlBatchHandler,
//! }
//!
//! impl TdsServerHandlers for MyHandlers {
//!     type Auth = MyAuthHandler;
//!     type SqlBatch = MySqlBatchHandler;
//!     type Rpc = RejectRpc;
//!     type Bulk = RejectBulkLoad;
//!     type Attention = NoOpAttention;
//!     type Error = NoOpError;
//!
//!     fn auth_handler(&self) -> &Self::Auth { &self.auth }
//!     fn sql_batch_handler(&self) -> &Self::SqlBatch { &self.sql_batch }
//!     fn rpc_handler(&self) -> &Self::Rpc { &RejectRpc }
//!     fn bulk_load_handler(&self) -> &Self::Bulk { &RejectBulkLoad }
//!     fn attention_handler(&self) -> &Self::Attention { &NoOpAttention }
//!     fn error_handler(&self) -> &Self::Error { &NoOpError }
//! }
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;

use futures_util::sink::Sink;

use crate::EncryptionLevel;
use crate::server::messages::{AllHeaders, TdsBackendMessage, TransactionDescriptor};
use crate::server::state::TdsConnectionState;
use crate::tds::codec::FeatureLevel;
use crate::Result;

/// Well-known connection metadata fields.
///
/// This struct provides typed access to commonly-used metadata fields
/// that are set during authentication. For custom or non-standard fields,
/// use the `custom` HashMap.
///
/// # Example
///
/// ```ignore
/// let metadata = client.connection_metadata();
/// if let Some(user) = &metadata.user {
///     println!("Connected user: {}", user);
/// }
/// ```
#[derive(Debug, Default, Clone)]
pub struct ConnectionMetadata {
    /// The authenticated user name.
    pub user: Option<String>,
    /// The database name selected during login.
    pub database: Option<String>,
    /// The client application name.
    pub application: Option<String>,
    /// The server name provided by the client.
    pub server: Option<String>,
    /// The client hostname.
    pub hostname: Option<String>,
    /// Custom metadata fields for extension.
    pub custom: HashMap<String, String>,
}

/// A boxed future that is `Send` and has a lifetime `'a`.
///
/// This type alias is provided for convenience when implementing handler traits.
///
/// # Example
///
/// ```ignore
/// fn on_sql_batch<'a, C>(&'a self, client: &'a mut C, msg: SqlBatchMessage) -> BoxFuture<'a, Result<()>>
/// where
///     C: TdsClient + 'a,
/// {
///     Box::pin(async move {
///         // handler implementation
///         Ok(())
///     })
/// }
/// ```
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Connection context exposed to handlers.
///
/// This trait provides access to connection state, metadata, and configuration.
/// For most handler implementations, use the [`TdsClient`] supertrait which
/// combines this with message sending capabilities.
pub trait TdsConnectionContext {
    fn socket_addr(&self) -> SocketAddr;
    fn is_secure(&self) -> bool;
    fn state(&self) -> TdsConnectionState;
    fn set_state(&mut self, state: TdsConnectionState);
    /// Get the connection metadata (typed fields + custom HashMap).
    fn connection_metadata(&self) -> &ConnectionMetadata;
    /// Get mutable access to the connection metadata.
    fn connection_metadata_mut(&mut self) -> &mut ConnectionMetadata;
    fn next_packet_id(&mut self) -> u8;
    fn packet_size(&self) -> u32;
    fn set_packet_size(&mut self, size: u32);
    fn tds_version(&self) -> FeatureLevel;
    fn set_tds_version(&mut self, version: FeatureLevel);
    /// Get the current transaction descriptor.
    fn transaction_descriptor(&self) -> TransactionDescriptor;
    /// Set the current transaction descriptor.
    fn set_transaction_descriptor(&mut self, desc: TransactionDescriptor);
    fn last_request_headers(&self) -> &AllHeaders;
    fn encryption(&self) -> EncryptionLevel;
    fn set_encryption(&mut self, encryption: EncryptionLevel);
    /// True if a cancel/attention has been observed.
    fn attention_pending(&self) -> bool;
    /// Clear the cancel/attention flag.
    fn clear_attention(&mut self);
    /// Poll the wire for an attention signal while inside a handler.
    fn poll_attention<'a>(&'a mut self) -> BoxFuture<'a, Result<bool>>
    where
        Self: Sized;
}

/// Combined trait for TDS client connections.
///
/// This trait combines [`TdsConnectionContext`] with the [`Sink`] trait for sending messages,
/// plus the required bounds (`Unpin`, `Send`). Using this trait simplifies handler
/// bounds significantly.
///
/// # Example
///
/// Instead of writing:
/// ```ignore
/// fn on_sql_batch<'a, C>(&'a self, client: &'a mut C, msg: SqlBatchMessage) -> BoxFuture<'a, Result<()>>
/// where
///     C: TdsConnectionContext + Sink<TdsBackendMessage, Error = Error> + Unpin + Send + 'a;
/// ```
///
/// You can write:
/// ```ignore
/// fn on_sql_batch<'a, C>(&'a self, client: &'a mut C, msg: SqlBatchMessage) -> BoxFuture<'a, Result<()>>
/// where
///     C: TdsClient + 'a;
/// ```
pub trait TdsClient:
    TdsConnectionContext + Sink<TdsBackendMessage, Error = crate::Error> + Unpin + Send
{
}

impl<T> TdsClient for T where
    T: TdsConnectionContext + Sink<TdsBackendMessage, Error = crate::Error> + Unpin + Send
{
}

/// Authentication and handshake handling.
///
/// This trait handles the TDS prelogin and login handshake. It is called
/// during the initial connection setup before the client can execute queries.
///
/// # Flow
///
/// 1. Client sends `Prelogin` → [`on_prelogin`](Self::on_prelogin) called
/// 2. (Optional) TLS upgrade if encryption negotiated
/// 3. Client sends `Login7` → [`on_login`](Self::on_login) called
/// 4. (Optional) For SSPI auth: [`on_sspi`](Self::on_sspi) called for each token
/// 5. Handler sends `LoginAck` + `Done` tokens on success
/// 6. Connection state becomes `ReadyForQuery`
///
/// # Provided Implementation
///
/// Use [`TdsAuthHandler`](crate::server::TdsAuthHandler) with [`AuthBuilder`](crate::server::AuthBuilder)
/// for a full-featured authentication handler supporting SQL auth, SSPI/Kerberos, and FedAuth.
///
/// # Example
///
/// ```ignore
/// impl AuthHandler for MyAuthHandler {
///     fn on_prelogin<'a, C>(&'a self, client: &'a mut C, msg: PreloginMessage) -> BoxFuture<'a, Result<()>>
///     where C: TdsClient + 'a
///     {
///         Box::pin(async move {
///             // Negotiate encryption, send prelogin response
///             client.set_state(TdsConnectionState::AwaitingLogin);
///             Ok(())
///         })
///     }
///
///     fn on_login<'a, C>(&'a self, client: &'a mut C, msg: LoginMessage<'static>) -> BoxFuture<'a, Result<()>>
///     where C: TdsClient + 'a
///     {
///         Box::pin(async move {
///             // Validate credentials, send LoginAck + Done
///             client.set_state(TdsConnectionState::ReadyForQuery);
///             Ok(())
///         })
///     }
/// }
/// ```
pub trait AuthHandler: Send + Sync {
    /// Handle a prelogin message from the client.
    ///
    /// This is the first message in the TDS handshake. The handler should:
    /// 1. Negotiate encryption level
    /// 2. Send a prelogin response
    /// 3. Transition state to `AwaitingLogin`
    fn on_prelogin<'a, C>(
        &'a self,
        client: &'a mut C,
        message: crate::tds::codec::PreloginMessage,
    ) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClient + 'a;

    /// Handle a login message from the client.
    ///
    /// This is called after prelogin (and optional TLS upgrade). The handler should:
    /// 1. Validate credentials (SQL auth, FedAuth, or initiate SSPI)
    /// 2. On success: send `LoginAck`, `EnvChange`, `Done` tokens
    /// 3. Transition state to `ReadyForQuery` (or `AuthenticationInProgress` for SSPI)
    /// 4. On failure: send `Error` + `Done` tokens and transition to `Closed`
    fn on_login<'a, C>(
        &'a self,
        client: &'a mut C,
        message: crate::tds::codec::LoginMessage<'static>,
    ) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClient + 'a;

    /// Handle an SSPI authentication token.
    ///
    /// Called during multi-step SSPI (Kerberos/NTLM) authentication. The handler
    /// should process the token and either:
    /// - Send an SSPI response token and remain in `AuthenticationInProgress`
    /// - Complete authentication with `LoginAck` + `Done` and transition to `ReadyForQuery`
    ///
    /// The default implementation rejects SSPI with a protocol error.
    fn on_sspi<'a, C>(
        &'a self,
        _client: &'a mut C,
        _token: crate::tds::codec::TokenSspi,
    ) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async {
            Err(crate::Error::Protocol(
                "SSPI message not supported by this auth handler".into(),
            ))
        })
    }
}

/// SQL batch handler for simple query execution.
///
/// This handler processes SQL batch requests (simple queries without parameters).
/// It is the primary handler for executing SQL statements.
///
/// # Response Format
///
/// The handler should send results using these token patterns:
///
/// - **Result set**: `ColMetaData` → `Row`* → `Done`
/// - **Row count**: `Done` with `DoneCount` flag and row count
/// - **Error**: `Error` → `Done` with `Error` flag
/// - **Multiple results**: Repeat the above patterns
///
/// Use [`ResultSetWriter`](crate::server::ResultSetWriter) for convenient result set generation.
///
/// # Attention Handling
///
/// For long-running queries, periodically check `client.attention_pending()` or
/// call `client.poll_attention().await` to detect cancellation requests. If an
/// attention is detected, stop processing and return `Ok(())` - the framework
/// will send the appropriate cancellation acknowledgment.
///
/// # Example
///
/// ```ignore
/// impl SqlBatchHandler for MySqlHandler {
///     fn on_sql_batch<'a, C>(&'a self, client: &'a mut C, msg: SqlBatchMessage) -> BoxFuture<'a, Result<()>>
///     where C: TdsClient + 'a
///     {
///         Box::pin(async move {
///             let sql = &msg.batch;
///             // Execute query, send results
///             let mut writer = ResultSetWriter::new(client);
///             writer.begin(&columns).await?;
///             writer.row(&row_data).await?;
///             writer.finish().await?;
///             Ok(())
///         })
///     }
/// }
/// ```
pub trait SqlBatchHandler: Send + Sync {
    /// Handle a SQL batch request from the client.
    ///
    /// The `message` contains the SQL text and request headers (including
    /// transaction descriptor if applicable).
    fn on_sql_batch<'a, C>(
        &'a self,
        client: &'a mut C,
        message: crate::server::messages::SqlBatchMessage,
    ) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClient + 'a;
}

/// RPC handler for stored procedure and parameterized query execution.
///
/// This handler processes RPC (Remote Procedure Call) requests, which are used for:
/// - Executing stored procedures by name or ID
/// - Parameterized queries via `sp_executesql`
/// - Prepared statement execution via `sp_prepexec`, `sp_execute`
///
/// # Well-Known Procedures
///
/// | Proc ID | Name | Purpose |
/// |---------|------|---------|
/// | 10 | `sp_executesql` | Parameterized query |
/// | 11 | `sp_prepare` | Prepare a statement |
/// | 12 | `sp_execute` | Execute prepared statement |
/// | 13 | `sp_prepexec` | Prepare and execute |
/// | 14 | `sp_unprepare` | Release prepared statement |
/// | 15 | `sp_cursor*` | Cursor operations |
///
/// # Default Implementation
///
/// Use [`RejectRpc`] if your server doesn't support RPC operations.
///
/// # Example
///
/// ```ignore
/// impl RpcHandler for MyRpcHandler {
///     fn on_rpc<'a, C>(&'a self, client: &'a mut C, msg: RpcMessage) -> BoxFuture<'a, Result<()>>
///     where C: TdsClient + 'a
///     {
///         Box::pin(async move {
///             match msg.proc_id {
///                 Some(RpcProcId::SpExecuteSql) => {
///                     // Handle parameterized query
///                 }
///                 _ => {
///                     // Unknown procedure
///                 }
///             }
///             Ok(())
///         })
///     }
/// }
/// ```
pub trait RpcHandler: Send + Sync {
    /// Handle an RPC request from the client.
    ///
    /// The `message` contains the procedure ID/name, parameters, and request headers.
    fn on_rpc<'a, C>(
        &'a self,
        client: &'a mut C,
        message: crate::server::messages::RpcMessage,
    ) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClient + 'a;
}

/// Bulk load handler for high-speed data import.
///
/// This handler processes bulk load operations (INSERT BULK). The data arrives
/// as raw binary chunks containing encoded rows. Bulk load is significantly
/// faster than individual INSERT statements for large data volumes.
///
/// # Protocol
///
/// 1. Client sends bulk load metadata (column definitions)
/// 2. Client sends data chunks → [`on_bulk_load`](Self::on_bulk_load) called for each
/// 3. Client signals end of data
/// 4. Handler sends `Done` with row count
///
/// # Default Implementation
///
/// Use [`RejectBulkLoad`] if your server doesn't support bulk load operations.
pub trait BulkLoadHandler: Send + Sync {
    /// Handle a bulk load data chunk from the client.
    ///
    /// The `payload` contains raw encoded row data. The handler should
    /// decode and process rows according to the bulk load metadata
    /// received earlier.
    fn on_bulk_load<'a, C>(
        &'a self,
        client: &'a mut C,
        payload: bytes::BytesMut,
    ) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClient + 'a;
}

/// Attention handler for query cancellation.
///
/// This handler is called when the client sends an attention signal to cancel
/// an in-flight operation. The handler can perform cleanup such as aborting
/// database transactions or releasing resources.
///
/// The server framework automatically sends the `Done` token with the `Attention`
/// flag after this handler completes.
///
/// # Default Implementation
///
/// Use [`NoOpAttention`] if you don't need custom cancellation logic.
///
/// # Example
///
/// ```ignore
/// impl AttentionHandler for MyAttentionHandler {
///     fn on_attention<'a, C>(&'a self, client: &'a mut C) -> BoxFuture<'a, Result<()>>
///     where C: TdsClient + 'a
///     {
///         Box::pin(async move {
///             // Abort any pending database transaction
///             // Release resources
///             log::info!("Query cancelled by client");
///             Ok(())
///         })
///     }
/// }
/// ```
pub trait AttentionHandler: Send + Sync {
    /// Handle an attention (cancel) signal from the client.
    fn on_attention<'a, C>(&'a self, client: &'a mut C) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClient + 'a;
}

/// Error handler for intercepting and logging errors.
///
/// This handler is called when an error occurs during request processing.
/// It can be used to:
/// - Log errors with connection context
/// - Modify error messages before sending to client
/// - Track error metrics
///
/// The handler receives a mutable reference to the error, allowing modification.
///
/// # Default Implementation
///
/// Use [`NoOpError`] if you don't need error interception.
///
/// # Example
///
/// ```ignore
/// impl ErrorHandler for MyErrorHandler {
///     fn on_error(&self, client: &dyn TdsConnectionContext, error: &mut tiberius::Error) {
///         let user = client.connection_metadata().user.as_deref().unwrap_or("unknown");
///         log::error!("Error for user {}: {:?}", user, error);
///     }
/// }
/// ```
pub trait ErrorHandler: Send + Sync {
    /// Called when an error occurs during request processing.
    ///
    /// The `client` provides read-only access to connection metadata.
    /// The `error` can be modified before it is sent to the client.
    fn on_error(&self, client: &dyn TdsConnectionContext, error: &mut crate::Error);
}

/// Bundle of handlers required by the server.
///
/// This trait aggregates all the handler types required to run a TDS server.
/// Implement this trait on a struct that holds your handler instances.
///
/// # Required Handlers
///
/// - [`AuthHandler`]: Authentication and login handshake
/// - [`SqlBatchHandler`]: Simple SQL query execution
/// - [`RpcHandler`]: Stored procedures and parameterized queries
/// - [`BulkLoadHandler`]: High-speed data import
/// - [`AttentionHandler`]: Query cancellation
/// - [`ErrorHandler`]: Error interception
///
/// # Default Handlers
///
/// For handlers you don't need, use the provided defaults:
/// - [`RejectRpc`]: Rejects all RPC requests
/// - [`RejectBulkLoad`]: Rejects all bulk load requests
/// - [`NoOpAttention`]: No-op attention handler
/// - [`NoOpError`]: No-op error handler
///
/// # Example
///
/// ```ignore
/// struct MyServer {
///     auth: TdsAuthHandler,
///     sql: MySqlBatchHandler,
/// }
///
/// impl TdsServerHandlers for MyServer {
///     type Auth = TdsAuthHandler;
///     type SqlBatch = MySqlBatchHandler;
///     type Rpc = RejectRpc;
///     type Bulk = RejectBulkLoad;
///     type Attention = NoOpAttention;
///     type Error = NoOpError;
///
///     fn auth_handler(&self) -> &Self::Auth { &self.auth }
///     fn sql_batch_handler(&self) -> &Self::SqlBatch { &self.sql }
///     fn rpc_handler(&self) -> &Self::Rpc { &RejectRpc }
///     fn bulk_load_handler(&self) -> &Self::Bulk { &RejectBulkLoad }
///     fn attention_handler(&self) -> &Self::Attention { &NoOpAttention }
///     fn error_handler(&self) -> &Self::Error { &NoOpError }
/// }
/// ```
pub trait TdsServerHandlers: Send + Sync {
    /// The authentication handler type.
    type Auth: AuthHandler;
    /// The SQL batch handler type.
    type SqlBatch: SqlBatchHandler;
    /// The RPC handler type.
    type Rpc: RpcHandler;
    /// The bulk load handler type.
    type Bulk: BulkLoadHandler;
    /// The attention handler type.
    type Attention: AttentionHandler;
    /// The error handler type.
    type Error: ErrorHandler;

    /// Returns the authentication handler.
    fn auth_handler(&self) -> &Self::Auth;
    /// Returns the SQL batch handler.
    fn sql_batch_handler(&self) -> &Self::SqlBatch;
    /// Returns the RPC handler.
    fn rpc_handler(&self) -> &Self::Rpc;
    /// Returns the bulk load handler.
    fn bulk_load_handler(&self) -> &Self::Bulk;
    /// Returns the attention handler.
    fn attention_handler(&self) -> &Self::Attention;
    /// Returns the error handler.
    fn error_handler(&self) -> &Self::Error;
}

// =============================================================================
// Default Handler Implementations
// =============================================================================

/// A default RPC handler that rejects all requests with an error.
///
/// Use this when your server does not support RPC operations.
///
/// # Example
///
/// ```ignore
/// struct MyHandlers {
///     auth: MyAuthHandler,
///     sql_batch: MySqlBatchHandler,
///     rpc: RejectRpc,  // Rejects all RPC requests
///     // ...
/// }
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct RejectRpc;

impl RpcHandler for RejectRpc {
    fn on_rpc<'a, C>(
        &'a self,
        _client: &'a mut C,
        _message: crate::server::messages::RpcMessage,
    ) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async {
            Err(crate::Error::Protocol(
                "RPC requests are not supported by this server".into(),
            ))
        })
    }
}

/// A default bulk load handler that rejects all requests with an error.
///
/// Use this when your server does not support bulk load operations.
///
/// # Example
///
/// ```ignore
/// struct MyHandlers {
///     auth: MyAuthHandler,
///     sql_batch: MySqlBatchHandler,
///     bulk: RejectBulkLoad,  // Rejects all bulk load requests
///     // ...
/// }
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct RejectBulkLoad;

impl BulkLoadHandler for RejectBulkLoad {
    fn on_bulk_load<'a, C>(
        &'a self,
        _client: &'a mut C,
        _payload: bytes::BytesMut,
    ) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async {
            Err(crate::Error::Protocol(
                "Bulk load operations are not supported by this server".into(),
            ))
        })
    }
}

/// A default attention handler that does nothing.
///
/// This is a no-op implementation that simply returns `Ok(())`. The server
/// will still send the appropriate DONE token with the Attention flag.
///
/// Use this when you don't need custom attention handling logic.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpAttention;

impl AttentionHandler for NoOpAttention {
    fn on_attention<'a, C>(&'a self, _client: &'a mut C) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async { Ok(()) })
    }
}

/// A default error handler that does nothing.
///
/// Use this when you don't need to intercept or log errors.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpError;

impl ErrorHandler for NoOpError {
    fn on_error(&self, _client: &dyn TdsConnectionContext, _error: &mut crate::Error) {
        // No-op: let the error propagate as-is
    }
}
