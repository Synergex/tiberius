//! Runtime-agnostic TDS server scaffolding.
//!
//! This module provides the infrastructure for building custom TDS (Tabular Data Stream)
//! servers. TDS is the wire protocol used by Microsoft SQL Server and Azure SQL.
//!
//! # Architecture
//!
//! The server is built around handler traits that you implement to process protocol messages:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                         TDS Server Architecture                     │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                     │
//! │  Client ──► NetStream ──► TdsConnection ──► Handlers ──► Response  │
//! │                               │                                     │
//! │                               ▼                                     │
//! │                          TdsCodec                                   │
//! │                         (encode/decode)                             │
//! │                                                                     │
//! │  Handlers:                                                          │
//! │  ┌────────────────┬────────────────┬────────────────┐              │
//! │  │ AuthHandler    │ SqlBatchHandler│ RpcHandler     │              │
//! │  │ (login flow)   │ (simple query) │ (stored procs) │              │
//! │  └────────────────┴────────────────┴────────────────┘              │
//! │  ┌────────────────┬────────────────┬────────────────┐              │
//! │  │ BulkLoadHandler│ AttentionHandler│ ErrorHandler  │              │
//! │  │ (bulk import)  │ (cancellation) │ (error logging)│              │
//! │  └────────────────┴────────────────┴────────────────┘              │
//! │                                                                     │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Quick Start
//!
//! ```ignore
//! use tiberius::server::{
//!     process_connection, AuthBuilder, TdsServerHandlers,
//!     SqlBatchHandler, TdsClient, BoxFuture,
//!     RejectRpc, RejectBulkLoad, NoOpAttention, NoOpError,
//! };
//!
//! // 1. Implement SqlBatchHandler for your query logic
//! struct MySqlHandler;
//!
//! impl SqlBatchHandler for MySqlHandler {
//!     fn on_sql_batch<'a, C>(&'a self, client: &'a mut C, msg: SqlBatchMessage) -> BoxFuture<'a, Result<()>>
//!     where C: TdsClient + 'a
//!     {
//!         Box::pin(async move {
//!             // Execute query and send results
//!             Ok(())
//!         })
//!     }
//! }
//!
//! // 2. Bundle handlers into TdsServerHandlers
//! struct MyServer {
//!     auth: TdsAuthHandler,
//!     sql: MySqlHandler,
//! }
//!
//! impl TdsServerHandlers for MyServer { /* ... */ }
//!
//! // 3. Process connections
//! let handlers = MyServer { /* ... */ };
//! process_connection(stream, tls_acceptor, &handlers).await?;
//! ```
//!
//! # Key Types
//!
//! | Type | Purpose |
//! |------|---------|
//! | [`TdsConnection`] | Manages a single client connection |
//! | [`TdsClient`] | Trait bound for handler client parameter |
//! | [`TdsServerHandlers`] | Aggregates all handlers for a server |
//! | [`ResultSetWriter`] | Helper for sending result sets |
//! | [`TdsAuthHandler`] | Full-featured authentication handler |
//! | [`AuthBuilder`] | Builder for configuring authentication |
//!
//! # Modules
//!
//! - [`handler`]: Handler traits for processing protocol messages
//! - [`auth`]: Authentication infrastructure
//! - [`messages`]: Protocol message types
//! - [`state`]: Connection state machine
//! - [`backend`]: Network abstraction traits
//! - [`tls`]: TLS/SSL support
//!
//! # Features
//!
//! - `server-smol`: Enables smol-based networking (async-io)
//! - `server-rustls`: Enables rustls-based TLS
//! - `integrated-auth-gssapi`: Enables GSSAPI/Kerberos authentication (Unix only)

pub mod backend;
pub mod auth;
pub mod builder;
pub mod codec;
pub mod connection;
pub mod handler;
mod handle_macro;
pub mod messages;
pub mod prepared;
pub mod query;
pub mod response;
pub mod router;
pub mod server;
pub mod sp_cursor;
pub mod sp_executesql;
pub mod sp_prepare;
pub mod sp_prepexec;
pub mod state;
pub mod tls;

pub use backend::{NetBackend, NetListener, NetStream, NetStreamExt};
pub use builder::{BuiltTdsServer, NotSet, Set, TdsServerBuilder};
pub use auth::{
    AuthBuilder, AuthError, AuthResult, AuthSuccess, DefaultEnvChangeProvider, EnvChangeProvider,
    FedAuthValidator, LoginInfo, SqlAuthSource, SspiAcceptor, SspiSession, SspiStart, SspiStep,
    TdsAuthHandler,
    METADATA_APPLICATION, METADATA_DATABASE, METADATA_SERVER, METADATA_USER,
};
pub use codec::{decode_rpc_params, DecodedRpcParam, RpcParamSet, TdsCodec};
pub use connection::TdsConnection;
pub use handler::{
    AttentionHandler, AuthHandler, BoxFuture, BulkLoadHandler, ConnectionMetadata, ErrorHandler,
    NoOpAttention, NoOpError, RejectBulkLoad, RejectRpc, RpcHandler, SqlBatchHandler, TdsClient,
    TdsConnectionContext, TdsServerHandlers,
};
pub use messages::{
    AllHeaders, BackendToken, RequestFlags, RpcMessage, SqlBatchMessage, TdsBackendMessage,
    TdsFrontendMessage, TransactionDescriptor,
};
pub use prepared::{PreparedHandle, PreparedStatement, ProcedureCache, ProcedureCacheConfig};
pub use response::{
    finish_proc, finish_proc_more, infer_type_info, send_output_param, send_output_params,
    send_return_status, OutputParameter, ResultSetWriter,
};
pub use server::process_connection;
pub use sp_executesql::{
    parse_executesql, ExecuteSqlParam, ParsedExecuteSql, SpExecuteSqlHandler,
    SpExecuteSqlRpcHandler,
};
pub use sp_prepare::{
    parse_execute, parse_prepare, parse_unprepare, ParsedExecute, ParsedPrepare, ParsedUnprepare,
    PreparedStatementRpcHandler, SpExecuteHandler, SpExecuteRpcHandler, SpPrepareHandler,
    SpPrepareRpcHandler, SpUnprepareHandler, SpUnprepareRpcHandler,
};
pub use sp_prepexec::{
    parse_prepexec, ParsedPrepExec, SpPrepExecHandler, SpPrepExecRpcHandler,
};
pub use sp_cursor::{
    parse_cursor_close, parse_cursor_fetch, parse_cursor_open, CursorCache, CursorCacheConfig,
    CursorEntry, CursorHandle, ParsedCursorClose, ParsedCursorFetch, ParsedCursorOpen,
    SpCursorCloseHandler, SpCursorCloseRpcHandler, SpCursorFetchHandler, SpCursorFetchRpcHandler,
    SpCursorOpenHandler, SpCursorOpenRpcHandler,
};
pub use query::{QueryColumn, QueryColumnType, QueryHandler, QueryOutput, SimpleQueryAdapter};
pub use router::{RejectUnknownProc, SystemProcRouter, SystemProcRouterBuilder};
pub use state::TdsConnectionState;
pub use tls::{NoTls, TlsAccept, TlsStream};
#[cfg(feature = "server-rustls")]
pub use tls::RustlsAcceptor;
#[cfg(all(unix, feature = "integrated-auth-gssapi"))]
pub use auth::gssapi::GssapiAcceptor;
