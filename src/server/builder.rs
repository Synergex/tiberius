//! Type-safe builder for TDS server handler bundles.
//!
//! This module provides a builder pattern with compile-time enforcement of required
//! handlers. The server requires both an [`AuthHandler`] and a [`SqlBatchHandler`]
//! (or [`QueryHandler`] via adapter), and the builder prevents construction without them.
//!
//! # Overview
//!
//! The [`TdsServerBuilder`] uses type-state parameters to track which handlers have been
//! configured. The [`build()`](TdsServerBuilder::build) method is only available when
//! both required handlers have been set.
//!
//! # Example
//!
//! ```ignore
//! use tiberius::server::{TdsServerBuilder, QueryHandler, AuthHandler};
//!
//! // Build a server with required handlers
//! let server = TdsServerBuilder::new()
//!     .auth(my_auth_handler)
//!     .query(my_query_handler)  // Uses SimpleQueryAdapter internally
//!     .build();
//!
//! // Or use a raw SqlBatchHandler
//! let server = TdsServerBuilder::new()
//!     .auth(my_auth_handler)
//!     .sql_batch(my_sql_batch_handler)
//!     .build();
//!
//! // Optional handlers can be added:
//! let server = TdsServerBuilder::new()
//!     .auth(my_auth_handler)
//!     .query(my_query_handler)
//!     .rpc(my_rpc_handler)
//!     .attention(my_attention_handler)
//!     .error(my_error_handler)
//!     .build();
//! ```
//!
//! # Compile-Time Safety
//!
//! The builder will not compile if you try to call `build()` without setting
//! both required handlers:
//!
//! ```compile_fail
//! use tiberius::server::TdsServerBuilder;
//!
//! // This won't compile - missing auth and sql_batch/query handlers
//! let server = TdsServerBuilder::new().build();
//! ```
//!
//! # Default Handlers
//!
//! Optional handlers have sensible defaults:
//!
//! - `RpcHandler`: [`RejectRpc`](crate::server::RejectRpc) - rejects all RPC requests
//! - `BulkLoadHandler`: [`RejectBulkLoad`](crate::server::RejectBulkLoad) - rejects bulk loads
//! - `AttentionHandler`: [`NoOpAttention`](crate::server::NoOpAttention) - no-op
//! - `ErrorHandler`: [`NoOpError`](crate::server::NoOpError) - no-op

use crate::server::handler::{
    AttentionHandler, AuthHandler, BulkLoadHandler, ErrorHandler, NoOpAttention, NoOpError,
    RejectBulkLoad, RejectRpc, RpcHandler, SqlBatchHandler, TdsServerHandlers,
};
use crate::server::query::{QueryHandler, SimpleQueryAdapter};

// =============================================================================
// Marker Types for Type-State Pattern
// =============================================================================

/// Marker type indicating a required handler has not been set.
///
/// This is used in the type-state pattern to track builder configuration.
/// The `build()` method is not available while any required field has this type.
#[derive(Debug, Clone, Copy, Default)]
pub struct NotSet;

/// Marker type indicating a required handler has been set.
///
/// The inner type `T` is the actual handler type that was provided.
/// Use [`get()`](Set::get), [`get_mut()`](Set::get_mut), or [`into_inner()`](Set::into_inner)
/// to access the wrapped value.
#[derive(Debug, Clone)]
pub struct Set<T>(T);

impl<T> Set<T> {
    /// Get a reference to the inner value.
    pub fn get(&self) -> &T {
        &self.0
    }

    /// Get a mutable reference to the inner value.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.0
    }

    /// Consume the wrapper and return the inner value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

// =============================================================================
// TdsServerBuilder
// =============================================================================

/// Type-safe builder for constructing a TDS server handler bundle.
///
/// The builder uses type-state parameters to enforce that required handlers
/// (`AuthHandler` and `SqlBatchHandler`) are set before building. Optional
/// handlers have defaults that can be overridden.
///
/// # Type Parameters
///
/// - `A`: Auth handler state (`NotSet` or `Set<H>`)
/// - `S`: SqlBatch handler state (`NotSet` or `Set<H>`)
/// - `R`: RPC handler type (default: `RejectRpc`)
/// - `B`: Bulk load handler type (default: `RejectBulkLoad`)
/// - `AT`: Attention handler type (default: `NoOpAttention`)
/// - `E`: Error handler type (default: `NoOpError`)
///
/// # Example
///
/// ```ignore
/// use tiberius::server::TdsServerBuilder;
///
/// let server = TdsServerBuilder::new()
///     .auth(my_auth_handler)
///     .query(my_query_handler)
///     .build();
/// ```
pub struct TdsServerBuilder<A, S, R, B, AT, E> {
    auth: A,
    sql_batch: S,
    rpc: R,
    bulk_load: B,
    attention: AT,
    error: E,
}

impl Default for TdsServerBuilder<NotSet, NotSet, RejectRpc, RejectBulkLoad, NoOpAttention, NoOpError> {
    fn default() -> Self {
        Self::new()
    }
}

impl TdsServerBuilder<NotSet, NotSet, RejectRpc, RejectBulkLoad, NoOpAttention, NoOpError> {
    /// Create a new builder with default handlers for optional types.
    ///
    /// The auth and sql_batch handlers must be set before calling `build()`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let builder = TdsServerBuilder::new();
    /// ```
    pub fn new() -> Self {
        Self {
            auth: NotSet,
            sql_batch: NotSet,
            rpc: RejectRpc,
            bulk_load: RejectBulkLoad,
            attention: NoOpAttention,
            error: NoOpError,
        }
    }
}

impl<A, S, R, B, AT, E> TdsServerBuilder<A, S, R, B, AT, E> {
    /// Set the authentication handler (required).
    ///
    /// The handler must implement [`AuthHandler`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// let builder = TdsServerBuilder::new()
    ///     .auth(my_auth_handler);
    /// ```
    pub fn auth<H>(self, handler: H) -> TdsServerBuilder<Set<H>, S, R, B, AT, E>
    where
        H: AuthHandler,
    {
        TdsServerBuilder {
            auth: Set(handler),
            sql_batch: self.sql_batch,
            rpc: self.rpc,
            bulk_load: self.bulk_load,
            attention: self.attention,
            error: self.error,
        }
    }

    /// Set the SQL batch handler directly (required, alternative to `query()`).
    ///
    /// The handler must implement [`SqlBatchHandler`].
    ///
    /// Use this when you need full control over SQL batch processing.
    /// For simpler use cases, prefer [`query()`](Self::query) which uses
    /// [`SimpleQueryAdapter`] to provide a higher-level interface.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let builder = TdsServerBuilder::new()
    ///     .auth(my_auth_handler)
    ///     .sql_batch(my_sql_batch_handler);
    /// ```
    pub fn sql_batch<H>(self, handler: H) -> TdsServerBuilder<A, Set<H>, R, B, AT, E>
    where
        H: SqlBatchHandler,
    {
        TdsServerBuilder {
            auth: self.auth,
            sql_batch: Set(handler),
            rpc: self.rpc,
            bulk_load: self.bulk_load,
            attention: self.attention,
            error: self.error,
        }
    }

    /// Set a query handler using [`SimpleQueryAdapter`] (required, alternative to `sql_batch()`).
    ///
    /// The handler must implement [`QueryHandler`]. This method wraps the handler
    /// in a [`SimpleQueryAdapter`] which provides a simpler interface for query
    /// processing with automatic result set management.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let builder = TdsServerBuilder::new()
    ///     .auth(my_auth_handler)
    ///     .query(my_query_handler);
    /// ```
    pub fn query<H>(self, handler: H) -> TdsServerBuilder<A, Set<SimpleQueryAdapter<H>>, R, B, AT, E>
    where
        H: QueryHandler,
    {
        TdsServerBuilder {
            auth: self.auth,
            sql_batch: Set(SimpleQueryAdapter::new(handler)),
            rpc: self.rpc,
            bulk_load: self.bulk_load,
            attention: self.attention,
            error: self.error,
        }
    }

    /// Set the RPC handler (optional, defaults to [`RejectRpc`]).
    ///
    /// The handler must implement [`RpcHandler`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// let builder = TdsServerBuilder::new()
    ///     .auth(my_auth_handler)
    ///     .query(my_query_handler)
    ///     .rpc(my_rpc_handler);
    /// ```
    pub fn rpc<H>(self, handler: H) -> TdsServerBuilder<A, S, H, B, AT, E>
    where
        H: RpcHandler,
    {
        TdsServerBuilder {
            auth: self.auth,
            sql_batch: self.sql_batch,
            rpc: handler,
            bulk_load: self.bulk_load,
            attention: self.attention,
            error: self.error,
        }
    }

    /// Set the bulk load handler (optional, defaults to [`RejectBulkLoad`]).
    ///
    /// The handler must implement [`BulkLoadHandler`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// let builder = TdsServerBuilder::new()
    ///     .auth(my_auth_handler)
    ///     .query(my_query_handler)
    ///     .bulk_load(my_bulk_load_handler);
    /// ```
    pub fn bulk_load<H>(self, handler: H) -> TdsServerBuilder<A, S, R, H, AT, E>
    where
        H: BulkLoadHandler,
    {
        TdsServerBuilder {
            auth: self.auth,
            sql_batch: self.sql_batch,
            rpc: self.rpc,
            bulk_load: handler,
            attention: self.attention,
            error: self.error,
        }
    }

    /// Set the attention handler (optional, defaults to [`NoOpAttention`]).
    ///
    /// The handler must implement [`AttentionHandler`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// let builder = TdsServerBuilder::new()
    ///     .auth(my_auth_handler)
    ///     .query(my_query_handler)
    ///     .attention(my_attention_handler);
    /// ```
    pub fn attention<H>(self, handler: H) -> TdsServerBuilder<A, S, R, B, H, E>
    where
        H: AttentionHandler,
    {
        TdsServerBuilder {
            auth: self.auth,
            sql_batch: self.sql_batch,
            rpc: self.rpc,
            bulk_load: self.bulk_load,
            attention: handler,
            error: self.error,
        }
    }

    /// Set the error handler (optional, defaults to [`NoOpError`]).
    ///
    /// The handler must implement [`ErrorHandler`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// let builder = TdsServerBuilder::new()
    ///     .auth(my_auth_handler)
    ///     .query(my_query_handler)
    ///     .error(my_error_handler);
    /// ```
    pub fn error<H>(self, handler: H) -> TdsServerBuilder<A, S, R, B, AT, H>
    where
        H: ErrorHandler,
    {
        TdsServerBuilder {
            auth: self.auth,
            sql_batch: self.sql_batch,
            rpc: self.rpc,
            bulk_load: self.bulk_load,
            attention: self.attention,
            error: handler,
        }
    }
}

// Implementation of build() only available when both required handlers are Set
impl<AH, SH, R, B, AT, E> TdsServerBuilder<Set<AH>, Set<SH>, R, B, AT, E>
where
    AH: AuthHandler,
    SH: SqlBatchHandler,
    R: RpcHandler,
    B: BulkLoadHandler,
    AT: AttentionHandler,
    E: ErrorHandler,
{
    /// Build the server handler bundle.
    ///
    /// This method is only available when both the auth handler and
    /// sql_batch/query handler have been set.
    ///
    /// # Returns
    ///
    /// A [`BuiltTdsServer`] that implements [`TdsServerHandlers`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// let server = TdsServerBuilder::new()
    ///     .auth(my_auth_handler)
    ///     .query(my_query_handler)
    ///     .build();
    ///
    /// // Use the server with process_connection
    /// process_connection(stream, tls_acceptor, &server).await?;
    /// ```
    pub fn build(self) -> BuiltTdsServer<AH, SH, R, B, AT, E> {
        BuiltTdsServer {
            auth: self.auth.into_inner(),
            sql_batch: self.sql_batch.into_inner(),
            rpc: self.rpc,
            bulk_load: self.bulk_load,
            attention: self.attention,
            error: self.error,
        }
    }
}

impl<A, S, R, B, AT, E> std::fmt::Debug for TdsServerBuilder<A, S, R, B, AT, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TdsServerBuilder")
            .field("auth", &std::any::type_name::<A>())
            .field("sql_batch", &std::any::type_name::<S>())
            .field("rpc", &std::any::type_name::<R>())
            .field("bulk_load", &std::any::type_name::<B>())
            .field("attention", &std::any::type_name::<AT>())
            .field("error", &std::any::type_name::<E>())
            .finish()
    }
}

// =============================================================================
// BuiltTdsServer
// =============================================================================

/// A fully configured TDS server handler bundle.
///
/// This struct is produced by [`TdsServerBuilder::build()`] and implements
/// [`TdsServerHandlers`], making it ready for use with [`process_connection`](crate::server::process_connection).
///
/// # Type Parameters
///
/// - `A`: Auth handler type
/// - `S`: SqlBatch handler type
/// - `R`: RPC handler type
/// - `B`: Bulk load handler type
/// - `AT`: Attention handler type
/// - `E`: Error handler type
///
/// # Example
///
/// ```ignore
/// use tiberius::server::{TdsServerBuilder, process_connection};
///
/// let server = TdsServerBuilder::new()
///     .auth(my_auth_handler)
///     .query(my_query_handler)
///     .build();
///
/// // The BuiltTdsServer implements TdsServerHandlers
/// process_connection(stream, tls_acceptor, &server).await?;
/// ```
pub struct BuiltTdsServer<A, S, R, B, AT, E> {
    auth: A,
    sql_batch: S,
    rpc: R,
    bulk_load: B,
    attention: AT,
    error: E,
}

impl<A, S, R, B, AT, E> BuiltTdsServer<A, S, R, B, AT, E> {
    /// Get a reference to the auth handler.
    pub fn auth_handler(&self) -> &A {
        &self.auth
    }

    /// Get a mutable reference to the auth handler.
    pub fn auth_handler_mut(&mut self) -> &mut A {
        &mut self.auth
    }

    /// Get a reference to the SQL batch handler.
    pub fn sql_batch_handler(&self) -> &S {
        &self.sql_batch
    }

    /// Get a mutable reference to the SQL batch handler.
    pub fn sql_batch_handler_mut(&mut self) -> &mut S {
        &mut self.sql_batch
    }

    /// Get a reference to the RPC handler.
    pub fn rpc_handler(&self) -> &R {
        &self.rpc
    }

    /// Get a mutable reference to the RPC handler.
    pub fn rpc_handler_mut(&mut self) -> &mut R {
        &mut self.rpc
    }

    /// Get a reference to the bulk load handler.
    pub fn bulk_load_handler(&self) -> &B {
        &self.bulk_load
    }

    /// Get a mutable reference to the bulk load handler.
    pub fn bulk_load_handler_mut(&mut self) -> &mut B {
        &mut self.bulk_load
    }

    /// Get a reference to the attention handler.
    pub fn attention_handler(&self) -> &AT {
        &self.attention
    }

    /// Get a mutable reference to the attention handler.
    pub fn attention_handler_mut(&mut self) -> &mut AT {
        &mut self.attention
    }

    /// Get a reference to the error handler.
    pub fn error_handler(&self) -> &E {
        &self.error
    }

    /// Get a mutable reference to the error handler.
    pub fn error_handler_mut(&mut self) -> &mut E {
        &mut self.error
    }
}

impl<A, S, R, B, AT, E> TdsServerHandlers for BuiltTdsServer<A, S, R, B, AT, E>
where
    A: AuthHandler,
    S: SqlBatchHandler,
    R: RpcHandler,
    B: BulkLoadHandler,
    AT: AttentionHandler,
    E: ErrorHandler,
{
    type Auth = A;
    type SqlBatch = S;
    type Rpc = R;
    type Bulk = B;
    type Attention = AT;
    type Error = E;

    fn auth_handler(&self) -> &Self::Auth {
        &self.auth
    }

    fn sql_batch_handler(&self) -> &Self::SqlBatch {
        &self.sql_batch
    }

    fn rpc_handler(&self) -> &Self::Rpc {
        &self.rpc
    }

    fn bulk_load_handler(&self) -> &Self::Bulk {
        &self.bulk_load
    }

    fn attention_handler(&self) -> &Self::Attention {
        &self.attention
    }

    fn error_handler(&self) -> &Self::Error {
        &self.error
    }
}

impl<A, S, R, B, AT, E> std::fmt::Debug for BuiltTdsServer<A, S, R, B, AT, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuiltTdsServer")
            .field("auth", &std::any::type_name::<A>())
            .field("sql_batch", &std::any::type_name::<S>())
            .field("rpc", &std::any::type_name::<R>())
            .field("bulk_load", &std::any::type_name::<B>())
            .field("attention", &std::any::type_name::<AT>())
            .field("error", &std::any::type_name::<E>())
            .finish()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::handler::{BoxFuture, TdsClient};
    use crate::server::messages::SqlBatchMessage;
    use crate::tds::codec::{LoginMessage, PreloginMessage};
    use crate::Result;

    // Dummy auth handler for testing
    struct DummyAuthHandler;

    impl AuthHandler for DummyAuthHandler {
        fn on_prelogin<'a, C>(
            &'a self,
            _client: &'a mut C,
            _message: PreloginMessage,
        ) -> BoxFuture<'a, Result<()>>
        where
            C: TdsClient + 'a,
        {
            Box::pin(async { Ok(()) })
        }

        fn on_login<'a, C>(
            &'a self,
            _client: &'a mut C,
            _message: LoginMessage<'static>,
        ) -> BoxFuture<'a, Result<()>>
        where
            C: TdsClient + 'a,
        {
            Box::pin(async { Ok(()) })
        }
    }

    // Dummy SQL batch handler for testing
    struct DummySqlBatchHandler;

    impl SqlBatchHandler for DummySqlBatchHandler {
        fn on_sql_batch<'a, C>(
            &'a self,
            _client: &'a mut C,
            _message: SqlBatchMessage,
        ) -> BoxFuture<'a, Result<()>>
        where
            C: TdsClient + 'a,
        {
            Box::pin(async { Ok(()) })
        }
    }

    // Dummy query handler for testing
    struct DummyQueryHandler;

    impl QueryHandler for DummyQueryHandler {
        fn query<'a, C: TdsClient + 'a>(
            &'a self,
            _sql: &'a str,
            _output: &'a mut crate::server::query::QueryOutput<'a, C>,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    // Dummy RPC handler for testing
    struct DummyRpcHandler;

    impl RpcHandler for DummyRpcHandler {
        fn on_rpc<'a, C>(
            &'a self,
            _client: &'a mut C,
            _message: crate::server::messages::RpcMessage,
        ) -> BoxFuture<'a, Result<()>>
        where
            C: TdsClient + 'a,
        {
            Box::pin(async { Ok(()) })
        }
    }

    // Dummy bulk load handler for testing
    struct DummyBulkLoadHandler;

    impl BulkLoadHandler for DummyBulkLoadHandler {
        fn on_bulk_load<'a, C>(
            &'a self,
            _client: &'a mut C,
            _payload: bytes::BytesMut,
        ) -> BoxFuture<'a, Result<()>>
        where
            C: TdsClient + 'a,
        {
            Box::pin(async { Ok(()) })
        }
    }

    // Dummy attention handler for testing
    struct DummyAttentionHandler;

    impl AttentionHandler for DummyAttentionHandler {
        fn on_attention<'a, C>(&'a self, _client: &'a mut C) -> BoxFuture<'a, Result<()>>
        where
            C: TdsClient + 'a,
        {
            Box::pin(async { Ok(()) })
        }
    }

    // Dummy error handler for testing
    struct DummyErrorHandler;

    impl ErrorHandler for DummyErrorHandler {
        fn on_error(
            &self,
            _client: &dyn crate::server::handler::TdsConnectionContext,
            _error: &mut crate::Error,
        ) {
            // No-op
        }
    }

    #[test]
    fn test_builder_new() {
        let builder = TdsServerBuilder::new();
        let debug_str = format!("{:?}", builder);
        assert!(debug_str.contains("TdsServerBuilder"));
        assert!(debug_str.contains("NotSet"));
    }

    #[test]
    fn test_builder_with_auth() {
        let builder = TdsServerBuilder::new().auth(DummyAuthHandler);
        let debug_str = format!("{:?}", builder);
        assert!(debug_str.contains("Set<"));
        assert!(debug_str.contains("DummyAuthHandler"));
    }

    #[test]
    fn test_builder_with_sql_batch() {
        let builder = TdsServerBuilder::new()
            .auth(DummyAuthHandler)
            .sql_batch(DummySqlBatchHandler);
        let debug_str = format!("{:?}", builder);
        assert!(debug_str.contains("DummySqlBatchHandler"));
    }

    #[test]
    fn test_builder_with_query() {
        let builder = TdsServerBuilder::new()
            .auth(DummyAuthHandler)
            .query(DummyQueryHandler);
        let debug_str = format!("{:?}", builder);
        assert!(debug_str.contains("SimpleQueryAdapter"));
    }

    #[test]
    fn test_builder_build_with_sql_batch() {
        let server = TdsServerBuilder::new()
            .auth(DummyAuthHandler)
            .sql_batch(DummySqlBatchHandler)
            .build();

        // Verify that the server implements TdsServerHandlers
        let _ = TdsServerHandlers::auth_handler(&server);
        let _ = TdsServerHandlers::sql_batch_handler(&server);
        let _ = TdsServerHandlers::rpc_handler(&server);
        let _ = TdsServerHandlers::bulk_load_handler(&server);
        let _ = TdsServerHandlers::attention_handler(&server);
        let _ = TdsServerHandlers::error_handler(&server);
    }

    #[test]
    fn test_builder_build_with_query() {
        let server = TdsServerBuilder::new()
            .auth(DummyAuthHandler)
            .query(DummyQueryHandler)
            .build();

        let debug_str = format!("{:?}", server);
        assert!(debug_str.contains("BuiltTdsServer"));
    }

    #[test]
    fn test_builder_with_all_handlers() {
        let server = TdsServerBuilder::new()
            .auth(DummyAuthHandler)
            .sql_batch(DummySqlBatchHandler)
            .rpc(DummyRpcHandler)
            .bulk_load(DummyBulkLoadHandler)
            .attention(DummyAttentionHandler)
            .error(DummyErrorHandler)
            .build();

        // Verify we can access all handlers
        let _ = server.auth_handler();
        let _ = server.sql_batch_handler();
        let _ = server.rpc_handler();
        let _ = server.bulk_load_handler();
        let _ = server.attention_handler();
        let _ = server.error_handler();
    }

    #[test]
    fn test_built_server_mutable_accessors() {
        let mut server = TdsServerBuilder::new()
            .auth(DummyAuthHandler)
            .sql_batch(DummySqlBatchHandler)
            .build();

        // Verify mutable accessors work
        let _ = server.auth_handler_mut();
        let _ = server.sql_batch_handler_mut();
        let _ = server.rpc_handler_mut();
        let _ = server.bulk_load_handler_mut();
        let _ = server.attention_handler_mut();
        let _ = server.error_handler_mut();
    }

    #[test]
    fn test_set_marker_accessors() {
        let set = Set(42);
        assert_eq!(*set.get(), 42);

        let mut set = Set(42);
        *set.get_mut() = 100;
        assert_eq!(*set.get(), 100);

        let set = Set(42);
        assert_eq!(set.into_inner(), 42);
    }

    #[test]
    fn test_builder_default() {
        let builder = TdsServerBuilder::default();
        let debug_str = format!("{:?}", builder);
        assert!(debug_str.contains("NotSet"));
    }

    #[test]
    fn test_builder_order_independence() {
        // Test that handlers can be set in any order
        let server1 = TdsServerBuilder::new()
            .auth(DummyAuthHandler)
            .sql_batch(DummySqlBatchHandler)
            .rpc(DummyRpcHandler)
            .build();

        let server2 = TdsServerBuilder::new()
            .rpc(DummyRpcHandler)
            .auth(DummyAuthHandler)
            .sql_batch(DummySqlBatchHandler)
            .build();

        // Both should compile and produce valid servers
        let _ = TdsServerHandlers::auth_handler(&server1);
        let _ = TdsServerHandlers::auth_handler(&server2);
    }

    // This test documents that build() is not available without required handlers.
    // It would fail to compile if uncommented, which is the desired behavior.
    //
    // #[test]
    // fn test_compile_fail_without_auth() {
    //     let _ = TdsServerBuilder::new()
    //         .sql_batch(DummySqlBatchHandler)
    //         .build(); // Should fail: missing auth handler
    // }
    //
    // #[test]
    // fn test_compile_fail_without_sql_batch() {
    //     let _ = TdsServerBuilder::new()
    //         .auth(DummyAuthHandler)
    //         .build(); // Should fail: missing sql_batch handler
    // }
}
