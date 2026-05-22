//! RPC routing infrastructure for system stored procedures.
//!
//! This module provides a flexible router for handling system stored procedure RPC requests.
//! It allows you to configure handlers for specific procedures (`sp_executesql`, `sp_prepare`,
//! `sp_execute`, `sp_unprepare`, `sp_prepexec`, `sp_cursoropen`, `sp_cursorfetch`,
//! `sp_cursorclose`) while providing a fallback for unknown procedures.
//!
//! # Overview
//!
//! The [`SystemProcRouter`] dispatches incoming RPC requests to the appropriate handler based
//! on the procedure ID. This provides a clean separation of concerns and makes it easy to
//! compose handlers for different system procedures.
//!
//! # Example
//!
//! ```ignore
//! use tiberius::server::SystemProcRouterBuilder;
//!
//! let router = SystemProcRouterBuilder::new()
//!     .with_executesql(my_executesql_handler)
//!     .with_prepare(my_prepare_handler)
//!     .with_execute(my_execute_handler)
//!     .with_unprepare(my_unprepare_handler)
//!     .with_prepexec(my_prepexec_handler)
//!     .with_cursor_open(my_cursor_open_handler)
//!     .with_cursor_fetch(my_cursor_fetch_handler)
//!     .with_cursor_close(my_cursor_close_handler)
//!     .build();
//! ```

use crate::server::handler::{BoxFuture, RpcHandler, TdsClient};
use crate::server::messages::RpcMessage;
use crate::server::sp_cursor::{
    parse_cursor_close, parse_cursor_fetch, parse_cursor_open, SpCursorCloseHandler,
    SpCursorFetchHandler, SpCursorOpenHandler,
};
use crate::server::sp_executesql::{parse_executesql, SpExecuteSqlHandler};
use crate::server::sp_prepare::{
    parse_execute, parse_prepare, parse_unprepare, SpExecuteHandler, SpPrepareHandler,
    SpUnprepareHandler,
};
use crate::server::sp_prepexec::{parse_prepexec, SpPrepExecHandler};
use crate::tds::codec::RpcProcId;
use crate::{Error, Result};

// =============================================================================
// RejectUnknownProc - Default fallback handler
// =============================================================================

/// Default fallback handler that rejects unknown procedures with an error.
#[derive(Debug, Clone, Copy, Default)]
pub struct RejectUnknownProc;

impl RpcHandler for RejectUnknownProc {
    fn on_rpc<'a, C>(
        &'a self,
        _client: &'a mut C,
        message: RpcMessage,
    ) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async move {
            let proc_name = if let Some(id) = message.proc_id {
                format!("proc_id {:?}", id)
            } else if let Some(name) = message.proc_name.as_deref() {
                format!("'{}'", name)
            } else {
                "<unknown>".to_string()
            };

            Err(Error::Protocol(
                format!("Unsupported RPC procedure: {}", proc_name).into(),
            ))
        })
    }
}

// =============================================================================
// SystemProcRouter
// =============================================================================

/// Router that dispatches RPC requests to specialized handlers by proc id.
///
/// Every handler slot is optional; unset slots delegate to the fallback
/// handler. The default fallback is [`RejectUnknownProc`].
pub struct SystemProcRouter<ES, P, E, U, PE, CO, CF, CC, F> {
    executesql: Option<ES>,
    prepare: Option<P>,
    execute: Option<E>,
    unprepare: Option<U>,
    prepexec: Option<PE>,
    cursor_open: Option<CO>,
    cursor_fetch: Option<CF>,
    cursor_close: Option<CC>,
    fallback: F,
}

impl<ES, P, E, U, PE, CO, CF, CC, F> SystemProcRouter<ES, P, E, U, PE, CO, CF, CC, F> {
    /// Direct constructor. Prefer [`SystemProcRouterBuilder`] in application
    /// code.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        executesql: Option<ES>,
        prepare: Option<P>,
        execute: Option<E>,
        unprepare: Option<U>,
        prepexec: Option<PE>,
        cursor_open: Option<CO>,
        cursor_fetch: Option<CF>,
        cursor_close: Option<CC>,
        fallback: F,
    ) -> Self {
        Self {
            executesql,
            prepare,
            execute,
            unprepare,
            prepexec,
            cursor_open,
            cursor_fetch,
            cursor_close,
            fallback,
        }
    }

    /// Borrow the `sp_executesql` handler, if configured.
    pub fn executesql_handler(&self) -> Option<&ES> {
        self.executesql.as_ref()
    }
    /// Borrow the `sp_prepare` handler, if configured.
    pub fn prepare_handler(&self) -> Option<&P> {
        self.prepare.as_ref()
    }
    /// Borrow the `sp_execute` handler, if configured.
    pub fn execute_handler(&self) -> Option<&E> {
        self.execute.as_ref()
    }
    /// Borrow the `sp_unprepare` handler, if configured.
    pub fn unprepare_handler(&self) -> Option<&U> {
        self.unprepare.as_ref()
    }
    /// Borrow the `sp_prepexec` handler, if configured.
    pub fn prepexec_handler(&self) -> Option<&PE> {
        self.prepexec.as_ref()
    }
    /// Borrow the `sp_cursoropen` handler, if configured.
    pub fn cursor_open_handler(&self) -> Option<&CO> {
        self.cursor_open.as_ref()
    }
    /// Borrow the `sp_cursorfetch` handler, if configured.
    pub fn cursor_fetch_handler(&self) -> Option<&CF> {
        self.cursor_fetch.as_ref()
    }
    /// Borrow the `sp_cursorclose` handler, if configured.
    pub fn cursor_close_handler(&self) -> Option<&CC> {
        self.cursor_close.as_ref()
    }
    /// Borrow the fallback handler.
    pub fn fallback_handler(&self) -> &F {
        &self.fallback
    }

    /// Is an `sp_executesql` handler configured?
    pub fn has_executesql(&self) -> bool {
        self.executesql.is_some()
    }
    /// Is an `sp_prepare` handler configured?
    pub fn has_prepare(&self) -> bool {
        self.prepare.is_some()
    }
    /// Is an `sp_execute` handler configured?
    pub fn has_execute(&self) -> bool {
        self.execute.is_some()
    }
    /// Is an `sp_unprepare` handler configured?
    pub fn has_unprepare(&self) -> bool {
        self.unprepare.is_some()
    }
    /// Is an `sp_prepexec` handler configured?
    pub fn has_prepexec(&self) -> bool {
        self.prepexec.is_some()
    }
    /// Is an `sp_cursoropen` handler configured?
    pub fn has_cursor_open(&self) -> bool {
        self.cursor_open.is_some()
    }
    /// Is an `sp_cursorfetch` handler configured?
    pub fn has_cursor_fetch(&self) -> bool {
        self.cursor_fetch.is_some()
    }
    /// Is an `sp_cursorclose` handler configured?
    pub fn has_cursor_close(&self) -> bool {
        self.cursor_close.is_some()
    }
}

impl<ES, P, E, U, PE, CO, CF, CC, F> std::fmt::Debug
    for SystemProcRouter<ES, P, E, U, PE, CO, CF, CC, F>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemProcRouter")
            .field("has_executesql", &self.executesql.is_some())
            .field("has_prepare", &self.prepare.is_some())
            .field("has_execute", &self.execute.is_some())
            .field("has_unprepare", &self.unprepare.is_some())
            .field("has_prepexec", &self.prepexec.is_some())
            .field("has_cursor_open", &self.cursor_open.is_some())
            .field("has_cursor_fetch", &self.cursor_fetch.is_some())
            .field("has_cursor_close", &self.cursor_close.is_some())
            .field("fallback", &std::any::type_name::<F>())
            .finish()
    }
}

impl<ES, P, E, U, PE, CO, CF, CC, F> RpcHandler
    for SystemProcRouter<ES, P, E, U, PE, CO, CF, CC, F>
where
    ES: SpExecuteSqlHandler,
    P: SpPrepareHandler,
    E: SpExecuteHandler,
    U: SpUnprepareHandler,
    PE: SpPrepExecHandler,
    CO: SpCursorOpenHandler,
    CF: SpCursorFetchHandler,
    CC: SpCursorCloseHandler,
    F: RpcHandler,
{
    fn on_rpc<'a, C>(
        &'a self,
        client: &'a mut C,
        message: RpcMessage,
    ) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async move {
            match message.proc_id {
                Some(RpcProcId::ExecuteSQL) => {
                    if let Some(h) = &self.executesql {
                        let request = parse_executesql(message.into_param_set().await?)?;
                        h.execute(client, request).await
                    } else {
                        self.fallback.on_rpc(client, message).await
                    }
                }
                Some(RpcProcId::Prepare) => {
                    if let Some(h) = &self.prepare {
                        let request = parse_prepare(message.into_param_set().await?)?;
                        let _ = h.prepare(client, request).await?;
                        Ok(())
                    } else {
                        self.fallback.on_rpc(client, message).await
                    }
                }
                Some(RpcProcId::Execute) => {
                    if let Some(h) = &self.execute {
                        let request = parse_execute(message.into_param_set().await?)?;
                        h.execute(client, request).await
                    } else {
                        self.fallback.on_rpc(client, message).await
                    }
                }
                Some(RpcProcId::Unprepare) => {
                    if let Some(h) = &self.unprepare {
                        let request = parse_unprepare(message.into_param_set().await?)?;
                        h.unprepare(client, request).await
                    } else {
                        self.fallback.on_rpc(client, message).await
                    }
                }
                Some(RpcProcId::PrepExec) => {
                    if let Some(h) = &self.prepexec {
                        let request = parse_prepexec(message.into_param_set().await?)?;
                        let _ = h.prep_exec(client, request).await?;
                        Ok(())
                    } else {
                        self.fallback.on_rpc(client, message).await
                    }
                }
                Some(RpcProcId::CursorOpen) => {
                    if let Some(h) = &self.cursor_open {
                        let request = parse_cursor_open(message.into_param_set().await?)?;
                        let _ = h.cursor_open(client, request).await?;
                        Ok(())
                    } else {
                        self.fallback.on_rpc(client, message).await
                    }
                }
                Some(RpcProcId::CursorFetch) => {
                    if let Some(h) = &self.cursor_fetch {
                        let request = parse_cursor_fetch(message.into_param_set().await?)?;
                        h.cursor_fetch(client, request).await
                    } else {
                        self.fallback.on_rpc(client, message).await
                    }
                }
                Some(RpcProcId::CursorClose) => {
                    if let Some(h) = &self.cursor_close {
                        let request = parse_cursor_close(message.into_param_set().await?)?;
                        h.cursor_close(client, request).await
                    } else {
                        self.fallback.on_rpc(client, message).await
                    }
                }
                // Named procedures fall through to the fallback.
                _ => self.fallback.on_rpc(client, message).await,
            }
        })
    }
}

// =============================================================================
// SystemProcRouterBuilder
// =============================================================================

/// Builder for [`SystemProcRouter`].
pub struct SystemProcRouterBuilder<ES, P, E, U, PE, CO, CF, CC, F> {
    executesql: Option<ES>,
    prepare: Option<P>,
    execute: Option<E>,
    unprepare: Option<U>,
    prepexec: Option<PE>,
    cursor_open: Option<CO>,
    cursor_fetch: Option<CF>,
    cursor_close: Option<CC>,
    fallback: F,
}

impl Default
    for SystemProcRouterBuilder<(), (), (), (), (), (), (), (), RejectUnknownProc>
{
    fn default() -> Self {
        Self::new()
    }
}

impl SystemProcRouterBuilder<(), (), (), (), (), (), (), (), RejectUnknownProc> {
    /// Start building a router with no handlers and [`RejectUnknownProc`] as
    /// the fallback.
    pub fn new() -> Self {
        Self {
            executesql: None,
            prepare: None,
            execute: None,
            unprepare: None,
            prepexec: None,
            cursor_open: None,
            cursor_fetch: None,
            cursor_close: None,
            fallback: RejectUnknownProc,
        }
    }
}

impl<ES, P, E, U, PE, CO, CF, CC, F> SystemProcRouterBuilder<ES, P, E, U, PE, CO, CF, CC, F> {
    /// Configure the `sp_executesql` handler.
    pub fn with_executesql<H>(
        self,
        handler: H,
    ) -> SystemProcRouterBuilder<H, P, E, U, PE, CO, CF, CC, F>
    where
        H: SpExecuteSqlHandler,
    {
        SystemProcRouterBuilder {
            executesql: Some(handler),
            prepare: self.prepare,
            execute: self.execute,
            unprepare: self.unprepare,
            prepexec: self.prepexec,
            cursor_open: self.cursor_open,
            cursor_fetch: self.cursor_fetch,
            cursor_close: self.cursor_close,
            fallback: self.fallback,
        }
    }

    /// Configure the `sp_prepare` handler.
    pub fn with_prepare<H>(
        self,
        handler: H,
    ) -> SystemProcRouterBuilder<ES, H, E, U, PE, CO, CF, CC, F>
    where
        H: SpPrepareHandler,
    {
        SystemProcRouterBuilder {
            executesql: self.executesql,
            prepare: Some(handler),
            execute: self.execute,
            unprepare: self.unprepare,
            prepexec: self.prepexec,
            cursor_open: self.cursor_open,
            cursor_fetch: self.cursor_fetch,
            cursor_close: self.cursor_close,
            fallback: self.fallback,
        }
    }

    /// Configure the `sp_execute` handler.
    pub fn with_execute<H>(
        self,
        handler: H,
    ) -> SystemProcRouterBuilder<ES, P, H, U, PE, CO, CF, CC, F>
    where
        H: SpExecuteHandler,
    {
        SystemProcRouterBuilder {
            executesql: self.executesql,
            prepare: self.prepare,
            execute: Some(handler),
            unprepare: self.unprepare,
            prepexec: self.prepexec,
            cursor_open: self.cursor_open,
            cursor_fetch: self.cursor_fetch,
            cursor_close: self.cursor_close,
            fallback: self.fallback,
        }
    }

    /// Configure the `sp_unprepare` handler.
    pub fn with_unprepare<H>(
        self,
        handler: H,
    ) -> SystemProcRouterBuilder<ES, P, E, H, PE, CO, CF, CC, F>
    where
        H: SpUnprepareHandler,
    {
        SystemProcRouterBuilder {
            executesql: self.executesql,
            prepare: self.prepare,
            execute: self.execute,
            unprepare: Some(handler),
            prepexec: self.prepexec,
            cursor_open: self.cursor_open,
            cursor_fetch: self.cursor_fetch,
            cursor_close: self.cursor_close,
            fallback: self.fallback,
        }
    }

    /// Configure the `sp_prepexec` handler.
    pub fn with_prepexec<H>(
        self,
        handler: H,
    ) -> SystemProcRouterBuilder<ES, P, E, U, H, CO, CF, CC, F>
    where
        H: SpPrepExecHandler,
    {
        SystemProcRouterBuilder {
            executesql: self.executesql,
            prepare: self.prepare,
            execute: self.execute,
            unprepare: self.unprepare,
            prepexec: Some(handler),
            cursor_open: self.cursor_open,
            cursor_fetch: self.cursor_fetch,
            cursor_close: self.cursor_close,
            fallback: self.fallback,
        }
    }

    /// Configure the `sp_cursoropen` handler.
    pub fn with_cursor_open<H>(
        self,
        handler: H,
    ) -> SystemProcRouterBuilder<ES, P, E, U, PE, H, CF, CC, F>
    where
        H: SpCursorOpenHandler,
    {
        SystemProcRouterBuilder {
            executesql: self.executesql,
            prepare: self.prepare,
            execute: self.execute,
            unprepare: self.unprepare,
            prepexec: self.prepexec,
            cursor_open: Some(handler),
            cursor_fetch: self.cursor_fetch,
            cursor_close: self.cursor_close,
            fallback: self.fallback,
        }
    }

    /// Configure the `sp_cursorfetch` handler.
    pub fn with_cursor_fetch<H>(
        self,
        handler: H,
    ) -> SystemProcRouterBuilder<ES, P, E, U, PE, CO, H, CC, F>
    where
        H: SpCursorFetchHandler,
    {
        SystemProcRouterBuilder {
            executesql: self.executesql,
            prepare: self.prepare,
            execute: self.execute,
            unprepare: self.unprepare,
            prepexec: self.prepexec,
            cursor_open: self.cursor_open,
            cursor_fetch: Some(handler),
            cursor_close: self.cursor_close,
            fallback: self.fallback,
        }
    }

    /// Configure the `sp_cursorclose` handler.
    pub fn with_cursor_close<H>(
        self,
        handler: H,
    ) -> SystemProcRouterBuilder<ES, P, E, U, PE, CO, CF, H, F>
    where
        H: SpCursorCloseHandler,
    {
        SystemProcRouterBuilder {
            executesql: self.executesql,
            prepare: self.prepare,
            execute: self.execute,
            unprepare: self.unprepare,
            prepexec: self.prepexec,
            cursor_open: self.cursor_open,
            cursor_fetch: self.cursor_fetch,
            cursor_close: Some(handler),
            fallback: self.fallback,
        }
    }

    /// Configure a custom fallback handler. Called for any proc id not
    /// matched by a configured handler slot.
    pub fn with_fallback<H>(
        self,
        handler: H,
    ) -> SystemProcRouterBuilder<ES, P, E, U, PE, CO, CF, CC, H>
    where
        H: RpcHandler,
    {
        SystemProcRouterBuilder {
            executesql: self.executesql,
            prepare: self.prepare,
            execute: self.execute,
            unprepare: self.unprepare,
            prepexec: self.prepexec,
            cursor_open: self.cursor_open,
            cursor_fetch: self.cursor_fetch,
            cursor_close: self.cursor_close,
            fallback: handler,
        }
    }

    /// Finalize the router.
    pub fn build(self) -> SystemProcRouter<ES, P, E, U, PE, CO, CF, CC, F> {
        SystemProcRouter::new(
            self.executesql,
            self.prepare,
            self.execute,
            self.unprepare,
            self.prepexec,
            self.cursor_open,
            self.cursor_fetch,
            self.cursor_close,
            self.fallback,
        )
    }
}

impl<ES, P, E, U, PE, CO, CF, CC, F> std::fmt::Debug
    for SystemProcRouterBuilder<ES, P, E, U, PE, CO, CF, CC, F>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemProcRouterBuilder")
            .field("has_executesql", &self.executesql.is_some())
            .field("has_prepare", &self.prepare.is_some())
            .field("has_execute", &self.execute.is_some())
            .field("has_unprepare", &self.unprepare.is_some())
            .field("has_prepexec", &self.prepexec.is_some())
            .field("has_cursor_open", &self.cursor_open.is_some())
            .field("has_cursor_fetch", &self.cursor_fetch.is_some())
            .field("has_cursor_close", &self.cursor_close.is_some())
            .field("fallback", &std::any::type_name::<F>())
            .finish()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::prepared::PreparedHandle;
    use crate::server::sp_cursor::CursorHandle;

    struct DummyExecuteSqlHandler;
    impl SpExecuteSqlHandler for DummyExecuteSqlHandler {
        fn execute<'a, C>(
            &'a self,
            _client: &'a mut C,
            _request: crate::server::sp_executesql::ParsedExecuteSql<'a>,
        ) -> BoxFuture<'a, Result<()>>
        where
            C: TdsClient + 'a,
        {
            Box::pin(async { Ok(()) })
        }
    }

    struct DummyPrepareHandler;
    impl SpPrepareHandler for DummyPrepareHandler {
        fn prepare<'a, C>(
            &'a self,
            _client: &'a mut C,
            _request: crate::server::sp_prepare::ParsedPrepare<'a>,
        ) -> BoxFuture<'a, Result<PreparedHandle>>
        where
            C: TdsClient + 'a,
        {
            Box::pin(async { Ok(PreparedHandle::from_i32(1)) })
        }
    }

    struct DummyExecuteHandler;
    impl SpExecuteHandler for DummyExecuteHandler {
        fn execute<'a, C>(
            &'a self,
            _client: &'a mut C,
            _request: crate::server::sp_prepare::ParsedExecute<'a>,
        ) -> BoxFuture<'a, Result<()>>
        where
            C: TdsClient + 'a,
        {
            Box::pin(async { Ok(()) })
        }
    }

    struct DummyUnprepareHandler;
    impl SpUnprepareHandler for DummyUnprepareHandler {
        fn unprepare<'a, C>(
            &'a self,
            _client: &'a mut C,
            _request: crate::server::sp_prepare::ParsedUnprepare,
        ) -> BoxFuture<'a, Result<()>>
        where
            C: TdsClient + 'a,
        {
            Box::pin(async { Ok(()) })
        }
    }

    struct DummyPrepExecHandler;
    impl SpPrepExecHandler for DummyPrepExecHandler {
        fn prep_exec<'a, C>(
            &'a self,
            _client: &'a mut C,
            _request: crate::server::sp_prepexec::ParsedPrepExec<'a>,
        ) -> BoxFuture<'a, Result<PreparedHandle>>
        where
            C: TdsClient + 'a,
        {
            Box::pin(async { Ok(PreparedHandle::from_i32(2)) })
        }
    }

    struct DummyCursorOpen;
    impl SpCursorOpenHandler for DummyCursorOpen {
        fn cursor_open<'a, C>(
            &'a self,
            _client: &'a mut C,
            _request: crate::server::sp_cursor::ParsedCursorOpen<'a>,
        ) -> BoxFuture<'a, Result<CursorHandle>>
        where
            C: TdsClient + 'a,
        {
            Box::pin(async { Ok(CursorHandle::from_i32(3)) })
        }
    }

    struct DummyCursorFetch;
    impl SpCursorFetchHandler for DummyCursorFetch {
        fn cursor_fetch<'a, C>(
            &'a self,
            _client: &'a mut C,
            _request: crate::server::sp_cursor::ParsedCursorFetch,
        ) -> BoxFuture<'a, Result<()>>
        where
            C: TdsClient + 'a,
        {
            Box::pin(async { Ok(()) })
        }
    }

    struct DummyCursorClose;
    impl SpCursorCloseHandler for DummyCursorClose {
        fn cursor_close<'a, C>(
            &'a self,
            _client: &'a mut C,
            _request: crate::server::sp_cursor::ParsedCursorClose,
        ) -> BoxFuture<'a, Result<()>>
        where
            C: TdsClient + 'a,
        {
            Box::pin(async { Ok(()) })
        }
    }

    struct DummyFallback;
    impl RpcHandler for DummyFallback {
        fn on_rpc<'a, C>(
            &'a self,
            _client: &'a mut C,
            _message: RpcMessage,
        ) -> BoxFuture<'a, Result<()>>
        where
            C: TdsClient + 'a,
        {
            Box::pin(async { Ok(()) })
        }
    }

    #[test]
    fn empty_builder() {
        let router = SystemProcRouterBuilder::new().build();
        assert!(!router.has_executesql());
        assert!(!router.has_prepare());
        assert!(!router.has_prepexec());
        assert!(!router.has_cursor_open());
    }

    #[test]
    fn full_builder() {
        let router = SystemProcRouterBuilder::new()
            .with_executesql(DummyExecuteSqlHandler)
            .with_prepare(DummyPrepareHandler)
            .with_execute(DummyExecuteHandler)
            .with_unprepare(DummyUnprepareHandler)
            .with_prepexec(DummyPrepExecHandler)
            .with_cursor_open(DummyCursorOpen)
            .with_cursor_fetch(DummyCursorFetch)
            .with_cursor_close(DummyCursorClose)
            .build();
        assert!(router.has_executesql());
        assert!(router.has_prepare());
        assert!(router.has_execute());
        assert!(router.has_unprepare());
        assert!(router.has_prepexec());
        assert!(router.has_cursor_open());
        assert!(router.has_cursor_fetch());
        assert!(router.has_cursor_close());
    }

    #[test]
    fn custom_fallback() {
        let router = SystemProcRouterBuilder::new()
            .with_executesql(DummyExecuteSqlHandler)
            .with_fallback(DummyFallback)
            .build();
        assert!(router.has_executesql());
    }

    #[test]
    fn reject_unknown_proc_default_debug() {
        let handler = RejectUnknownProc;
        let _ = format!("{:?}", handler);
    }

    #[test]
    fn router_debug_mentions_all_slots() {
        let router = SystemProcRouterBuilder::new().build();
        let debug = format!("{:?}", router);
        assert!(debug.contains("has_prepexec"));
        assert!(debug.contains("has_cursor_open"));
    }
}
