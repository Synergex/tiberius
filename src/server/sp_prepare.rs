//! Handlers for `sp_prepare`, `sp_execute`, and `sp_unprepare` RPC requests.
//!
//! This module provides types and utilities for parsing and handling prepared statement
//! RPC requests in TDS. Prepared statements allow clients to prepare a query once and
//! execute it multiple times with different parameters.
//!
//! # Overview
//!
//! The prepared statement workflow consists of three operations:
//!
//! 1. **sp_prepare** - Prepares a SQL statement and returns a handle
//! 2. **sp_execute** - Executes a prepared statement using its handle
//! 3. **sp_unprepare** - Releases a prepared statement handle
//!
//! # Protocol Details
//!
//! ## sp_prepare Parameters
//!
//! - `@handle OUTPUT int` - Output parameter to receive the prepared handle
//! - `@params nvarchar` - Parameter definitions string (e.g., "@id int, @name nvarchar(100)")
//! - `@stmt nvarchar` - The SQL statement to prepare
//! - `@options int` - Options (optional, defaults to 1)
//!
//! ## sp_execute Parameters
//!
//! - `@handle int` - The prepared statement handle
//! - Additional parameters - Parameter values for execution
//!
//! ## sp_unprepare Parameters
//!
//! - `@handle int` - The prepared statement handle to release
//!
//! # Example
//!
//! ```ignore
//! use tiberius::server::{SpPrepareHandler, SpExecuteHandler, SpUnprepareHandler, PreparedHandle};
//!
//! struct MyPrepareHandler {
//!     cache: Arc<Mutex<ProcedureCache>>,
//! }
//!
//! impl SpPrepareHandler for MyPrepareHandler {
//!     fn prepare<'a, C>(
//!         &'a self,
//!         client: &'a mut C,
//!         request: ParsedPrepare<'a>,
//!     ) -> BoxFuture<'a, crate::Result<PreparedHandle>>
//!     where
//!         C: TdsClient + 'a,
//!     {
//!         Box::pin(async move {
//!             let mut cache = self.cache.lock().unwrap();
//!             let handle = cache.prepare(request.sql().to_string(), vec![], vec![]);
//!             Ok(handle)
//!         })
//!     }
//! }
//! ```

use std::borrow::Cow;

use crate::server::codec::{DecodedRpcParam, RpcParamSet};
use crate::server::handler::{BoxFuture, RpcHandler, TdsClient};
use crate::server::messages::RpcMessage;
use crate::server::prepared::PreparedHandle;
use crate::server::sp_executesql::ExecuteSqlParam;
use crate::tds::codec::{ColumnData, RpcProcId, TypeInfo};
use crate::{Error, Result};

// =============================================================================
// Parsed Request Structs
// =============================================================================

/// A parsed `sp_prepare` request.
///
/// This struct contains the parameter definitions, SQL statement, and options
/// extracted from an RPC request.
///
/// # Fields
///
/// - `param_defs`: Parameter definitions string (e.g., "@id int, @name nvarchar(100)")
/// - `sql`: The SQL statement to prepare
/// - `options`: Preparation options (default 1)
/// - `handle_type_info`: Type information for the output handle parameter
#[derive(Debug)]
pub struct ParsedPrepare<'a> {
    /// The parameter definitions string.
    param_defs: Option<Cow<'a, str>>,
    /// The SQL statement to prepare.
    sql: Cow<'a, str>,
    /// Preparation options (defaults to 1).
    options: i32,
    /// Type information for the handle output parameter.
    handle_type_info: TypeInfo,
}

impl<'a> ParsedPrepare<'a> {
    /// Returns the parameter definitions string, if present.
    pub fn param_defs(&self) -> Option<&str> {
        self.param_defs.as_deref()
    }

    /// Returns the SQL statement to prepare.
    pub fn sql(&self) -> &str {
        &self.sql
    }

    /// Returns the preparation options.
    pub fn options(&self) -> i32 {
        self.options
    }

    /// Returns the type information for the handle output parameter.
    pub fn handle_type_info(&self) -> &TypeInfo {
        &self.handle_type_info
    }
}

/// A parsed `sp_execute` request.
///
/// This struct contains the prepared statement handle and the parameter values
/// to use for execution.
///
/// # Fields
///
/// - `handle`: The prepared statement handle
/// - `params`: The parameter values for execution
#[derive(Debug)]
pub struct ParsedExecute<'a> {
    /// The prepared statement handle.
    handle: PreparedHandle,
    /// The parameter values.
    params: Vec<ExecuteSqlParam<'a>>,
}

impl<'a> ParsedExecute<'a> {
    /// Returns the prepared statement handle.
    pub fn handle(&self) -> PreparedHandle {
        self.handle
    }

    /// Returns a slice of the parameters.
    pub fn params(&self) -> &[ExecuteSqlParam<'a>] {
        &self.params
    }

    /// Consumes the request and returns the parameters.
    pub fn into_params(self) -> Vec<ExecuteSqlParam<'a>> {
        self.params
    }

    /// Returns the number of parameters.
    pub fn param_count(&self) -> usize {
        self.params.len()
    }

    /// Finds a parameter by name (case-insensitive, @ prefix optional).
    ///
    /// # Complexity
    ///
    /// This method performs a linear search, O(n) where n is the parameter count.
    pub fn param_by_name(&self, name: &str) -> Option<&ExecuteSqlParam<'a>> {
        let name_normalized = name.strip_prefix('@').unwrap_or(name);
        self.params.iter().find(|p| {
            let param_name = p.name().strip_prefix('@').unwrap_or(p.name());
            param_name.eq_ignore_ascii_case(name_normalized)
        })
    }
}

/// A parsed `sp_unprepare` request.
///
/// This struct contains the prepared statement handle to release.
#[derive(Debug)]
pub struct ParsedUnprepare {
    /// The prepared statement handle to release.
    handle: PreparedHandle,
}

impl ParsedUnprepare {
    /// Returns the prepared statement handle.
    pub fn handle(&self) -> PreparedHandle {
        self.handle
    }
}

// =============================================================================
// Parser Functions
// =============================================================================

/// Extract an i32 value from a parameter.
fn extract_i32(param: &DecodedRpcParam, param_name: &str) -> Result<i32> {
    match &param.value {
        ColumnData::I32(Some(v)) => Ok(*v),
        ColumnData::I32(None) => Err(Error::Protocol(
            format!("{}: parameter is NULL", param_name).into(),
        )),
        other => Err(Error::Protocol(
            format!(
                "{}: expected int, got {:?}",
                param_name,
                std::mem::discriminant(other)
            )
            .into(),
        )),
    }
}

/// Extract an optional string value from a parameter.
fn extract_optional_string(param: DecodedRpcParam) -> Option<Cow<'static, str>> {
    match param.value {
        ColumnData::String(Some(s)) if !s.is_empty() => Some(Cow::Owned(s.into_owned())),
        ColumnData::String(Some(_)) => None, // Empty string
        ColumnData::String(None) => None,    // NULL
        ColumnData::I32(Some(0)) => None,    // Special marker for no params
        ColumnData::I32(None) => None,       // NULL as I32
        _ => None,
    }
}

/// Extract a required string value from a parameter.
fn extract_string(param: DecodedRpcParam, param_name: &str) -> Result<Cow<'static, str>> {
    match param.value {
        ColumnData::String(Some(s)) => Ok(Cow::Owned(s.into_owned())),
        ColumnData::String(None) => Err(Error::Protocol(
            format!("{}: parameter is NULL", param_name).into(),
        )),
        other => Err(Error::Protocol(
            format!(
                "{}: expected string, got {:?}",
                param_name,
                std::mem::discriminant(&other)
            )
            .into(),
        )),
    }
}

/// Parse an `sp_prepare` request from an RPC parameter set.
///
/// # Parameters
///
/// The RPC request for `sp_prepare` has the following structure:
/// - `params[0]`: `@handle OUTPUT int` - output parameter to receive handle
/// - `params[1]`: `@params nvarchar` - parameter definitions string
/// - `params[2]`: `@stmt nvarchar` - SQL statement
/// - `params[3]`: `@options int` (optional, default 1)
///
/// # Errors
///
/// Returns an error if:
/// - The parameter set has fewer than 3 parameters
/// - The SQL statement (params[2]) is not a string
///
/// # Example
///
/// ```ignore
/// let param_set = rpc_message.into_param_set().await?;
/// let parsed = parse_prepare(param_set)?;
/// ```
pub fn parse_prepare(params: RpcParamSet) -> Result<ParsedPrepare<'static>> {
    let mut params_vec = params.into_inner();

    if params_vec.len() < 3 {
        return Err(Error::Protocol(
            format!(
                "sp_prepare: expected at least 3 parameters, got {}",
                params_vec.len()
            )
            .into(),
        ));
    }

    // params[0]: @handle OUTPUT int - we need to preserve the type info
    let handle_param = params_vec.remove(0);
    let handle_type_info = handle_param.ty.clone();

    // params[1]: @params nvarchar - parameter definitions
    let params_param = params_vec.remove(0);
    let param_defs = extract_optional_string(params_param);

    // params[2]: @stmt nvarchar - SQL statement
    let stmt_param = params_vec.remove(0);
    let sql = extract_string(stmt_param, "sp_prepare @stmt")?;

    // params[3]: @options int (optional, default 1)
    // Options: 1 = prepare only (default), 2 = prepare and execute
    let options = if let Some(options_param) = params_vec.first() {
        match &options_param.value {
            ColumnData::I32(Some(v)) => *v,
            _ => 1,
        }
    } else {
        1
    };

    Ok(ParsedPrepare {
        param_defs,
        sql,
        options,
        handle_type_info,
    })
}

/// Parse an `sp_execute` request from an RPC parameter set.
///
/// # Parameters
///
/// The RPC request for `sp_execute` has the following structure:
/// - `params[0]`: `@handle int` - prepared statement handle
/// - `params[1..]`: parameter values for the prepared statement
///
/// # Errors
///
/// Returns an error if:
/// - The parameter set is empty
/// - The handle (params[0]) is not a valid integer
///
/// # Example
///
/// ```ignore
/// let param_set = rpc_message.into_param_set().await?;
/// let parsed = parse_execute(param_set)?;
/// ```
pub fn parse_execute(params: RpcParamSet) -> Result<ParsedExecute<'static>> {
    let mut params_vec = params.into_inner();

    if params_vec.is_empty() {
        return Err(Error::Protocol(
            "sp_execute: missing handle parameter".into(),
        ));
    }

    // params[0]: @handle int
    let handle_param = params_vec.remove(0);
    let handle_value = extract_i32(&handle_param, "sp_execute @handle")?;
    // SECURITY: Handlers MUST validate that handle.conn_id() matches the current
    // connection ID to prevent cross-connection handle reuse attacks.
    let handle = PreparedHandle::from_i32(handle_value);

    // Remaining params are the actual parameter values
    let params: Vec<ExecuteSqlParam<'static>> = params_vec
        .into_iter()
        .enumerate()
        .map(|(i, p)| ExecuteSqlParam::new(p, i))
        .collect();

    Ok(ParsedExecute { handle, params })
}

/// Parse an `sp_unprepare` request from an RPC parameter set.
///
/// # Parameters
///
/// The RPC request for `sp_unprepare` has the following structure:
/// - `params[0]`: `@handle int` - prepared statement handle to release
///
/// # Errors
///
/// Returns an error if:
/// - The parameter set is empty
/// - The handle (params[0]) is not a valid integer
///
/// # Example
///
/// ```ignore
/// let param_set = rpc_message.into_param_set().await?;
/// let parsed = parse_unprepare(param_set)?;
/// ```
pub fn parse_unprepare(params: RpcParamSet) -> Result<ParsedUnprepare> {
    let mut params_vec = params.into_inner();

    if params_vec.is_empty() {
        return Err(Error::Protocol(
            "sp_unprepare: missing handle parameter".into(),
        ));
    }

    // params[0]: @handle int
    let handle_param = params_vec.remove(0);
    let handle_value = extract_i32(&handle_param, "sp_unprepare @handle")?;
    // SECURITY: Handlers MUST validate that handle.conn_id() matches the current
    // connection ID to prevent cross-connection handle reuse attacks.
    let handle = PreparedHandle::from_i32(handle_value);

    Ok(ParsedUnprepare { handle })
}

// =============================================================================
// Handler Traits
// =============================================================================

/// Handler trait for `sp_prepare` requests.
///
/// Implement this trait to handle prepared statement preparation. The handler
/// should store the prepared statement and return a handle.
///
/// # Example
///
/// ```ignore
/// use tiberius::server::{SpPrepareHandler, ParsedPrepare, TdsClient, BoxFuture, PreparedHandle};
///
/// struct MyHandler {
///     cache: Arc<Mutex<ProcedureCache>>,
/// }
///
/// impl SpPrepareHandler for MyHandler {
///     fn prepare<'a, C>(
///         &'a self,
///         client: &'a mut C,
///         request: ParsedPrepare<'a>,
///     ) -> BoxFuture<'a, crate::Result<PreparedHandle>>
///     where
///         C: TdsClient + 'a,
///     {
///         Box::pin(async move {
///             let mut cache = self.cache.lock().unwrap();
///             let handle = cache.prepare(request.sql().to_string(), vec![], vec![]);
///             Ok(handle)
///         })
///     }
/// }
/// ```
pub trait SpPrepareHandler: Send + Sync {
    /// Prepare a SQL statement and return a handle.
    ///
    /// # Arguments
    ///
    /// * `client` - The TDS client connection for sending responses
    /// * `request` - The parsed sp_prepare request containing SQL and parameter definitions
    ///
    /// # Returns
    ///
    /// Returns `Ok(PreparedHandle)` on success.
    ///
    /// # Response Protocol
    ///
    /// The handler MUST send the following tokens before returning:
    /// 1. `RETURNVALUE` token with the handle (use `send_output_param()`)
    /// 2. `RETURNSTATUS` token (use `send_return_status(0)`)
    /// 3. `DONEPROC` token (use `finish_proc(0)`)
    ///
    /// Use `request.handle_type_info()` when constructing the output parameter.
    fn prepare<'a, C>(
        &'a self,
        client: &'a mut C,
        request: ParsedPrepare<'a>,
    ) -> BoxFuture<'a, Result<PreparedHandle>>
    where
        C: TdsClient + 'a;
}

/// Handler trait for `sp_execute` requests.
///
/// Implement this trait to handle prepared statement execution. The handler
/// should look up the prepared statement by handle, execute it with the provided
/// parameters, and send the results.
///
/// # Example
///
/// ```ignore
/// use tiberius::server::{SpExecuteHandler, ParsedExecute, TdsClient, BoxFuture};
///
/// struct MyHandler {
///     cache: Arc<Mutex<ProcedureCache>>,
/// }
///
/// impl SpExecuteHandler for MyHandler {
///     fn execute<'a, C>(
///         &'a self,
///         client: &'a mut C,
///         request: ParsedExecute<'a>,
///     ) -> BoxFuture<'a, crate::Result<()>>
///     where
///         C: TdsClient + 'a,
///     {
///         Box::pin(async move {
///             let cache = self.cache.lock().unwrap();
///             if let Some(stmt) = cache.get(&request.handle()) {
///                 // Execute the statement with the provided parameters
///             }
///             Ok(())
///         })
///     }
/// }
/// ```
pub trait SpExecuteHandler: Send + Sync {
    /// Execute a prepared statement with the given parameters.
    ///
    /// # Arguments
    ///
    /// * `client` - The TDS client connection for sending responses
    /// * `request` - The parsed sp_execute request containing handle and parameters
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success. The handler is responsible for sending
    /// appropriate response tokens (results, done tokens, etc.) to the client.
    fn execute<'a, C>(
        &'a self,
        client: &'a mut C,
        request: ParsedExecute<'a>,
    ) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClient + 'a;
}

/// Handler trait for `sp_unprepare` requests.
///
/// Implement this trait to handle prepared statement release. The handler
/// should remove the prepared statement from the cache.
///
/// # Example
///
/// ```ignore
/// use tiberius::server::{SpUnprepareHandler, ParsedUnprepare, TdsClient, BoxFuture};
///
/// struct MyHandler {
///     cache: Arc<Mutex<ProcedureCache>>,
/// }
///
/// impl SpUnprepareHandler for MyHandler {
///     fn unprepare<'a, C>(
///         &'a self,
///         client: &'a mut C,
///         request: ParsedUnprepare,
///     ) -> BoxFuture<'a, crate::Result<()>>
///     where
///         C: TdsClient + 'a,
///     {
///         Box::pin(async move {
///             let mut cache = self.cache.lock().unwrap();
///             cache.unprepare(&request.handle());
///             Ok(())
///         })
///     }
/// }
/// ```
pub trait SpUnprepareHandler: Send + Sync {
    /// Release a prepared statement handle.
    ///
    /// # Arguments
    ///
    /// * `client` - The TDS client connection for sending responses
    /// * `request` - The parsed sp_unprepare request containing the handle
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success. The handler is responsible for sending
    /// appropriate done tokens to the client.
    fn unprepare<'a, C>(
        &'a self,
        client: &'a mut C,
        request: ParsedUnprepare,
    ) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClient + 'a;
}

// =============================================================================
// RPC Handler Adapters
// =============================================================================

/// Wrapper that adapts an [`SpPrepareHandler`] to the [`RpcHandler`] trait.
///
/// This struct checks if the incoming RPC is `sp_prepare` (RpcProcId::Prepare),
/// parses the parameters, and delegates to the inner handler. For other RPC calls,
/// it returns an error.
///
/// # Example
///
/// ```ignore
/// use tiberius::server::{SpPrepareRpcHandler, SpPrepareHandler};
///
/// struct MyPrepareHandler;
/// impl SpPrepareHandler for MyPrepareHandler {
///     // ... implementation
/// }
///
/// let rpc_handler = SpPrepareRpcHandler::new(MyPrepareHandler);
/// ```
pub struct SpPrepareRpcHandler<H> {
    inner: H,
}

impl<H> SpPrepareRpcHandler<H> {
    /// Create a new `SpPrepareRpcHandler` wrapping the given handler.
    pub fn new(inner: H) -> Self {
        Self { inner }
    }

    /// Returns a reference to the inner handler.
    pub fn inner(&self) -> &H {
        &self.inner
    }

    /// Returns a mutable reference to the inner handler.
    pub fn inner_mut(&mut self) -> &mut H {
        &mut self.inner
    }

    /// Consumes the wrapper and returns the inner handler.
    pub fn into_inner(self) -> H {
        self.inner
    }
}

impl<H> RpcHandler for SpPrepareRpcHandler<H>
where
    H: SpPrepareHandler,
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
                Some(RpcProcId::Prepare) => {
                    let param_set = message.into_param_set().await?;
                    let request = parse_prepare(param_set)?;

                    // Delegate to the inner handler
                    let _handle = self.inner.prepare(client, request).await?;

                    // Note: The handler is responsible for sending the output parameter
                    // and done token. This is a simple adapter that just calls the handler.
                    Ok(())
                }
                Some(other) => Err(Error::Protocol(
                    format!(
                        "SpPrepareRpcHandler: unsupported RPC proc ID {:?}",
                        other
                    )
                    .into(),
                )),
                None => {
                    let name = message.proc_name.as_deref().unwrap_or("<unknown>");
                    Err(Error::Protocol(
                        format!(
                            "SpPrepareRpcHandler: unsupported RPC procedure '{}'",
                            name
                        )
                        .into(),
                    ))
                }
            }
        })
    }
}

/// Wrapper that adapts an [`SpExecuteHandler`] to the [`RpcHandler`] trait.
///
/// This struct checks if the incoming RPC is `sp_execute` (RpcProcId::Execute),
/// parses the parameters, and delegates to the inner handler. For other RPC calls,
/// it returns an error.
///
/// # Example
///
/// ```ignore
/// use tiberius::server::{SpExecuteRpcHandler, SpExecuteHandler};
///
/// struct MyExecuteHandler;
/// impl SpExecuteHandler for MyExecuteHandler {
///     // ... implementation
/// }
///
/// let rpc_handler = SpExecuteRpcHandler::new(MyExecuteHandler);
/// ```
pub struct SpExecuteRpcHandler<H> {
    inner: H,
}

impl<H> SpExecuteRpcHandler<H> {
    /// Create a new `SpExecuteRpcHandler` wrapping the given handler.
    pub fn new(inner: H) -> Self {
        Self { inner }
    }

    /// Returns a reference to the inner handler.
    pub fn inner(&self) -> &H {
        &self.inner
    }

    /// Returns a mutable reference to the inner handler.
    pub fn inner_mut(&mut self) -> &mut H {
        &mut self.inner
    }

    /// Consumes the wrapper and returns the inner handler.
    pub fn into_inner(self) -> H {
        self.inner
    }
}

impl<H> RpcHandler for SpExecuteRpcHandler<H>
where
    H: SpExecuteHandler,
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
                Some(RpcProcId::Execute) => {
                    let param_set = message.into_param_set().await?;
                    let request = parse_execute(param_set)?;

                    // Delegate to the inner handler
                    self.inner.execute(client, request).await
                }
                Some(other) => Err(Error::Protocol(
                    format!(
                        "SpExecuteRpcHandler: unsupported RPC proc ID {:?}",
                        other
                    )
                    .into(),
                )),
                None => {
                    let name = message.proc_name.as_deref().unwrap_or("<unknown>");
                    Err(Error::Protocol(
                        format!(
                            "SpExecuteRpcHandler: unsupported RPC procedure '{}'",
                            name
                        )
                        .into(),
                    ))
                }
            }
        })
    }
}

/// Wrapper that adapts an [`SpUnprepareHandler`] to the [`RpcHandler`] trait.
///
/// This struct checks if the incoming RPC is `sp_unprepare` (RpcProcId::Unprepare),
/// parses the parameters, and delegates to the inner handler. For other RPC calls,
/// it returns an error.
///
/// # Example
///
/// ```ignore
/// use tiberius::server::{SpUnprepareRpcHandler, SpUnprepareHandler};
///
/// struct MyUnprepareHandler;
/// impl SpUnprepareHandler for MyUnprepareHandler {
///     // ... implementation
/// }
///
/// let rpc_handler = SpUnprepareRpcHandler::new(MyUnprepareHandler);
/// ```
pub struct SpUnprepareRpcHandler<H> {
    inner: H,
}

impl<H> SpUnprepareRpcHandler<H> {
    /// Create a new `SpUnprepareRpcHandler` wrapping the given handler.
    pub fn new(inner: H) -> Self {
        Self { inner }
    }

    /// Returns a reference to the inner handler.
    pub fn inner(&self) -> &H {
        &self.inner
    }

    /// Returns a mutable reference to the inner handler.
    pub fn inner_mut(&mut self) -> &mut H {
        &mut self.inner
    }

    /// Consumes the wrapper and returns the inner handler.
    pub fn into_inner(self) -> H {
        self.inner
    }
}

impl<H> RpcHandler for SpUnprepareRpcHandler<H>
where
    H: SpUnprepareHandler,
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
                Some(RpcProcId::Unprepare) => {
                    let param_set = message.into_param_set().await?;
                    let request = parse_unprepare(param_set)?;

                    // Delegate to the inner handler
                    self.inner.unprepare(client, request).await
                }
                Some(other) => Err(Error::Protocol(
                    format!(
                        "SpUnprepareRpcHandler: unsupported RPC proc ID {:?}",
                        other
                    )
                    .into(),
                )),
                None => {
                    let name = message.proc_name.as_deref().unwrap_or("<unknown>");
                    Err(Error::Protocol(
                        format!(
                            "SpUnprepareRpcHandler: unsupported RPC procedure '{}'",
                            name
                        )
                        .into(),
                    ))
                }
            }
        })
    }
}

// =============================================================================
// Combined Handler
// =============================================================================

/// A combined RPC handler that routes `sp_prepare`, `sp_execute`, and `sp_unprepare`
/// requests to their respective handlers.
///
/// This struct provides a convenient way to handle all three prepared statement
/// operations with a single RPC handler.
///
/// # Example
///
/// ```ignore
/// use tiberius::server::{PreparedStatementRpcHandler, SpPrepareHandler, SpExecuteHandler, SpUnprepareHandler};
///
/// struct MyPrepareHandler;
/// impl SpPrepareHandler for MyPrepareHandler { /* ... */ }
///
/// struct MyExecuteHandler;
/// impl SpExecuteHandler for MyExecuteHandler { /* ... */ }
///
/// struct MyUnprepareHandler;
/// impl SpUnprepareHandler for MyUnprepareHandler { /* ... */ }
///
/// let handler = PreparedStatementRpcHandler::new(
///     MyPrepareHandler,
///     MyExecuteHandler,
///     MyUnprepareHandler,
/// );
/// ```
pub struct PreparedStatementRpcHandler<P, E, U> {
    prepare: P,
    execute: E,
    unprepare: U,
}

impl<P, E, U> PreparedStatementRpcHandler<P, E, U> {
    /// Create a new `PreparedStatementRpcHandler` with the given handlers.
    pub fn new(prepare: P, execute: E, unprepare: U) -> Self {
        Self {
            prepare,
            execute,
            unprepare,
        }
    }

    /// Returns a reference to the prepare handler.
    pub fn prepare_handler(&self) -> &P {
        &self.prepare
    }

    /// Returns a reference to the execute handler.
    pub fn execute_handler(&self) -> &E {
        &self.execute
    }

    /// Returns a reference to the unprepare handler.
    pub fn unprepare_handler(&self) -> &U {
        &self.unprepare
    }

    /// Returns a mutable reference to the prepare handler.
    pub fn prepare_handler_mut(&mut self) -> &mut P {
        &mut self.prepare
    }

    /// Returns a mutable reference to the execute handler.
    pub fn execute_handler_mut(&mut self) -> &mut E {
        &mut self.execute
    }

    /// Returns a mutable reference to the unprepare handler.
    pub fn unprepare_handler_mut(&mut self) -> &mut U {
        &mut self.unprepare
    }

    /// Consumes the handler and returns the inner handlers.
    pub fn into_inner(self) -> (P, E, U) {
        (self.prepare, self.execute, self.unprepare)
    }
}

impl<P, E, U> RpcHandler for PreparedStatementRpcHandler<P, E, U>
where
    P: SpPrepareHandler,
    E: SpExecuteHandler,
    U: SpUnprepareHandler,
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
                Some(RpcProcId::Prepare) => {
                    let param_set = message.into_param_set().await?;
                    let request = parse_prepare(param_set)?;
                    let _handle = self.prepare.prepare(client, request).await?;
                    Ok(())
                }
                Some(RpcProcId::Execute) => {
                    let param_set = message.into_param_set().await?;
                    let request = parse_execute(param_set)?;
                    self.execute.execute(client, request).await
                }
                Some(RpcProcId::Unprepare) => {
                    let param_set = message.into_param_set().await?;
                    let request = parse_unprepare(param_set)?;
                    self.unprepare.unprepare(client, request).await
                }
                Some(other) => Err(Error::Protocol(
                    format!(
                        "PreparedStatementRpcHandler: unsupported RPC proc ID {:?}",
                        other
                    )
                    .into(),
                )),
                None => {
                    let name = message.proc_name.as_deref().unwrap_or("<unknown>");
                    Err(Error::Protocol(
                        format!(
                            "PreparedStatementRpcHandler: unsupported RPC procedure '{}'",
                            name
                        )
                        .into(),
                    ))
                }
            }
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tds::codec::{FixedLenType, VarLenContext, VarLenType};
    use enumflags2::BitFlags;

    fn make_string_param(name: &str, value: &str) -> DecodedRpcParam {
        DecodedRpcParam {
            name: name.to_string(),
            flags: BitFlags::empty(),
            ty: TypeInfo::VarLenSized(VarLenContext::new(VarLenType::NVarchar, 4000, None)),
            value: ColumnData::String(Some(Cow::Owned(value.to_string()))),
        }
    }

    fn make_i32_param(name: &str, value: i32) -> DecodedRpcParam {
        DecodedRpcParam {
            name: name.to_string(),
            flags: BitFlags::empty(),
            ty: TypeInfo::FixedLen(FixedLenType::Int4),
            value: ColumnData::I32(Some(value)),
        }
    }

    fn make_output_i32_param(name: &str) -> DecodedRpcParam {
        use crate::tds::codec::RpcStatus;
        DecodedRpcParam {
            name: name.to_string(),
            flags: RpcStatus::ByRefValue.into(),
            ty: TypeInfo::FixedLen(FixedLenType::Int4),
            value: ColumnData::I32(None),
        }
    }

    // -------------------------------------------------------------------------
    // sp_prepare tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_parse_prepare_basic() {
        let params = vec![
            make_output_i32_param("@handle"),
            make_string_param("@params", "@id int"),
            make_string_param("@stmt", "SELECT * FROM users WHERE id = @id"),
        ];

        let param_set = RpcParamSet::new(params);
        let parsed = parse_prepare(param_set).unwrap();

        assert_eq!(parsed.sql(), "SELECT * FROM users WHERE id = @id");
        assert_eq!(parsed.param_defs(), Some("@id int"));
        assert_eq!(parsed.options(), 1); // Default
    }

    #[test]
    fn test_parse_prepare_with_options() {
        let params = vec![
            make_output_i32_param("@handle"),
            make_string_param("@params", "@id int"),
            make_string_param("@stmt", "SELECT 1"),
            make_i32_param("@options", 3),
        ];

        let param_set = RpcParamSet::new(params);
        let parsed = parse_prepare(param_set).unwrap();

        assert_eq!(parsed.options(), 3);
    }

    #[test]
    fn test_parse_prepare_no_params() {
        let params = vec![
            make_output_i32_param("@handle"),
            make_string_param("@params", ""),
            make_string_param("@stmt", "SELECT 1"),
        ];

        let param_set = RpcParamSet::new(params);
        let parsed = parse_prepare(param_set).unwrap();

        assert_eq!(parsed.sql(), "SELECT 1");
        assert_eq!(parsed.param_defs(), None);
    }

    #[test]
    fn test_parse_prepare_too_few_params() {
        let params = vec![
            make_output_i32_param("@handle"),
            make_string_param("@params", "@id int"),
        ];

        let param_set = RpcParamSet::new(params);
        let result = parse_prepare(param_set);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expected at least 3"));
    }

    // -------------------------------------------------------------------------
    // sp_execute tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_parse_execute_basic() {
        let params = vec![
            make_i32_param("@handle", 42),
            make_i32_param("@id", 100),
        ];

        let param_set = RpcParamSet::new(params);
        let parsed = parse_execute(param_set).unwrap();

        assert_eq!(parsed.handle().as_i32(), 42);
        assert_eq!(parsed.param_count(), 1);
        assert_eq!(parsed.params()[0].get_i32(), Some(100));
    }

    #[test]
    fn test_parse_execute_no_params() {
        let params = vec![make_i32_param("@handle", 123)];

        let param_set = RpcParamSet::new(params);
        let parsed = parse_execute(param_set).unwrap();

        assert_eq!(parsed.handle().as_i32(), 123);
        assert_eq!(parsed.param_count(), 0);
    }

    #[test]
    fn test_parse_execute_multiple_params() {
        let params = vec![
            make_i32_param("@handle", 1),
            make_i32_param("@a", 10),
            make_string_param("@b", "hello"),
            make_i32_param("@c", 20),
        ];

        let param_set = RpcParamSet::new(params);
        let parsed = parse_execute(param_set).unwrap();

        assert_eq!(parsed.handle().as_i32(), 1);
        assert_eq!(parsed.param_count(), 3);
        assert_eq!(parsed.params()[0].get_i32(), Some(10));
        assert_eq!(parsed.params()[1].get_string(), Some("hello"));
        assert_eq!(parsed.params()[2].get_i32(), Some(20));
    }

    #[test]
    fn test_parse_execute_missing_handle() {
        let params: Vec<DecodedRpcParam> = vec![];

        let param_set = RpcParamSet::new(params);
        let result = parse_execute(param_set);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing handle"));
    }

    #[test]
    fn test_parse_execute_param_by_name() {
        let params = vec![
            make_i32_param("@handle", 1),
            make_i32_param("@id", 42),
            make_string_param("@name", "test"),
        ];

        let param_set = RpcParamSet::new(params);
        let parsed = parse_execute(param_set).unwrap();

        // With @ prefix
        let id = parsed.param_by_name("@id").unwrap();
        assert_eq!(id.get_i32(), Some(42));

        // Without @ prefix
        let name = parsed.param_by_name("name").unwrap();
        assert_eq!(name.get_string(), Some("test"));

        // Case insensitive
        let id_upper = parsed.param_by_name("ID");
        assert!(id_upper.is_some());

        // Not found
        assert!(parsed.param_by_name("unknown").is_none());
    }

    // -------------------------------------------------------------------------
    // sp_unprepare tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_parse_unprepare_basic() {
        let params = vec![make_i32_param("@handle", 99)];

        let param_set = RpcParamSet::new(params);
        let parsed = parse_unprepare(param_set).unwrap();

        assert_eq!(parsed.handle().as_i32(), 99);
    }

    #[test]
    fn test_parse_unprepare_missing_handle() {
        let params: Vec<DecodedRpcParam> = vec![];

        let param_set = RpcParamSet::new(params);
        let result = parse_unprepare(param_set);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing handle"));
    }

    #[test]
    fn test_parse_unprepare_invalid_type() {
        let params = vec![make_string_param("@handle", "not an int")];

        let param_set = RpcParamSet::new(params);
        let result = parse_unprepare(param_set);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expected int"));
    }

    // -------------------------------------------------------------------------
    // Struct accessor tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_parsed_prepare_accessors() {
        let params = vec![
            make_output_i32_param("@handle"),
            make_string_param("@params", "@a int, @b varchar(50)"),
            make_string_param("@stmt", "SELECT @a, @b"),
            make_i32_param("@options", 5),
        ];

        let param_set = RpcParamSet::new(params);
        let parsed = parse_prepare(param_set).unwrap();

        assert_eq!(parsed.sql(), "SELECT @a, @b");
        assert_eq!(parsed.param_defs(), Some("@a int, @b varchar(50)"));
        assert_eq!(parsed.options(), 5);
        // Check that handle_type_info is preserved
        assert!(matches!(parsed.handle_type_info(), TypeInfo::FixedLen(FixedLenType::Int4)));
    }

    #[test]
    fn test_parsed_execute_into_params() {
        let params = vec![
            make_i32_param("@handle", 1),
            make_i32_param("@id", 42),
        ];

        let param_set = RpcParamSet::new(params);
        let parsed = parse_execute(param_set).unwrap();

        let owned_params = parsed.into_params();
        assert_eq!(owned_params.len(), 1);
        assert_eq!(owned_params[0].get_i32(), Some(42));
    }
}
