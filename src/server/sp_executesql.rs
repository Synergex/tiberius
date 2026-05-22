//! Handler for `sp_executesql` RPC requests.
//!
//! This module provides types and utilities for parsing and handling `sp_executesql` requests,
//! which are used for parameterized query execution in TDS.
//!
//! # Overview
//!
//! When a client executes a parameterized query, it sends an RPC request with
//! [`RpcProcId::ExecuteSQL`](crate::tds::codec::RpcProcId::ExecuteSQL). The request contains:
//!
//! 1. The SQL query text (parameter 0)
//! 2. Parameter definitions string (parameter 1, may be empty)
//! 3. Parameter values (parameters 2..N)
//!
//! # Example
//!
//! ```ignore
//! use tiberius::server::{SpExecuteSqlHandler, ParsedExecuteSql, TdsClient, BoxFuture};
//!
//! struct MyHandler;
//!
//! impl SpExecuteSqlHandler for MyHandler {
//!     fn execute<'a, C>(
//!         &'a self,
//!         client: &'a mut C,
//!         request: ParsedExecuteSql<'a>,
//!     ) -> BoxFuture<'a, crate::Result<()>>
//!     where
//!         C: TdsClient + 'a,
//!     {
//!         Box::pin(async move {
//!             println!("SQL: {}", request.sql());
//!             for param in request.params() {
//!                 println!("  {}: {:?}", param.name(), param.value());
//!             }
//!             Ok(())
//!         })
//!     }
//! }
//! ```

use std::borrow::Cow;

use crate::server::codec::{DecodedRpcParam, RpcParamSet};
use crate::server::handler::{BoxFuture, RpcHandler, TdsClient};
use crate::server::messages::RpcMessage;
use crate::tds::codec::{ColumnData, RpcProcId, TypeInfo};
use crate::{Error, Result};

/// A parsed parameter from an `sp_executesql` request.
///
/// This struct wraps an RPC parameter and provides convenient typed accessors
/// for common value types.
///
/// # Example
///
/// ```ignore
/// let param: &ExecuteSqlParam = &request.params()[0];
///
/// // Get the parameter name (without @ prefix)
/// let name = param.name();
///
/// // Try to extract as specific types
/// if let Some(id) = param.get_i32() {
///     println!("id = {}", id);
/// }
/// if let Some(name) = param.get_string() {
///     println!("name = {}", name);
/// }
/// ```
#[derive(Debug)]
pub struct ExecuteSqlParam<'a> {
    /// The parameter name (may include @ prefix).
    name: Cow<'a, str>,
    /// The parameter value.
    value: ColumnData<'a>,
    /// Type information for the parameter.
    type_info: TypeInfo,
    /// Whether this is an output parameter.
    is_output: bool,
    /// The ordinal position of this parameter (0-based, relative to user params).
    ordinal: usize,
}

impl<'a> ExecuteSqlParam<'a> {
    /// Create a new `ExecuteSqlParam` from a decoded RPC parameter.
    pub(crate) fn new(param: DecodedRpcParam, ordinal: usize) -> ExecuteSqlParam<'static> {
        let is_output = param.is_output();
        ExecuteSqlParam {
            name: Cow::Owned(param.name),
            value: param.value,
            type_info: param.ty,
            is_output,
            ordinal,
        }
    }

    /// Returns the parameter name.
    ///
    /// The name may include the `@` prefix as sent by the client.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the parameter name without the `@` prefix.
    pub fn name_without_prefix(&self) -> &str {
        self.name.strip_prefix('@').unwrap_or(&self.name)
    }

    /// Returns a reference to the parameter value.
    pub fn value(&self) -> &ColumnData<'a> {
        &self.value
    }

    /// Consumes the parameter and returns the value.
    pub fn into_value(self) -> ColumnData<'a> {
        self.value
    }

    /// Returns the type information for this parameter.
    pub fn type_info(&self) -> &TypeInfo {
        &self.type_info
    }

    /// Returns `true` if this is an output parameter.
    pub fn is_output(&self) -> bool {
        self.is_output
    }

    /// Returns the ordinal position of this parameter (0-based).
    pub fn ordinal(&self) -> usize {
        self.ordinal
    }

    // -------------------------------------------------------------------------
    // Typed Accessors
    // -------------------------------------------------------------------------

    /// Attempts to extract the value as an `i32`.
    ///
    /// Returns `Some(value)` if the parameter is `I32(Some(v))`, otherwise `None`.
    pub fn get_i32(&self) -> Option<i32> {
        match &self.value {
            ColumnData::I32(Some(v)) => Some(*v),
            _ => None,
        }
    }

    /// Attempts to extract the value as an `i64`.
    ///
    /// Returns `Some(value)` if the parameter is `I64(Some(v))`, otherwise `None`.
    pub fn get_i64(&self) -> Option<i64> {
        match &self.value {
            ColumnData::I64(Some(v)) => Some(*v),
            _ => None,
        }
    }

    /// Attempts to extract the value as an `i16`.
    ///
    /// Returns `Some(value)` if the parameter is `I16(Some(v))`, otherwise `None`.
    pub fn get_i16(&self) -> Option<i16> {
        match &self.value {
            ColumnData::I16(Some(v)) => Some(*v),
            _ => None,
        }
    }

    /// Attempts to extract the value as a `u8`.
    ///
    /// Returns `Some(value)` if the parameter is `U8(Some(v))`, otherwise `None`.
    pub fn get_u8(&self) -> Option<u8> {
        match &self.value {
            ColumnData::U8(Some(v)) => Some(*v),
            _ => None,
        }
    }

    /// Attempts to extract the value as a `bool`.
    ///
    /// Returns `Some(value)` if the parameter is `Bit(Some(v))`, otherwise `None`.
    pub fn get_bool(&self) -> Option<bool> {
        match &self.value {
            ColumnData::Bit(Some(v)) => Some(*v),
            _ => None,
        }
    }

    /// Attempts to extract the value as an `f32`.
    ///
    /// Returns `Some(value)` if the parameter is `F32(Some(v))`, otherwise `None`.
    pub fn get_f32(&self) -> Option<f32> {
        match &self.value {
            ColumnData::F32(Some(v)) => Some(*v),
            _ => None,
        }
    }

    /// Attempts to extract the value as an `f64`.
    ///
    /// Returns `Some(value)` if the parameter is `F64(Some(v))`, otherwise `None`.
    pub fn get_f64(&self) -> Option<f64> {
        match &self.value {
            ColumnData::F64(Some(v)) => Some(*v),
            _ => None,
        }
    }

    /// Attempts to extract the value as a string reference.
    ///
    /// Returns `Some(&str)` if the parameter is `String(Some(v))`, otherwise `None`.
    pub fn get_string(&self) -> Option<&str> {
        match &self.value {
            ColumnData::String(Some(v)) => Some(v.as_ref()),
            _ => None,
        }
    }

    /// Attempts to extract the value as a byte slice.
    ///
    /// Returns `Some(&[u8])` if the parameter is `Binary(Some(v))`, otherwise `None`.
    pub fn get_binary(&self) -> Option<&[u8]> {
        match &self.value {
            ColumnData::Binary(Some(v)) => Some(v.as_ref()),
            _ => None,
        }
    }

    /// Attempts to extract the value as a UUID.
    ///
    /// Returns `Some(Uuid)` if the parameter is `Guid(Some(v))`, otherwise `None`.
    pub fn get_guid(&self) -> Option<uuid::Uuid> {
        match &self.value {
            ColumnData::Guid(Some(v)) => Some(*v),
            _ => None,
        }
    }

    /// Returns `true` if the value is `NULL`.
    pub fn is_null(&self) -> bool {
        matches!(
            &self.value,
            ColumnData::U8(None)
                | ColumnData::I16(None)
                | ColumnData::I32(None)
                | ColumnData::I64(None)
                | ColumnData::F32(None)
                | ColumnData::F64(None)
                | ColumnData::Bit(None)
                | ColumnData::String(None)
                | ColumnData::Guid(None)
                | ColumnData::Binary(None)
                | ColumnData::Numeric(None)
                | ColumnData::Xml(None)
                | ColumnData::DateTime(None)
                | ColumnData::SmallDateTime(None)
                | ColumnData::Time(None)
                | ColumnData::Date(None)
                | ColumnData::DateTime2(None)
                | ColumnData::DateTimeOffset(None)
                | ColumnData::Udt(None)
                | ColumnData::Variant(None)
                | ColumnData::Tvp(None)
        )
    }
}

/// A parsed `sp_executesql` request.
///
/// This struct contains the SQL query, optional parameter definitions, and
/// the parameter values extracted from an RPC request.
///
/// # Fields
///
/// - `sql`: The SQL query text to execute
/// - `param_defs`: Optional parameter definitions string (e.g., "@id int, @name nvarchar(100)")
/// - `params`: The parameter values
///
/// # Example
///
/// ```ignore
/// let parsed = parse_executesql(param_set)?;
/// println!("SQL: {}", parsed.sql());
/// if let Some(defs) = parsed.param_defs() {
///     println!("Param definitions: {}", defs);
/// }
/// for param in parsed.params() {
///     println!("  {} = {:?}", param.name(), param.value());
/// }
/// ```
#[derive(Debug)]
pub struct ParsedExecuteSql<'a> {
    /// The SQL query text.
    sql: Cow<'a, str>,
    /// The parameter definitions string (e.g., "@id int, @name nvarchar(100)").
    param_defs: Option<Cow<'a, str>>,
    /// The parameter values.
    params: Vec<ExecuteSqlParam<'a>>,
}

impl<'a> ParsedExecuteSql<'a> {
    /// Returns the SQL query text.
    pub fn sql(&self) -> &str {
        &self.sql
    }

    /// Returns the parameter definitions string, if present.
    pub fn param_defs(&self) -> Option<&str> {
        self.param_defs.as_deref()
    }

    /// Returns a slice of the parameters.
    pub fn params(&self) -> &[ExecuteSqlParam<'a>] {
        &self.params
    }

    /// Consumes the request and returns the parameters.
    pub fn into_params(self) -> Vec<ExecuteSqlParam<'a>> {
        self.params
    }

    /// Returns an iterator over output parameters only.
    ///
    /// Output parameters have the `ByRefValue` RPC status flag set.
    pub fn output_params(&self) -> impl Iterator<Item = &ExecuteSqlParam<'a>> {
        self.params.iter().filter(|p| p.is_output())
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

    /// Returns the number of parameters.
    pub fn param_count(&self) -> usize {
        self.params.len()
    }
}

/// Parse an `sp_executesql` request from an RPC parameter set.
///
/// This function extracts the SQL text, parameter definitions, and parameter values
/// from the raw RPC parameters.
///
/// # Parameters
///
/// The RPC request for `sp_executesql` has the following structure:
/// - `params[0]`: SQL query text (nvarchar)
/// - `params[1]`: Parameter definitions (nvarchar, may be `I32(0)` or empty string for no params)
/// - `params[2..]`: Actual parameter values
///
/// # Errors
///
/// Returns an error if:
/// - The parameter set has fewer than 1 parameter
/// - The SQL text (params[0]) is not a string
///
/// # Example
///
/// ```ignore
/// let param_set = rpc_message.into_param_set().await?;
/// let parsed = parse_executesql(param_set)?;
/// ```
pub fn parse_executesql(params: RpcParamSet) -> Result<ParsedExecuteSql<'static>> {
    let mut params_vec = params.into_inner();

    if params_vec.is_empty() {
        return Err(Error::Protocol(
            "sp_executesql: missing SQL parameter".into(),
        ));
    }

    // Extract SQL text from params[0]
    let sql_param = params_vec.remove(0);
    let sql = match sql_param.value {
        ColumnData::String(Some(s)) => Cow::Owned(s.into_owned()),
        ColumnData::String(None) => {
            return Err(Error::Protocol(
                "sp_executesql: SQL parameter is NULL".into(),
            ));
        }
        other => {
            return Err(Error::Protocol(
                format!(
                    "sp_executesql: SQL parameter must be a string, got {:?}",
                    std::mem::discriminant(&other)
                )
                .into(),
            ));
        }
    };

    // Extract parameter definitions from params[1] (may be absent, empty, or I32(0))
    let param_defs = if !params_vec.is_empty() {
        let defs_param = params_vec.remove(0);
        match defs_param.value {
            ColumnData::String(Some(s)) if !s.is_empty() => Some(Cow::Owned(s.into_owned())),
            ColumnData::String(Some(_)) => None, // Empty string
            ColumnData::String(None) => None,    // NULL
            ColumnData::I32(Some(0)) => None,    // Special marker for no params
            ColumnData::I32(None) => None,       // NULL as I32
            _ => None, // Other types treated as no param defs
        }
    } else {
        None
    };

    // Remaining params are the actual parameter values
    let params: Vec<ExecuteSqlParam<'static>> = params_vec
        .into_iter()
        .enumerate()
        .map(|(i, p)| ExecuteSqlParam::new(p, i))
        .collect();

    Ok(ParsedExecuteSql {
        sql,
        param_defs,
        params,
    })
}

/// Handler trait for `sp_executesql` requests.
///
/// Implement this trait to handle parameterized query execution. The trait
/// provides a convenient interface for processing `sp_executesql` RPC requests.
///
/// # Example
///
/// ```ignore
/// use tiberius::server::{SpExecuteSqlHandler, ParsedExecuteSql, TdsClient, BoxFuture};
///
/// struct MyHandler;
///
/// impl SpExecuteSqlHandler for MyHandler {
///     fn execute<'a, C>(
///         &'a self,
///         client: &'a mut C,
///         request: ParsedExecuteSql<'a>,
///     ) -> BoxFuture<'a, crate::Result<()>>
///     where
///         C: TdsClient + 'a,
///     {
///         Box::pin(async move {
///             // Parse and execute the SQL with parameters
///             let sql = request.sql();
///             for param in request.params() {
///                 // Process parameters...
///             }
///             Ok(())
///         })
///     }
/// }
/// ```
pub trait SpExecuteSqlHandler: Send + Sync {
    /// Execute a parsed `sp_executesql` request.
    ///
    /// # Arguments
    ///
    /// * `client` - The TDS client connection for sending responses
    /// * `request` - The parsed sp_executesql request containing SQL and parameters
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success. The handler is responsible for sending
    /// appropriate response tokens (results, done tokens, etc.) to the client.
    fn execute<'a, C>(
        &'a self,
        client: &'a mut C,
        request: ParsedExecuteSql<'a>,
    ) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClient + 'a;
}

/// Wrapper that adapts an [`SpExecuteSqlHandler`] to the [`RpcHandler`] trait.
///
/// This struct checks if the incoming RPC is `sp_executesql` (RpcProcId::ExecuteSQL),
/// parses the parameters, and delegates to the inner handler. For other RPC calls,
/// it returns an error.
///
/// # Example
///
/// ```ignore
/// use tiberius::server::{SpExecuteSqlRpcHandler, SpExecuteSqlHandler, TdsServerHandlers};
///
/// struct MyExecuteSqlHandler;
/// impl SpExecuteSqlHandler for MyExecuteSqlHandler {
///     // ... implementation
/// }
///
/// let rpc_handler = SpExecuteSqlRpcHandler::new(MyExecuteSqlHandler);
///
/// // Use in TdsServerHandlers
/// struct MyHandlers {
///     rpc: SpExecuteSqlRpcHandler<MyExecuteSqlHandler>,
///     // ...
/// }
/// ```
pub struct SpExecuteSqlRpcHandler<H> {
    inner: H,
}

impl<H> SpExecuteSqlRpcHandler<H> {
    /// Create a new `SpExecuteSqlRpcHandler` wrapping the given handler.
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

impl<H> RpcHandler for SpExecuteSqlRpcHandler<H>
where
    H: SpExecuteSqlHandler,
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
            // Check if this is an sp_executesql call
            match message.proc_id {
                Some(RpcProcId::ExecuteSQL) => {
                    // Parse the parameters
                    let param_set = message.into_param_set().await?;
                    let request = parse_executesql(param_set)?;

                    // Delegate to the inner handler
                    self.inner.execute(client, request).await
                }
                Some(other) => Err(Error::Protocol(
                    format!(
                        "SpExecuteSqlRpcHandler: unsupported RPC proc ID {:?}",
                        other
                    )
                    .into(),
                )),
                None => {
                    let name = message.proc_name.as_deref().unwrap_or("<unknown>");
                    Err(Error::Protocol(
                        format!(
                            "SpExecuteSqlRpcHandler: unsupported RPC procedure '{}'",
                            name
                        )
                        .into(),
                    ))
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tds::codec::TypeInfo;
    use enumflags2::BitFlags;

    fn make_string_param(name: &str, value: &str) -> DecodedRpcParam {
        DecodedRpcParam {
            name: name.to_string(),
            flags: BitFlags::empty(),
            ty: TypeInfo::VarLenSized(crate::tds::codec::VarLenContext::new(
                crate::tds::codec::VarLenType::NVarchar,
                4000,
                None,
            )),
            value: ColumnData::String(Some(Cow::Owned(value.to_string()))),
        }
    }

    fn make_i32_param(name: &str, value: i32) -> DecodedRpcParam {
        DecodedRpcParam {
            name: name.to_string(),
            flags: BitFlags::empty(),
            ty: TypeInfo::FixedLen(crate::tds::codec::FixedLenType::Int4),
            value: ColumnData::I32(Some(value)),
        }
    }

    #[test]
    fn test_parse_executesql_simple() {
        let params = vec![
            make_string_param("", "SELECT * FROM users WHERE id = @id"),
            make_string_param("", "@id int"),
            make_i32_param("@id", 42),
        ];

        let param_set = RpcParamSet::new(params);
        let parsed = parse_executesql(param_set).unwrap();

        assert_eq!(parsed.sql(), "SELECT * FROM users WHERE id = @id");
        assert_eq!(parsed.param_defs(), Some("@id int"));
        assert_eq!(parsed.param_count(), 1);
        assert_eq!(parsed.params()[0].get_i32(), Some(42));
    }

    #[test]
    fn test_parse_executesql_no_params() {
        let params = vec![make_string_param("", "SELECT 1")];

        let param_set = RpcParamSet::new(params);
        let parsed = parse_executesql(param_set).unwrap();

        assert_eq!(parsed.sql(), "SELECT 1");
        assert_eq!(parsed.param_defs(), None);
        assert_eq!(parsed.param_count(), 0);
    }

    #[test]
    fn test_parse_executesql_empty_param_defs() {
        let params = vec![
            make_string_param("", "SELECT 1"),
            make_string_param("", ""),
        ];

        let param_set = RpcParamSet::new(params);
        let parsed = parse_executesql(param_set).unwrap();

        assert_eq!(parsed.sql(), "SELECT 1");
        assert_eq!(parsed.param_defs(), None);
    }

    #[test]
    fn test_parse_executesql_missing_sql() {
        let params: Vec<DecodedRpcParam> = vec![];
        let param_set = RpcParamSet::new(params);
        let result = parse_executesql(param_set);
        assert!(result.is_err());
    }

    #[test]
    fn test_param_by_name() {
        let params = vec![
            make_string_param("", "SELECT @a, @b"),
            make_string_param("", "@a int, @b varchar(50)"),
            make_i32_param("@a", 1),
            make_string_param("@b", "hello"),
        ];

        let param_set = RpcParamSet::new(params);
        let parsed = parse_executesql(param_set).unwrap();

        // With @ prefix
        let a = parsed.param_by_name("@a").unwrap();
        assert_eq!(a.get_i32(), Some(1));

        // Without @ prefix
        let b = parsed.param_by_name("b").unwrap();
        assert_eq!(b.get_string(), Some("hello"));

        // Case insensitive
        let a_upper = parsed.param_by_name("A");
        assert!(a_upper.is_some());

        // Not found
        assert!(parsed.param_by_name("c").is_none());
    }

    #[test]
    fn test_execute_sql_param_accessors() {
        let param = ExecuteSqlParam {
            name: Cow::Borrowed("@test"),
            value: ColumnData::I32(Some(42)),
            type_info: TypeInfo::FixedLen(crate::tds::codec::FixedLenType::Int4),
            is_output: false,
            ordinal: 0,
        };

        assert_eq!(param.name(), "@test");
        assert_eq!(param.name_without_prefix(), "test");
        assert_eq!(param.get_i32(), Some(42));
        assert_eq!(param.get_i64(), None);
        assert_eq!(param.get_string(), None);
        assert!(!param.is_null());
        assert!(!param.is_output());
        assert_eq!(param.ordinal(), 0);
    }

    #[test]
    fn test_execute_sql_param_null() {
        let param = ExecuteSqlParam {
            name: Cow::Borrowed("@nullable"),
            value: ColumnData::I32(None),
            type_info: TypeInfo::FixedLen(crate::tds::codec::FixedLenType::Int4),
            is_output: false,
            ordinal: 0,
        };

        assert!(param.is_null());
        assert_eq!(param.get_i32(), None);
    }
}
