//! Handler for `sp_prepexec` RPC requests.
//!
//! `sp_prepexec` is the combined "prepare + execute in one round trip" RPC.
//! Its wire format is essentially [`sp_prepare`](super::sp_prepare) followed
//! by the execution parameters:
//!
//! - `params[0]`: `@handle OUTPUT int` — output parameter for the new handle
//! - `params[1]`: `@params nvarchar` — parameter definitions string (e.g.
//!   `"@id int, @name nvarchar(100)"`), empty or `I32(0)` for no params
//! - `params[2]`: `@stmt nvarchar` — the SQL statement to prepare & execute
//! - `params[3..]`: actual parameter values for the execution
//!
//! The response should contain any result sets produced by the execution,
//! followed by a `RETURNVALUE` carrying the newly-minted `@handle`, a
//! `RETURNSTATUS`, and a closing `DONEPROC`.

use std::borrow::Cow;

use crate::server::codec::RpcParamSet;
use crate::server::handler::{BoxFuture, RpcHandler, TdsClient};
use crate::server::messages::RpcMessage;
use crate::server::prepared::PreparedHandle;
use crate::server::sp_executesql::ExecuteSqlParam;
use crate::tds::codec::{ColumnData, RpcProcId, TypeInfo};
use crate::{Error, Result};

/// A parsed `sp_prepexec` request.
#[derive(Debug)]
pub struct ParsedPrepExec<'a> {
    /// The parameter definitions string (e.g. `"@id int"`), if present.
    param_defs: Option<Cow<'a, str>>,
    /// The SQL statement to prepare and execute.
    sql: Cow<'a, str>,
    /// Type information for the `@handle` output parameter — handlers echo
    /// this back when constructing the `RETURNVALUE` response.
    handle_type_info: TypeInfo,
    /// The parameter values for this execution.
    params: Vec<ExecuteSqlParam<'a>>,
}

impl<'a> ParsedPrepExec<'a> {
    /// The parameter definitions string, if present.
    pub fn param_defs(&self) -> Option<&str> {
        self.param_defs.as_deref()
    }

    /// The SQL statement.
    pub fn sql(&self) -> &str {
        &self.sql
    }

    /// Type information for the `@handle` output parameter.
    pub fn handle_type_info(&self) -> &TypeInfo {
        &self.handle_type_info
    }

    /// Execution parameters.
    pub fn params(&self) -> &[ExecuteSqlParam<'a>] {
        &self.params
    }

    /// Consume the request and return the parameter vector.
    pub fn into_params(self) -> Vec<ExecuteSqlParam<'a>> {
        self.params
    }

    /// Number of execution parameters.
    pub fn param_count(&self) -> usize {
        self.params.len()
    }
}

/// Parse an `sp_prepexec` request from a raw RPC parameter set.
///
/// # Errors
///
/// Returns an error if the set has fewer than three parameters, or if the
/// `@stmt` parameter is not a string.
pub fn parse_prepexec(params: RpcParamSet) -> Result<ParsedPrepExec<'static>> {
    let mut params_vec = params.into_inner();

    if params_vec.len() < 3 {
        return Err(Error::Protocol(
            format!(
                "sp_prepexec: expected at least 3 parameters, got {}",
                params_vec.len()
            )
            .into(),
        ));
    }

    // params[0]: @handle OUTPUT int — preserve type info for the response.
    let handle_param = params_vec.remove(0);
    let handle_type_info = handle_param.ty.clone();

    // params[1]: @params nvarchar (may be empty, NULL, or I32(0) sentinel).
    let params_param = params_vec.remove(0);
    let param_defs = match params_param.value {
        ColumnData::String(Some(s)) if !s.is_empty() => Some(Cow::Owned(s.into_owned())),
        ColumnData::String(Some(_)) | ColumnData::String(None) => None,
        ColumnData::I32(_) => None,
        _ => None,
    };

    // params[2]: @stmt nvarchar — required.
    let stmt_param = params_vec.remove(0);
    let sql = match stmt_param.value {
        ColumnData::String(Some(s)) => Cow::Owned(s.into_owned()),
        ColumnData::String(None) => {
            return Err(Error::Protocol(
                "sp_prepexec: @stmt parameter is NULL".into(),
            ));
        }
        other => {
            return Err(Error::Protocol(
                format!(
                    "sp_prepexec: @stmt must be a string, got {:?}",
                    std::mem::discriminant(&other)
                )
                .into(),
            ));
        }
    };

    // Remaining params are the execution values.
    let params: Vec<ExecuteSqlParam<'static>> = params_vec
        .into_iter()
        .enumerate()
        .map(|(i, p)| ExecuteSqlParam::new(p, i))
        .collect();

    Ok(ParsedPrepExec {
        param_defs,
        sql,
        handle_type_info,
        params,
    })
}

/// Handler trait for `sp_prepexec` requests.
///
/// Implementers should:
///
/// 1. Generate a handle (typically via a `ProcedureCache`), record the SQL
///    and parameter definitions under that handle.
/// 2. Execute the statement and stream any result sets to the client.
/// 3. Send the handle back as an output parameter via
///    [`send_output_param`](crate::server::send_output_param) using
///    `request.handle_type_info()`.
/// 4. Send a `RETURNSTATUS` (typically `0`) and finish with `DONEPROC`.
///
/// The returned [`PreparedHandle`] is metadata for the server framework /
/// caller; the adapter does not use it to send a response (the handler is
/// responsible for that, because it also needs to produce the result set).
pub trait SpPrepExecHandler: Send + Sync {
    /// Prepare and execute a statement, returning the handle assigned to it.
    fn prep_exec<'a, C>(
        &'a self,
        client: &'a mut C,
        request: ParsedPrepExec<'a>,
    ) -> BoxFuture<'a, Result<PreparedHandle>>
    where
        C: TdsClient + 'a;
}

/// Adapts an [`SpPrepExecHandler`] to the generic [`RpcHandler`] trait.
pub struct SpPrepExecRpcHandler<H> {
    inner: H,
}

impl<H> SpPrepExecRpcHandler<H> {
    /// Wrap the given handler.
    pub fn new(inner: H) -> Self {
        Self { inner }
    }

    /// Borrow the inner handler.
    pub fn inner(&self) -> &H {
        &self.inner
    }

    /// Mutably borrow the inner handler.
    pub fn inner_mut(&mut self) -> &mut H {
        &mut self.inner
    }

    /// Consume the wrapper and return the inner handler.
    pub fn into_inner(self) -> H {
        self.inner
    }
}

impl<H> RpcHandler for SpPrepExecRpcHandler<H>
where
    H: SpPrepExecHandler,
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
                Some(RpcProcId::PrepExec) => {
                    let param_set = message.into_param_set().await?;
                    let request = parse_prepexec(param_set)?;
                    let _handle = self.inner.prep_exec(client, request).await?;
                    Ok(())
                }
                Some(other) => Err(Error::Protocol(
                    format!(
                        "SpPrepExecRpcHandler: unsupported RPC proc ID {:?}",
                        other
                    )
                    .into(),
                )),
                None => {
                    let name = message.proc_name.as_deref().unwrap_or("<unknown>");
                    Err(Error::Protocol(
                        format!(
                            "SpPrepExecRpcHandler: unsupported RPC procedure '{}'",
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
    use crate::server::codec::DecodedRpcParam;
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

    #[test]
    fn parses_basic_prepexec() {
        let params = vec![
            make_output_i32_param("@handle"),
            make_string_param("@params", "@id int"),
            make_string_param("@stmt", "SELECT * FROM t WHERE id = @id"),
            make_i32_param("@id", 42),
        ];
        let parsed = parse_prepexec(RpcParamSet::new(params)).unwrap();

        assert_eq!(parsed.sql(), "SELECT * FROM t WHERE id = @id");
        assert_eq!(parsed.param_defs(), Some("@id int"));
        assert_eq!(parsed.param_count(), 1);
        assert_eq!(parsed.params()[0].get_i32(), Some(42));
        assert!(matches!(
            parsed.handle_type_info(),
            TypeInfo::FixedLen(FixedLenType::Int4)
        ));
    }

    #[test]
    fn parses_prepexec_without_value_params() {
        let params = vec![
            make_output_i32_param("@handle"),
            make_string_param("@params", ""),
            make_string_param("@stmt", "SELECT 1"),
        ];
        let parsed = parse_prepexec(RpcParamSet::new(params)).unwrap();

        assert_eq!(parsed.sql(), "SELECT 1");
        assert_eq!(parsed.param_defs(), None);
        assert_eq!(parsed.param_count(), 0);
    }

    #[test]
    fn rejects_too_few_params() {
        let params = vec![
            make_output_i32_param("@handle"),
            make_string_param("@params", ""),
        ];
        let err = parse_prepexec(RpcParamSet::new(params)).unwrap_err();
        assert!(err.to_string().contains("expected at least 3"));
    }

    #[test]
    fn rejects_null_stmt() {
        let params = vec![
            make_output_i32_param("@handle"),
            make_string_param("@params", ""),
            DecodedRpcParam {
                name: "@stmt".into(),
                flags: BitFlags::empty(),
                ty: TypeInfo::VarLenSized(VarLenContext::new(VarLenType::NVarchar, 4000, None)),
                value: ColumnData::String(None),
            },
        ];
        let err = parse_prepexec(RpcParamSet::new(params)).unwrap_err();
        assert!(err.to_string().contains("NULL"));
    }
}
