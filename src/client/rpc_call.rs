//! Public API for invoking arbitrary stored procedures via native TDS RPC.

use super::rpc_response::{self, BufferedResultSet, OutputValue};
use super::Client;
use crate::tds::codec::{RpcParam, RpcStatus};
use crate::{ColumnData, TypeInfo};
use enumflags2::BitFlags;
use futures_util::io::{AsyncRead, AsyncWrite};
use std::borrow::Cow;

/// Whether a [`ProcedureParameter`] carries a value to the server, a value
/// back from the server, or both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParameterDirection {
    /// The value is sent to the server; no value is returned for it.
    Input,
    /// The value is not meaningful on the way in; the server writes a value
    /// back for it.
    Output,
    /// The value is sent to the server, which may return a different value
    /// for the same parameter.
    InputOutput,
}

/// A single parameter for [`Client::call_procedure`].
///
/// The wire type ([`TypeInfo`]) is always explicit and independent of the
/// value — this is what lets an [`Output`](ParameterDirection::Output)
/// parameter use a real SQL `NULL` (`ColumnData::I32(None)`, etc.) as its
/// placeholder: the declared type, not the value, decides whether the wire
/// representation is nullable.
///
/// Parameters bind positionally by default; call [`named`](Self::named) to
/// bind by name instead.
#[derive(Debug, Clone)]
pub struct ProcedureParameter<'a> {
    name: Option<Cow<'a, str>>,
    direction: ParameterDirection,
    type_info: TypeInfo,
    value: ColumnData<'a>,
}

impl<'a> ProcedureParameter<'a> {
    /// An input-only parameter: `value` is sent to the server and not
    /// expected back.
    pub fn input(type_info: TypeInfo, value: ColumnData<'a>) -> Self {
        Self {
            name: None,
            direction: ParameterDirection::Input,
            type_info,
            value,
        }
    }

    /// An output-only parameter. `value` is the placeholder sent to the
    /// server before it writes the real value back — typically a `NULL` of
    /// the declared `type_info` (e.g. `ColumnData::I32(None)`).
    pub fn output(type_info: TypeInfo, value: ColumnData<'a>) -> Self {
        Self {
            name: None,
            direction: ParameterDirection::Output,
            type_info,
            value,
        }
    }

    /// An input/output parameter: `value` is sent to the server as the
    /// initial input, and the server may return a different value for the
    /// same parameter.
    pub fn input_output(type_info: TypeInfo, value: ColumnData<'a>) -> Self {
        Self {
            name: None,
            direction: ParameterDirection::InputOutput,
            type_info,
            value,
        }
    }

    /// Bind this parameter by name (e.g. `"@handle"`) instead of by
    /// position.
    pub fn named(mut self, name: impl Into<Cow<'a, str>>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// The parameter's name, if bound by name.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The parameter's direction.
    pub fn direction(&self) -> ParameterDirection {
        self.direction
    }

    /// The parameter's declared wire type.
    pub fn type_info(&self) -> &TypeInfo {
        &self.type_info
    }

    /// The parameter's value.
    pub fn value(&self) -> &ColumnData<'a> {
        &self.value
    }

    fn into_rpc_param(self) -> RpcParam<'a> {
        let flags = match self.direction {
            ParameterDirection::Input => BitFlags::empty(),
            ParameterDirection::Output | ParameterDirection::InputOutput => {
                RpcStatus::ByRefValue.into()
            }
        };

        RpcParam {
            name: self.name.unwrap_or(Cow::Borrowed("")),
            flags,
            type_info: Some(self.type_info),
            value: self.value,
        }
    }
}

/// The full response to a [`Client::call_procedure`] call: any result sets
/// the procedure produced, its output parameter values, its `RETURN`
/// status, and any informational messages it emitted.
#[derive(Debug)]
pub struct ProcedureResult {
    /// Result sets produced by the procedure, in the order the server sent
    /// them.
    pub result_sets: Vec<BufferedResultSet>,
    /// Output parameter values the server returned.
    pub output_values: Vec<OutputValue>,
    /// The procedure's `RETURN` status, if any. TDS `RETURNSTATUS` is a
    /// signed 32-bit integer, so this is `i32` rather than the wire-level
    /// `u32`.
    pub return_status: Option<i32>,
    /// Informational messages (`PRINT`, `RAISERROR` with severity <= 10)
    /// emitted while the procedure ran, in emission order.
    pub messages: Vec<crate::TokenInfo>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> Client<S> {
    /// Call a stored procedure by name via native TDS RPC.
    ///
    /// Unlike [`query`](Self::query) / [`execute`](Self::execute) (which
    /// synthesize an `sp_executesql` call and only expose row data / row
    /// counts), this can invoke *any* stored procedure — including
    /// user-defined ones — and gives access to everything the RPC response
    /// carries: result sets, output parameter values, the procedure's
    /// `RETURN` status, and informational messages.
    ///
    /// Build `parameters` with [`ProcedureParameter::input`],
    /// [`ProcedureParameter::output`], and
    /// [`ProcedureParameter::input_output`]. The response is fully buffered
    /// before this call returns, so the connection is safe to reuse
    /// immediately afterward, and an in-flight call can be interrupted with
    /// [`cancellation_token`](Self::cancellation_token) exactly like
    /// `query`/`execute`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tiberius::{Config, ColumnData, ProcedureParameter, TypeInfo, VarLenContext, VarLenType};
    /// # use tokio_util::compat::TokioAsyncWriteCompatExt;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let config = Config::new();
    /// # let tcp = tokio::net::TcpStream::connect(config.get_addr()).await?;
    /// # let mut client = tiberius::Client::connect(config, tcp.compat_write()).await?;
    /// let int_type = TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 4, None));
    ///
    /// let result = client
    ///     .call_procedure(
    ///         "my_schema.my_procedure",
    ///         vec![
    ///             ProcedureParameter::input(int_type.clone(), ColumnData::I32(Some(42)))
    ///                 .named("@input"),
    ///             ProcedureParameter::output(int_type, ColumnData::I32(None)).named("@output"),
    ///         ],
    ///     )
    ///     .await?;
    ///
    /// for output in &result.output_values {
    ///     let _: Option<i32> = output.get()?;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn call_procedure<'a>(
        &mut self,
        proc: impl Into<Cow<'a, str>>,
        parameters: Vec<ProcedureParameter<'a>>,
    ) -> crate::Result<ProcedureResult> {
        self.connection.flush_stream().await?;

        let proc: Cow<'a, str> = proc.into();
        let rpc_params: Vec<RpcParam<'a>> = parameters
            .into_iter()
            .map(ProcedureParameter::into_rpc_param)
            .collect();
        self.send_rpc(proc, rpc_params).await?;

        let (result_sets, output_values, return_status, messages) =
            rpc_response::collect_rpc_result_sets(&mut self.connection).await?;

        Ok(ProcedureResult {
            result_sets,
            output_values,
            return_status: return_status.map(|status| status as i32),
            messages,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_sets_no_flags() {
        let p = ProcedureParameter::input(TypeInfo::FixedLen(crate::FixedLenType::Int4), ColumnData::I32(Some(1)));
        assert_eq!(p.direction(), ParameterDirection::Input);
        let rpc = p.into_rpc_param();
        assert_eq!(rpc.flags, BitFlags::empty());
        assert_eq!(rpc.name, Cow::Borrowed(""));
    }

    #[test]
    fn output_sets_byref_flag_and_preserves_explicit_null() {
        use crate::{VarLenContext, VarLenType};
        let ty = TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 4, None));
        let p = ProcedureParameter::output(ty.clone(), ColumnData::I32(None)).named("@out");
        assert_eq!(p.direction(), ParameterDirection::Output);
        assert_eq!(p.name(), Some("@out"));
        assert_eq!(p.type_info(), &ty);
        assert!(matches!(p.value(), ColumnData::I32(None)));

        let rpc = p.into_rpc_param();
        assert_eq!(rpc.flags, BitFlags::from(RpcStatus::ByRefValue));
        assert_eq!(rpc.name, Cow::Borrowed("@out"));
        assert_eq!(rpc.type_info, Some(ty));
        assert!(matches!(rpc.value, ColumnData::I32(None)));
    }

    #[test]
    fn input_output_sets_byref_flag_and_keeps_value() {
        let p = ProcedureParameter::input_output(
            TypeInfo::FixedLen(crate::FixedLenType::Int4),
            ColumnData::I32(Some(7)),
        );
        assert_eq!(p.direction(), ParameterDirection::InputOutput);
        let rpc = p.into_rpc_param();
        assert_eq!(rpc.flags, BitFlags::from(RpcStatus::ByRefValue));
        assert!(matches!(rpc.value, ColumnData::I32(Some(7))));
    }

    #[test]
    fn positional_by_default() {
        let p = ProcedureParameter::input(TypeInfo::FixedLen(crate::FixedLenType::Int4), ColumnData::I32(Some(1)));
        assert_eq!(p.name(), None);
        let rpc = p.into_rpc_param();
        assert_eq!(rpc.name, Cow::Borrowed(""));
    }

    #[test]
    fn return_status_wire_bits_reinterpreted_as_signed() {
        // TDS RETURNSTATUS is a signed i32; a wire value of 0xFFFFFFFF
        // (a common "failure" convention) must surface as -1, not
        // 4294967295.
        let wire: u32 = 0xFFFF_FFFF;
        assert_eq!(wire as i32, -1);
    }
}
