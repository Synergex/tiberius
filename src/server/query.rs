//! High-level query handling utilities for TDS servers.
//!
//! This module provides simplified abstractions for building query handlers:
//!
//! - [`QueryColumnType`]: Simplified SQL type definitions
//! - [`QueryColumn`]: Column metadata builder
//! - [`QueryOutput`]: Simplified result set writer with state tracking
//! - [`QueryHandler`]: High-level trait for query execution
//! - [`SimpleQueryAdapter`]: Bridges `QueryHandler` to `SqlBatchHandler`
//!
//! # Example
//!
//! ```ignore
//! use tiberius::server::{QueryHandler, QueryOutput, QueryColumn, QueryColumnType, BoxFuture};
//! use tiberius::ColumnData;
//!
//! struct MyQueryHandler;
//!
//! impl QueryHandler for MyQueryHandler {
//!     fn query<'a, C: TdsClient + 'a>(
//!         &'a self,
//!         sql: &'a str,
//!         output: &'a mut QueryOutput<'a, C>,
//!     ) -> BoxFuture<'a, Result<()>> {
//!         Box::pin(async move {
//!             // Define columns
//!             let columns = vec![
//!                 QueryColumn::new("id", QueryColumnType::Int),
//!                 QueryColumn::new("name", QueryColumnType::NVarChar(100)).nullable(),
//!             ];
//!
//!             // Send result set
//!             output.columns(columns).await?;
//!             output.row(vec![
//!                 ColumnData::I32(Some(1)),
//!                 ColumnData::String(Some("Alice".into())),
//!             ]).await?;
//!             output.complete(1).await?;
//!
//!             Ok(())
//!         })
//!     }
//! }
//! ```

use std::borrow::Cow;

use enumflags2::BitFlags;
use futures_util::sink::SinkExt;

use crate::server::handler::{BoxFuture, SqlBatchHandler, TdsClient};
use crate::server::messages::{BackendToken, SqlBatchMessage, TdsBackendMessage};
use crate::server::response::ResultSetWriter;
use crate::tds::codec::{
    BaseMetaDataColumn, ColumnData, ColumnFlag, DoneStatus, MetaDataColumn, TokenDone, TokenError,
    TypeInfo, VarLenContext, VarLenType,
};
use crate::tds::Collation;
use crate::Result;

/// Default collation used for string types (SQL_Latin1_General_CP1_CI_AS).
const DEFAULT_COLLATION: Collation = Collation::new(13632521, 52);

/// Simplified SQL column type definitions.
///
/// This enum provides a more ergonomic way to define column types compared to
/// using `TypeInfo` directly. Use [`to_type_info`](Self::to_type_info) to convert
/// to the low-level type representation.
///
/// # Example
///
/// ```ignore
/// use tiberius::server::QueryColumnType;
///
/// let int_type = QueryColumnType::Int;
/// let varchar_type = QueryColumnType::NVarChar(100);
/// let decimal_type = QueryColumnType::Decimal(18, 2);
///
/// // Convert to TypeInfo for protocol encoding
/// let type_info = int_type.to_type_info();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryColumnType {
    // Integer types
    /// 1-byte unsigned integer (0-255)
    TinyInt,
    /// 2-byte signed integer
    SmallInt,
    /// 4-byte signed integer
    Int,
    /// 8-byte signed integer
    BigInt,

    // Floating point types
    /// 4-byte floating point (single precision)
    Real,
    /// 8-byte floating point (double precision)
    Float,

    // Boolean
    /// Boolean value (true/false)
    Bit,

    // String types
    /// Unicode variable-length string with maximum length in characters.
    /// Use 0xFFFF (65535) for MAX.
    NVarChar(u16),
    /// Unicode fixed-length string with length in characters
    NChar(u16),
    /// Non-Unicode variable-length string with maximum length in bytes.
    /// Use 0xFFFF (65535) for MAX.
    VarChar(u16),
    /// Non-Unicode fixed-length string with length in bytes
    Char(u16),

    // Binary types
    /// Variable-length binary data with maximum length in bytes.
    /// Use 0xFFFF (65535) for MAX.
    VarBinary(u16),
    /// Fixed-length binary data with length in bytes
    Binary(u16),

    // Date/Time types
    /// Date only (no time component)
    Date,
    /// Time only with specified fractional seconds precision (0-7)
    Time(u8),
    /// Date and time with specified fractional seconds precision (0-7)
    DateTime2(u8),
    /// Legacy datetime type
    DateTime,
    /// Legacy small datetime type
    SmallDateTime,
    /// Date and time with timezone offset, with specified precision (0-7)
    DateTimeOffset(u8),

    // Numeric types
    /// Exact numeric with precision and scale
    Decimal(u8, u8),
    /// Exact numeric with precision and scale (alias for Decimal)
    Numeric(u8, u8),

    // Other types
    /// Globally unique identifier (GUID/UUID)
    UniqueIdentifier,
    /// XML data
    Xml,
}

impl QueryColumnType {
    /// Convert to the low-level `TypeInfo` representation.
    ///
    /// This is used when encoding column metadata for the TDS protocol.
    pub fn to_type_info(&self) -> TypeInfo {
        match *self {
            // Integer types - use nullable variants (Intn)
            QueryColumnType::TinyInt => {
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 1, None))
            }
            QueryColumnType::SmallInt => {
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 2, None))
            }
            QueryColumnType::Int => {
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 4, None))
            }
            QueryColumnType::BigInt => {
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 8, None))
            }

            // Floating point types - use nullable variants (Floatn)
            QueryColumnType::Real => {
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Floatn, 4, None))
            }
            QueryColumnType::Float => {
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Floatn, 8, None))
            }

            // Boolean - use nullable variant (Bitn)
            QueryColumnType::Bit => {
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Bitn, 1, None))
            }

            // Unicode string types
            QueryColumnType::NVarChar(len) => TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::NVarchar,
                if len == 0xFFFF {
                    0xFFFF
                } else {
                    (len as usize) * 2
                }, // UTF-16 encoding
                Some(DEFAULT_COLLATION),
            )),
            QueryColumnType::NChar(len) => TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::NChar,
                (len as usize) * 2, // UTF-16 encoding
                Some(DEFAULT_COLLATION),
            )),

            // Non-Unicode string types
            QueryColumnType::VarChar(len) => TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::BigVarChar,
                len as usize,
                Some(DEFAULT_COLLATION),
            )),
            QueryColumnType::Char(len) => TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::BigChar,
                len as usize,
                Some(DEFAULT_COLLATION),
            )),

            // Binary types
            QueryColumnType::VarBinary(len) => TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::BigVarBin,
                len as usize,
                None,
            )),
            QueryColumnType::Binary(len) => TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::BigBinary,
                len as usize,
                None,
            )),

            // Date/Time types
            QueryColumnType::Date => {
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Daten, 3, None))
            }
            QueryColumnType::Time(scale) => TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::Timen,
                scale as usize,
                None,
            )),
            QueryColumnType::DateTime2(scale) => TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::Datetime2,
                scale as usize,
                None,
            )),
            QueryColumnType::DateTime => {
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Datetimen, 8, None))
            }
            QueryColumnType::SmallDateTime => {
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Datetimen, 4, None))
            }
            QueryColumnType::DateTimeOffset(scale) => TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::DatetimeOffsetn,
                scale as usize,
                None,
            )),

            // Numeric types
            QueryColumnType::Decimal(precision, scale)
            | QueryColumnType::Numeric(precision, scale) => {
                let size = match precision {
                    1..=9 => 5,
                    10..=19 => 9,
                    20..=28 => 13,
                    _ => 17,
                };
                TypeInfo::VarLenSizedPrecision {
                    ty: VarLenType::Numericn,
                    size,
                    precision,
                    scale,
                }
            }

            // GUID
            QueryColumnType::UniqueIdentifier => {
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Guid, 16, None))
            }

            // XML
            QueryColumnType::Xml => TypeInfo::Xml {
                schema: None,
                size: 0xfffffffffffffffe_usize,
            },
        }
    }

    /// Create a nullable NVARCHAR(MAX) type.
    pub fn nvarchar_max() -> Self {
        QueryColumnType::NVarChar(0xFFFF)
    }

    /// Create a nullable VARCHAR(MAX) type.
    pub fn varchar_max() -> Self {
        QueryColumnType::VarChar(0xFFFF)
    }

    /// Create a nullable VARBINARY(MAX) type.
    pub fn varbinary_max() -> Self {
        QueryColumnType::VarBinary(0xFFFF)
    }
}

/// Simple column definition for result sets.
///
/// Use this to define columns in a result set with a fluent builder interface.
///
/// # Example
///
/// ```ignore
/// use tiberius::server::{QueryColumn, QueryColumnType};
///
/// // Non-nullable INT column
/// let id_col = QueryColumn::new("id", QueryColumnType::Int);
///
/// // Nullable NVARCHAR(100) column
/// let name_col = QueryColumn::new("name", QueryColumnType::NVarChar(100)).nullable();
/// ```
#[derive(Debug, Clone)]
pub struct QueryColumn {
    /// Column name
    pub name: String,
    /// Column type
    pub ty: QueryColumnType,
    /// Whether the column allows NULL values
    pub nullable: bool,
}

impl QueryColumn {
    /// Create a new column with the given name and type.
    ///
    /// By default, columns are NOT nullable. Use [`.nullable()`](Self::nullable)
    /// to allow NULL values.
    pub fn new(name: impl Into<String>, ty: QueryColumnType) -> Self {
        Self {
            name: name.into(),
            ty,
            nullable: false,
        }
    }

    /// Mark this column as nullable (allows NULL values).
    pub fn nullable(mut self) -> Self {
        self.nullable = true;
        self
    }

    /// Convert to the low-level `MetaDataColumn` representation.
    ///
    /// This is used when encoding column metadata for the TDS protocol.
    pub fn into_metadata(self) -> MetaDataColumn<'static> {
        let mut flags = BitFlags::empty();
        if self.nullable {
            flags |= ColumnFlag::Nullable;
        }

        MetaDataColumn {
            base: BaseMetaDataColumn {
                user_type: 0,
                flags,
                ty: self.ty.to_type_info(),
                table_name: None,
            },
            col_name: Cow::Owned(self.name),
        }
    }
}

/// State tracking for result set output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputState {
    /// Initial state, no result set started
    Initial,
    /// Column metadata has been sent, ready for rows
    InResultSet,
    /// Result set completed
    Completed,
    /// An error was sent
    Error,
}

/// Simplified output writer for query results.
///
/// This struct provides a higher-level interface for sending query results
/// compared to using `ResultSetWriter` directly. It tracks state to ensure
/// correct protocol sequencing.
///
/// # State Machine
///
/// ```text
/// Initial -> InResultSet (after columns())
/// InResultSet -> InResultSet (after row())
/// InResultSet -> Completed (after complete())
/// Any -> Error (after error())
/// ```
///
/// # Example
///
/// ```ignore
/// use tiberius::server::{QueryOutput, QueryColumn, QueryColumnType};
/// use tiberius::ColumnData;
///
/// async fn send_results<C: TdsClient>(output: &mut QueryOutput<'_, C>) -> Result<()> {
///     // Define and send columns
///     output.columns(vec![
///         QueryColumn::new("id", QueryColumnType::Int),
///         QueryColumn::new("value", QueryColumnType::NVarChar(50)).nullable(),
///     ]).await?;
///
///     // Send rows
///     output.row(vec![
///         ColumnData::I32(Some(1)),
///         ColumnData::String(Some("test".into())),
///     ]).await?;
///
///     // Complete the result set
///     output.complete(1).await?;
///
///     Ok(())
/// }
/// ```
pub struct QueryOutput<'a, C> {
    client: &'a mut C,
    state: OutputState,
    columns: Vec<MetaDataColumn<'static>>,
}

impl<'a, C> QueryOutput<'a, C>
where
    C: TdsClient,
{
    /// Create a new query output writer.
    pub fn new(client: &'a mut C) -> Self {
        Self {
            client,
            state: OutputState::Initial,
            columns: Vec::new(),
        }
    }

    /// Send column metadata to start a result set.
    ///
    /// This must be called before sending any rows. After calling this,
    /// use [`row()`](Self::row) to send data and [`complete()`](Self::complete)
    /// to finish the result set.
    ///
    /// # Errors
    ///
    /// Returns an error if called when already in a result set or after completion.
    pub async fn columns(&mut self, columns: Vec<QueryColumn>) -> Result<()> {
        if self.state != OutputState::Initial {
            return Err(crate::Error::Protocol(
                "columns() can only be called in initial state".into(),
            ));
        }

        let metadata_columns: Vec<MetaDataColumn<'static>> =
            columns.into_iter().map(|c| c.into_metadata()).collect();

        // Store columns for row encoding
        self.columns = metadata_columns.clone();

        // Send column metadata
        let token = crate::tds::codec::TokenColMetaData {
            columns: metadata_columns,
        };
        self.client
            .send(TdsBackendMessage::TokenPartial(BackendToken::ColMetaData(
                token,
            )))
            .await?;

        self.state = OutputState::InResultSet;
        Ok(())
    }

    /// Send a row of data.
    ///
    /// The values must match the column types sent via [`columns()`](Self::columns).
    ///
    /// # Errors
    ///
    /// Returns an error if called before `columns()` or after `complete()`.
    pub async fn row(&mut self, values: Vec<ColumnData<'static>>) -> Result<()> {
        if self.state != OutputState::InResultSet {
            return Err(crate::Error::Protocol(
                "row() can only be called after columns() and before complete()".into(),
            ));
        }

        if values.len() != self.columns.len() {
            return Err(crate::Error::Protocol(
                format!(
                    "row has {} values but {} columns were defined",
                    values.len(),
                    self.columns.len()
                )
                .into(),
            ));
        }

        let mut row = crate::tds::codec::TokenRow::with_capacity(values.len());
        for value in values {
            row.push(value);
        }

        self.client
            .send(TdsBackendMessage::TokenPartial(BackendToken::Row(row)))
            .await
    }

    /// Send a row using NBCROW encoding (null bitmap compression).
    ///
    /// This is more efficient when rows contain many NULL values.
    pub async fn row_nbc(&mut self, values: Vec<ColumnData<'static>>) -> Result<()> {
        if self.state != OutputState::InResultSet {
            return Err(crate::Error::Protocol(
                "row_nbc() can only be called after columns() and before complete()".into(),
            ));
        }

        if values.len() != self.columns.len() {
            return Err(crate::Error::Protocol(
                format!(
                    "row has {} values but {} columns were defined",
                    values.len(),
                    self.columns.len()
                )
                .into(),
            ));
        }

        let mut row = crate::tds::codec::TokenRow::with_capacity(values.len());
        for value in values {
            row.push(value);
        }

        self.client
            .send(TdsBackendMessage::TokenPartial(BackendToken::NbcRow(row)))
            .await
    }

    /// Complete the current result set.
    ///
    /// # Arguments
    ///
    /// * `rows` - The number of rows sent in this result set
    ///
    /// # Errors
    ///
    /// Returns an error if not currently in a result set.
    pub async fn complete(&mut self, rows: u64) -> Result<()> {
        if self.state != OutputState::InResultSet {
            return Err(crate::Error::Protocol(
                "complete() can only be called after columns()".into(),
            ));
        }

        let done = TokenDone::with_rows(rows);
        self.client
            .send(TdsBackendMessage::Token(BackendToken::Done(done)))
            .await?;

        self.state = OutputState::Completed;
        self.columns.clear();
        Ok(())
    }

    /// Complete the result set indicating more results will follow.
    ///
    /// Use this when sending multiple result sets in a single response.
    pub async fn complete_more(&mut self, rows: u64) -> Result<()> {
        if self.state != OutputState::InResultSet {
            return Err(crate::Error::Protocol(
                "complete_more() can only be called after columns()".into(),
            ));
        }

        let done = TokenDone::with_more_rows(rows);
        self.client
            .send(TdsBackendMessage::Token(BackendToken::Done(done)))
            .await?;

        // Reset to initial state for next result set
        self.state = OutputState::Initial;
        self.columns.clear();
        Ok(())
    }

    /// Send an empty result set (no columns, no rows).
    ///
    /// This is useful for commands that don't return data (e.g., DDL statements).
    /// Can only be called in initial state (before any result set is started).
    pub async fn empty(&mut self) -> Result<()> {
        if self.state != OutputState::Initial {
            return Err(crate::Error::Protocol(
                "empty() can only be called in initial state".into(),
            ));
        }
        let done = TokenDone::with_rows(0);
        self.client
            .send(TdsBackendMessage::Token(BackendToken::Done(done)))
            .await?;

        self.state = OutputState::Completed;
        Ok(())
    }

    /// Send a "rows affected" result without a result set.
    ///
    /// This is useful for INSERT/UPDATE/DELETE statements.
    /// Can only be called in initial state (before any result set is started).
    pub async fn rows_affected(&mut self, count: u64) -> Result<()> {
        if self.state != OutputState::Initial {
            return Err(crate::Error::Protocol(
                "rows_affected() can only be called in initial state".into(),
            ));
        }
        let done = TokenDone::with_rows(count);
        self.client
            .send(TdsBackendMessage::Token(BackendToken::Done(done)))
            .await?;

        self.state = OutputState::Completed;
        Ok(())
    }

    /// Send an error to the client.
    ///
    /// This sends an ERROR token followed by a DONE token with error status.
    pub async fn error(&mut self, error: TokenError) -> Result<()> {
        self.client
            .send(TdsBackendMessage::TokenPartial(BackendToken::Error(error)))
            .await?;

        let done = TokenDone::with_status(DoneStatus::Error.into(), 0);
        self.client
            .send(TdsBackendMessage::Token(BackendToken::Done(done)))
            .await?;

        self.state = OutputState::Error;
        Ok(())
    }

    /// Send a simple error with message.
    ///
    /// This is a convenience method that creates a TokenError with default values.
    pub async fn error_message(&mut self, number: u32, message: impl Into<String>) -> Result<()> {
        let error = TokenError::new(
            number,
            0, // state
            16, // class (severity) - 16 is "user error"
            message.into(),
            String::new(), // server
            String::new(), // procedure
            0,             // line
        );
        self.error(error).await
    }

    /// Check if an attention/cancel signal has been received.
    pub async fn poll_attention(&mut self) -> Result<bool> {
        self.client.poll_attention().await
    }

    /// Get access to the underlying client.
    ///
    /// This is useful for advanced scenarios where you need direct access
    /// to the client connection.
    pub fn client(&mut self) -> &mut C {
        self.client
    }

    /// Get the current state of the output writer.
    pub fn state(&self) -> &'static str {
        match self.state {
            OutputState::Initial => "initial",
            OutputState::InResultSet => "in_result_set",
            OutputState::Completed => "completed",
            OutputState::Error => "error",
        }
    }

    /// Check if the output is in initial state (ready to start a result set).
    pub fn is_initial(&self) -> bool {
        self.state == OutputState::Initial
    }

    /// Check if the output is currently in a result set.
    pub fn is_in_result_set(&self) -> bool {
        self.state == OutputState::InResultSet
    }

    /// Check if the output has been completed.
    pub fn is_completed(&self) -> bool {
        self.state == OutputState::Completed
    }

    /// Create a `ResultSetWriter` for advanced row streaming.
    ///
    /// This is useful when you need the advanced features of `ResultSetWriter`
    /// (e.g., batch row sending, streaming) but want to use `QueryOutput` for
    /// state tracking.
    ///
    /// # Warning
    ///
    /// After using the returned `ResultSetWriter`, you must manually update
    /// the state of this `QueryOutput` or create a new one.
    pub async fn start_result_set(
        &mut self,
        columns: Vec<QueryColumn>,
    ) -> Result<ResultSetWriter<'_, C>> {
        if self.state != OutputState::Initial {
            return Err(crate::Error::Protocol(
                "start_result_set() can only be called in initial state".into(),
            ));
        }

        let metadata_columns: Vec<MetaDataColumn<'static>> =
            columns.into_iter().map(|c| c.into_metadata()).collect();

        let writer = ResultSetWriter::start(self.client, metadata_columns).await?;
        self.state = OutputState::InResultSet;
        Ok(writer)
    }
}

/// High-level query handler trait.
///
/// Implement this trait to process SQL queries with a simplified interface.
/// The [`QueryOutput`] abstraction handles protocol details like column metadata
/// encoding and result set sequencing.
///
/// # Example
///
/// ```ignore
/// use tiberius::server::{QueryHandler, QueryOutput, QueryColumn, QueryColumnType, TdsClient, BoxFuture};
/// use tiberius::ColumnData;
///
/// struct EchoQueryHandler;
///
/// impl QueryHandler for EchoQueryHandler {
///     fn query<'a, C: TdsClient + 'a>(
///         &'a self,
///         sql: &'a str,
///         output: &'a mut QueryOutput<'a, C>,
///     ) -> BoxFuture<'a, Result<()>> {
///         Box::pin(async move {
///             // Echo back the SQL as a single-row, single-column result
///             output.columns(vec![
///                 QueryColumn::new("sql", QueryColumnType::nvarchar_max()).nullable(),
///             ]).await?;
///
///             output.row(vec![
///                 ColumnData::String(Some(sql.to_string().into())),
///             ]).await?;
///
///             output.complete(1).await?;
///             Ok(())
///         })
///     }
/// }
/// ```
pub trait QueryHandler: Send + Sync {
    /// Handle a SQL query and write results to the output.
    ///
    /// # Arguments
    ///
    /// * `sql` - The SQL query text
    /// * `output` - The output writer for sending results
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or an error if query processing fails.
    fn query<'a, C: TdsClient + 'a>(
        &'a self,
        sql: &'a str,
        output: &'a mut QueryOutput<'a, C>,
    ) -> BoxFuture<'a, Result<()>>;
}

/// Adapter that bridges [`QueryHandler`] to [`SqlBatchHandler`].
///
/// This allows you to implement the simpler `QueryHandler` trait and use it
/// with the server's `SqlBatchHandler` infrastructure.
///
/// # Example
///
/// ```ignore
/// use tiberius::server::{SimpleQueryAdapter, QueryHandler, TdsServerHandlers};
///
/// struct MyQueryHandler;
/// impl QueryHandler for MyQueryHandler { /* ... */ }
///
/// struct MyServer {
///     query_adapter: SimpleQueryAdapter<MyQueryHandler>,
/// }
///
/// impl TdsServerHandlers for MyServer {
///     type SqlBatch = SimpleQueryAdapter<MyQueryHandler>;
///     // ...
///     fn sql_batch_handler(&self) -> &Self::SqlBatch {
///         &self.query_adapter
///     }
/// }
/// ```
pub struct SimpleQueryAdapter<Q> {
    handler: Q,
}

impl<Q> SimpleQueryAdapter<Q> {
    /// Create a new adapter wrapping the given query handler.
    pub fn new(handler: Q) -> Self {
        Self { handler }
    }

    /// Get a reference to the wrapped handler.
    pub fn handler(&self) -> &Q {
        &self.handler
    }

    /// Get a mutable reference to the wrapped handler.
    pub fn handler_mut(&mut self) -> &mut Q {
        &mut self.handler
    }

    /// Consume the adapter and return the wrapped handler.
    pub fn into_handler(self) -> Q {
        self.handler
    }
}

impl<Q: QueryHandler> SqlBatchHandler for SimpleQueryAdapter<Q> {
    fn on_sql_batch<'a, C>(
        &'a self,
        client: &'a mut C,
        message: SqlBatchMessage,
    ) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async move {
            let mut output = QueryOutput::new(client);
            self.handler.query(&message.batch, &mut output).await
        })
    }
}

// Note: Send and Sync are auto-derived for SimpleQueryAdapter<Q>
// when Q: Send and Q: Sync, since it's a simple wrapper struct.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_column_type_to_type_info_integers() {
        // TinyInt
        let ti = QueryColumnType::TinyInt.to_type_info();
        match ti {
            TypeInfo::VarLenSized(ctx) => {
                assert_eq!(ctx.r#type(), VarLenType::Intn);
                assert_eq!(ctx.len(), 1);
            }
            _ => panic!("Expected VarLenSized"),
        }

        // SmallInt
        let ti = QueryColumnType::SmallInt.to_type_info();
        match ti {
            TypeInfo::VarLenSized(ctx) => {
                assert_eq!(ctx.r#type(), VarLenType::Intn);
                assert_eq!(ctx.len(), 2);
            }
            _ => panic!("Expected VarLenSized"),
        }

        // Int
        let ti = QueryColumnType::Int.to_type_info();
        match ti {
            TypeInfo::VarLenSized(ctx) => {
                assert_eq!(ctx.r#type(), VarLenType::Intn);
                assert_eq!(ctx.len(), 4);
            }
            _ => panic!("Expected VarLenSized"),
        }

        // BigInt
        let ti = QueryColumnType::BigInt.to_type_info();
        match ti {
            TypeInfo::VarLenSized(ctx) => {
                assert_eq!(ctx.r#type(), VarLenType::Intn);
                assert_eq!(ctx.len(), 8);
            }
            _ => panic!("Expected VarLenSized"),
        }
    }

    #[test]
    fn test_query_column_type_to_type_info_floats() {
        // Real
        let ti = QueryColumnType::Real.to_type_info();
        match ti {
            TypeInfo::VarLenSized(ctx) => {
                assert_eq!(ctx.r#type(), VarLenType::Floatn);
                assert_eq!(ctx.len(), 4);
            }
            _ => panic!("Expected VarLenSized"),
        }

        // Float
        let ti = QueryColumnType::Float.to_type_info();
        match ti {
            TypeInfo::VarLenSized(ctx) => {
                assert_eq!(ctx.r#type(), VarLenType::Floatn);
                assert_eq!(ctx.len(), 8);
            }
            _ => panic!("Expected VarLenSized"),
        }
    }

    #[test]
    fn test_query_column_type_to_type_info_bit() {
        let ti = QueryColumnType::Bit.to_type_info();
        match ti {
            TypeInfo::VarLenSized(ctx) => {
                assert_eq!(ctx.r#type(), VarLenType::Bitn);
                assert_eq!(ctx.len(), 1);
            }
            _ => panic!("Expected VarLenSized"),
        }
    }

    #[test]
    fn test_query_column_type_to_type_info_strings() {
        // NVarChar
        let ti = QueryColumnType::NVarChar(100).to_type_info();
        match ti {
            TypeInfo::VarLenSized(ctx) => {
                assert_eq!(ctx.r#type(), VarLenType::NVarchar);
                assert_eq!(ctx.len(), 200); // UTF-16, so 100 chars = 200 bytes
                assert!(ctx.collation().is_some());
            }
            _ => panic!("Expected VarLenSized"),
        }

        // NVarChar MAX
        let ti = QueryColumnType::nvarchar_max().to_type_info();
        match ti {
            TypeInfo::VarLenSized(ctx) => {
                assert_eq!(ctx.r#type(), VarLenType::NVarchar);
                assert_eq!(ctx.len(), 0xFFFF);
            }
            _ => panic!("Expected VarLenSized"),
        }

        // VarChar
        let ti = QueryColumnType::VarChar(50).to_type_info();
        match ti {
            TypeInfo::VarLenSized(ctx) => {
                assert_eq!(ctx.r#type(), VarLenType::BigVarChar);
                assert_eq!(ctx.len(), 50);
                assert!(ctx.collation().is_some());
            }
            _ => panic!("Expected VarLenSized"),
        }
    }

    #[test]
    fn test_query_column_type_to_type_info_binary() {
        // VarBinary
        let ti = QueryColumnType::VarBinary(100).to_type_info();
        match ti {
            TypeInfo::VarLenSized(ctx) => {
                assert_eq!(ctx.r#type(), VarLenType::BigVarBin);
                assert_eq!(ctx.len(), 100);
                assert!(ctx.collation().is_none());
            }
            _ => panic!("Expected VarLenSized"),
        }

        // Binary
        let ti = QueryColumnType::Binary(50).to_type_info();
        match ti {
            TypeInfo::VarLenSized(ctx) => {
                assert_eq!(ctx.r#type(), VarLenType::BigBinary);
                assert_eq!(ctx.len(), 50);
            }
            _ => panic!("Expected VarLenSized"),
        }
    }

    #[test]
    fn test_query_column_type_to_type_info_datetime() {
        // Date
        let ti = QueryColumnType::Date.to_type_info();
        match ti {
            TypeInfo::VarLenSized(ctx) => {
                assert_eq!(ctx.r#type(), VarLenType::Daten);
            }
            _ => panic!("Expected VarLenSized"),
        }

        // Time with scale 3
        let ti = QueryColumnType::Time(3).to_type_info();
        match ti {
            TypeInfo::VarLenSized(ctx) => {
                assert_eq!(ctx.r#type(), VarLenType::Timen);
                assert_eq!(ctx.len(), 3);
            }
            _ => panic!("Expected VarLenSized"),
        }

        // DateTime2 with scale 7
        let ti = QueryColumnType::DateTime2(7).to_type_info();
        match ti {
            TypeInfo::VarLenSized(ctx) => {
                assert_eq!(ctx.r#type(), VarLenType::Datetime2);
                assert_eq!(ctx.len(), 7);
            }
            _ => panic!("Expected VarLenSized"),
        }

        // DateTime
        let ti = QueryColumnType::DateTime.to_type_info();
        match ti {
            TypeInfo::VarLenSized(ctx) => {
                assert_eq!(ctx.r#type(), VarLenType::Datetimen);
                assert_eq!(ctx.len(), 8);
            }
            _ => panic!("Expected VarLenSized"),
        }

        // SmallDateTime
        let ti = QueryColumnType::SmallDateTime.to_type_info();
        match ti {
            TypeInfo::VarLenSized(ctx) => {
                assert_eq!(ctx.r#type(), VarLenType::Datetimen);
                assert_eq!(ctx.len(), 4);
            }
            _ => panic!("Expected VarLenSized"),
        }
    }

    #[test]
    fn test_query_column_type_to_type_info_decimal() {
        // Decimal(18, 2)
        let ti = QueryColumnType::Decimal(18, 2).to_type_info();
        match ti {
            TypeInfo::VarLenSizedPrecision {
                ty,
                precision,
                scale,
                size,
            } => {
                assert_eq!(ty, VarLenType::Numericn);
                assert_eq!(precision, 18);
                assert_eq!(scale, 2);
                assert_eq!(size, 9); // 10-19 precision uses 9 bytes
            }
            _ => panic!("Expected VarLenSizedPrecision"),
        }

        // Decimal(5, 0) - small precision
        let ti = QueryColumnType::Decimal(5, 0).to_type_info();
        match ti {
            TypeInfo::VarLenSizedPrecision { size, .. } => {
                assert_eq!(size, 5); // 1-9 precision uses 5 bytes
            }
            _ => panic!("Expected VarLenSizedPrecision"),
        }

        // Decimal(38, 10) - max precision
        let ti = QueryColumnType::Decimal(38, 10).to_type_info();
        match ti {
            TypeInfo::VarLenSizedPrecision { size, .. } => {
                assert_eq!(size, 17); // 29-38 precision uses 17 bytes
            }
            _ => panic!("Expected VarLenSizedPrecision"),
        }
    }

    #[test]
    fn test_query_column_type_to_type_info_guid() {
        let ti = QueryColumnType::UniqueIdentifier.to_type_info();
        match ti {
            TypeInfo::VarLenSized(ctx) => {
                assert_eq!(ctx.r#type(), VarLenType::Guid);
                assert_eq!(ctx.len(), 16);
            }
            _ => panic!("Expected VarLenSized"),
        }
    }

    #[test]
    fn test_query_column_type_to_type_info_xml() {
        let ti = QueryColumnType::Xml.to_type_info();
        match ti {
            TypeInfo::Xml { schema, .. } => {
                assert!(schema.is_none());
            }
            _ => panic!("Expected Xml"),
        }
    }

    #[test]
    fn test_query_column_new() {
        let col = QueryColumn::new("test_col", QueryColumnType::Int);
        assert_eq!(col.name, "test_col");
        assert!(!col.nullable);
        assert_eq!(col.ty, QueryColumnType::Int);
    }

    #[test]
    fn test_query_column_nullable() {
        let col = QueryColumn::new("nullable_col", QueryColumnType::NVarChar(50)).nullable();
        assert_eq!(col.name, "nullable_col");
        assert!(col.nullable);
    }

    #[test]
    fn test_query_column_into_metadata() {
        let col = QueryColumn::new("meta_col", QueryColumnType::BigInt).nullable();
        let meta = col.into_metadata();

        assert_eq!(meta.col_name, "meta_col");
        assert!(meta.base.flags.contains(ColumnFlag::Nullable));
        match meta.base.ty {
            TypeInfo::VarLenSized(ctx) => {
                assert_eq!(ctx.r#type(), VarLenType::Intn);
                assert_eq!(ctx.len(), 8);
            }
            _ => panic!("Expected VarLenSized"),
        }
    }

    #[test]
    fn test_query_column_into_metadata_not_nullable() {
        let col = QueryColumn::new("not_null", QueryColumnType::Int);
        let meta = col.into_metadata();

        assert!(!meta.base.flags.contains(ColumnFlag::Nullable));
    }
}
