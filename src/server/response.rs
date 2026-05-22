//! Helpers for streaming resultsets efficiently.

use std::borrow::Cow;

use futures_util::sink::SinkExt;

use crate::server::handler::TdsClient;
use crate::server::messages::{BackendToken, TdsBackendMessage};
use crate::tds::codec::{
    BaseMetaDataColumn, BytesMutWithTypeInfo, ColumnData, ColumnFlag, DoneStatus, Encode,
    MetaDataColumn, TokenColMetaData, TokenDone, TokenReturnValue, TokenRow, TokenType, TypeInfo,
    VarLenContext, VarLenType, HEADER_BYTES,
};
use crate::tds::Collation;
use crate::Result;
use bytes::{BufMut, BytesMut};
use enumflags2::BitFlags;

/// Default collation used for string output parameters when none is specified.
///
/// This is SQL_Latin1_General_CP1_CI_AS (LCID 1033, sort ID 52).
const DEFAULT_COLLATION: Collation = Collation::new(13632521, 52);

/// A user-friendly representation of an RPC output parameter.
///
/// This struct provides a convenient way to specify output parameters that will
/// be sent back to the client after an RPC call. The type information is inferred
/// from the value if not explicitly provided.
///
/// # Example
///
/// ```ignore
/// use tiberius::server::OutputParameter;
/// use tiberius::ColumnData;
///
/// // Simple output parameter with inferred type
/// let param = OutputParameter::new("@result", ColumnData::I32(Some(42)));
///
/// // Output parameter with explicit ordinal
/// let param = OutputParameter::new("@count", ColumnData::I64(Some(100)))
///     .with_ordinal(1);
/// ```
#[derive(Debug, Clone)]
pub struct OutputParameter<'a> {
    /// The parameter name (e.g., "@result").
    pub name: Cow<'a, str>,
    /// The parameter value.
    pub value: ColumnData<'a>,
    /// The ordinal position of the parameter (1-based).
    pub ordinal: u16,
    /// Whether this is a user-defined function return value.
    pub udf: bool,
    /// Optional explicit type info. If None, type is inferred from value.
    pub type_info: Option<TypeInfo>,
    /// Optional collation for string types.
    pub collation: Option<Collation>,
}

impl<'a> OutputParameter<'a> {
    /// Create a new output parameter with the given name and value.
    ///
    /// The type information will be inferred from the value.
    pub fn new(name: impl Into<Cow<'a, str>>, value: ColumnData<'a>) -> Self {
        Self {
            name: name.into(),
            value,
            ordinal: 0,
            udf: false,
            type_info: None,
            collation: None,
        }
    }

    /// Set the ordinal position of this parameter.
    pub fn with_ordinal(mut self, ordinal: u16) -> Self {
        self.ordinal = ordinal;
        self
    }

    /// Mark this parameter as a user-defined function return value.
    ///
    /// UDF return values use a different status byte in the TDS protocol.
    pub fn as_udf(mut self) -> Self {
        self.udf = true;
        self
    }

    /// Set explicit type information for this parameter.
    pub fn with_type_info(mut self, type_info: TypeInfo) -> Self {
        self.type_info = Some(type_info);
        self
    }

    /// Set the collation for string types.
    pub fn with_collation(mut self, collation: Collation) -> Self {
        self.collation = Some(collation);
        self
    }

    /// Create an output parameter from a decoded input parameter with a new value.
    ///
    /// This is useful when implementing stored procedures that have output parameters.
    /// The parameter name and type info are taken from the input parameter, while
    /// the value is replaced with the provided new value.
    ///
    /// # Arguments
    ///
    /// * `input` - The decoded RPC parameter from the client request
    /// * `value` - The new value to return to the client
    ///
    /// # Example
    ///
    /// ```ignore
    /// use tiberius::server::{OutputParameter, DecodedRpcParam};
    /// use tiberius::ColumnData;
    ///
    /// // In an RPC handler, create output param from input
    /// let input_param: &DecodedRpcParam = &params[0];
    /// let output = OutputParameter::from_input(input_param, ColumnData::I32(Some(42)));
    /// writer.send_output_param(output).await?;
    /// ```
    pub fn from_input(input: &crate::server::codec::DecodedRpcParam, value: ColumnData<'a>) -> Self {
        Self {
            name: Cow::Owned(input.name.clone()),
            value,
            ordinal: 0,
            udf: false,
            type_info: Some(input.ty.clone()),
            collation: None,
        }
    }

    /// Build the TokenReturnValue for this output parameter.
    ///
    /// Note: This clones string and binary values to produce a 'static version
    /// compatible with TokenReturnValue.
    fn into_token(self) -> TokenReturnValue {
        let collation = self.collation.unwrap_or(DEFAULT_COLLATION);
        let ty = self
            .type_info
            .unwrap_or_else(|| infer_type_info(&self.value, collation));

        let meta = BaseMetaDataColumn {
            user_type: 0,
            flags: BitFlags::from(ColumnFlag::Nullable),
            ty,
            table_name: None,
        };

        // Convert to 'static by cloning any borrowed data.
        // For most ColumnData variants (primitives), this is a no-op.
        // For Cow types (String, Binary, Xml, Udt), this produces an Owned variant.
        let static_value = column_data_into_static(self.value);

        TokenReturnValue {
            param_ordinal: self.ordinal,
            param_name: self.name.into_owned(),
            udf: self.udf,
            meta,
            value: static_value,
        }
    }
}

/// Convert a ColumnData with any lifetime to a 'static version.
///
/// This function clones borrowed data (strings, binary, etc.) to produce
/// owned values that have a 'static lifetime.
fn column_data_into_static(value: ColumnData<'_>) -> ColumnData<'static> {
    match value {
        // Primitive types - no lifetime data
        ColumnData::U8(v) => ColumnData::U8(v),
        ColumnData::I16(v) => ColumnData::I16(v),
        ColumnData::I32(v) => ColumnData::I32(v),
        ColumnData::I64(v) => ColumnData::I64(v),
        ColumnData::F32(v) => ColumnData::F32(v),
        ColumnData::F64(v) => ColumnData::F64(v),
        ColumnData::Bit(v) => ColumnData::Bit(v),
        ColumnData::Guid(v) => ColumnData::Guid(v),
        ColumnData::Numeric(v) => ColumnData::Numeric(v),
        ColumnData::DateTime(v) => ColumnData::DateTime(v),
        ColumnData::SmallDateTime(v) => ColumnData::SmallDateTime(v),
        ColumnData::Time(v) => ColumnData::Time(v),
        ColumnData::Date(v) => ColumnData::Date(v),
        ColumnData::DateTime2(v) => ColumnData::DateTime2(v),
        ColumnData::DateTimeOffset(v) => ColumnData::DateTimeOffset(v),

        // Cow types - convert to owned
        ColumnData::String(s) => {
            ColumnData::String(s.map(|cow| Cow::Owned(cow.into_owned())))
        }
        ColumnData::Binary(b) => {
            ColumnData::Binary(b.map(|cow| Cow::Owned(cow.into_owned())))
        }
        ColumnData::Xml(x) => {
            ColumnData::Xml(x.map(|cow| Cow::Owned(cow.into_owned())))
        }
        ColumnData::Udt(u) => {
            ColumnData::Udt(u.map(|cow| Cow::Owned(cow.into_owned())))
        }
        ColumnData::Variant(v) => {
            ColumnData::Variant(v.map(|var| var.into_owned()))
        }
        ColumnData::Tvp(t) => {
            ColumnData::Tvp(t.map(|tvp| tvp_data_into_static(tvp)))
        }
    }
}

/// Convert TvpData to a 'static version.
fn tvp_data_into_static(tvp: crate::tds::codec::TvpData<'_>) -> crate::tds::codec::TvpData<'static> {
    crate::tds::codec::TvpData {
        db_name: Cow::Owned(tvp.db_name.into_owned()),
        schema: Cow::Owned(tvp.schema.into_owned()),
        type_name: Cow::Owned(tvp.type_name.into_owned()),
        columns: tvp
            .columns
            .into_iter()
            .map(|col| crate::tds::codec::TvpColumn {
                name: Cow::Owned(col.name.into_owned()),
                user_type: col.user_type,
                flags: col.flags,
                ty: col.ty,
            })
            .collect(),
        rows: tvp
            .rows
            .into_iter()
            .map(|row| row.into_iter().map(column_data_into_static).collect())
            .collect(),
    }
}

/// Infer TypeInfo from a ColumnData value.
///
/// This function examines the ColumnData variant and produces an appropriate
/// TypeInfo for encoding. For nullable types, a reasonable default size is used.
/// String types use the provided collation.
///
/// # Arguments
///
/// * `value` - The column data to infer type from
/// * `collation` - The collation to use for string types
///
/// # Returns
///
/// The inferred TypeInfo suitable for encoding the value.
pub fn infer_type_info(value: &ColumnData<'_>, collation: Collation) -> TypeInfo {
    match value {
        ColumnData::U8(_) => TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 1, None)),
        ColumnData::I16(_) => TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 2, None)),
        ColumnData::I32(_) => TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 4, None)),
        ColumnData::I64(_) => TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 8, None)),
        ColumnData::F32(_) => TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Floatn, 4, None)),
        ColumnData::F64(_) => TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Floatn, 8, None)),
        ColumnData::Bit(_) => TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Bitn, 1, None)),
        ColumnData::String(s) => {
            // Use NVARCHAR with appropriate length
            // Use saturating_mul to prevent overflow on extremely large strings
            let len = s
                .as_ref()
                .map(|s| s.len().saturating_mul(2)) // UTF-16 encoding
                .unwrap_or(0);
            // Use max if > 4000 chars (8000 bytes), otherwise use actual length or default
            let type_len = if len > 8000 { 0xFFFF } else { std::cmp::max(len, 8000) };
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::NVarchar,
                type_len,
                Some(collation),
            ))
        }
        ColumnData::Guid(_) => {
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Guid, 16, None))
        }
        ColumnData::Binary(b) => {
            let len = b.as_ref().map(|b| b.len()).unwrap_or(0);
            // Use max if > 8000, otherwise use actual length or default
            let type_len = if len > 8000 { 0xFFFF } else { std::cmp::max(len, 8000) };
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigVarBin, type_len, None))
        }
        ColumnData::Numeric(n) => {
            let (precision, scale) = n
                .as_ref()
                .map(|n| (n.precision(), n.scale()))
                .unwrap_or((18, 0));
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
        ColumnData::Xml(_) => TypeInfo::Xml {
            schema: None,
            size: 0xfffffffffffffffe_usize,
        },
        ColumnData::DateTime(_) => {
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Datetimen, 8, None))
        }
        ColumnData::SmallDateTime(_) => {
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Datetimen, 4, None))
        }
        ColumnData::Time(t) => {
            let scale = t.as_ref().map(|t| t.scale()).unwrap_or(7);
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Timen, scale as usize, None))
        }
        ColumnData::Date(_) => {
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Daten, 3, None))
        }
        ColumnData::DateTime2(dt2) => {
            let scale = dt2.as_ref().map(|dt| dt.time().scale()).unwrap_or(7);
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::Datetime2,
                scale as usize,
                None,
            ))
        }
        ColumnData::DateTimeOffset(dto) => {
            let scale = dto
                .as_ref()
                .map(|dt| dt.datetime2().time().scale())
                .unwrap_or(7);
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::DatetimeOffsetn,
                scale as usize,
                None,
            ))
        }
        ColumnData::Udt(u) => {
            let len = u.as_ref().map(|b| b.len()).unwrap_or(0);
            let type_len = if len > 8000 { 0xFFFF } else { std::cmp::max(len, 8000) };
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigVarBin, type_len, None))
        }
        ColumnData::Variant(_) => TypeInfo::SsVariant(crate::tds::codec::SsVariantInfo { max_len: 8016 }),
        ColumnData::Tvp(_) => TypeInfo::Tvp(crate::tds::codec::TvpInfo {
            db_name: String::new(),
            schema: String::new(),
            type_name: String::new(),
        }),
    }
}

/// A lightweight resultset writer that streams tokens directly to the client.
///
/// This keeps row encoding incremental and avoids buffering full resultsets,
/// which aligns well with Arrow batch producers.
pub struct ResultSetWriter<'a, C> {
    client: &'a mut C,
    columns: Vec<MetaDataColumn<'static>>,
}

impl<'a, C> ResultSetWriter<'a, C>
where
    C: TdsClient,
{
    /// Start a new resultset and send column metadata.
    pub async fn start(client: &'a mut C, columns: Vec<MetaDataColumn<'static>>) -> Result<Self> {
        let token = TokenColMetaData {
            columns: columns.clone(),
        };
        client
            .send(TdsBackendMessage::TokenPartial(BackendToken::ColMetaData(token)))
            .await?;

        Ok(Self { client, columns })
    }

    /// Send a single row.
    pub async fn send_row(&mut self, row: TokenRow<'static>) -> Result<()> {
        let _ = &self.columns;
        self.client
            .send(TdsBackendMessage::TokenPartial(BackendToken::Row(row)))
            .await
    }

    /// Send a single row using NBCROW (null bitmap compression).
    pub async fn send_row_nbc(&mut self, row: TokenRow<'static>) -> Result<()> {
        let _ = &self.columns;
        self.client
            .send(TdsBackendMessage::TokenPartial(BackendToken::NbcRow(row)))
            .await
    }

    /// Send a single row from an iterator of column data.
    pub async fn send_row_iter<I>(&mut self, values: I) -> Result<()>
    where
        I: IntoIterator<Item = ColumnData<'static>>,
    {
        let mut row = TokenRow::with_capacity(self.columns.len());
        for value in values {
            row.push(value);
        }
        self.send_row(row).await
    }

    /// Send a single row (NBCROW) from an iterator of column data.
    pub async fn send_row_iter_nbc<I>(&mut self, values: I) -> Result<()>
    where
        I: IntoIterator<Item = ColumnData<'static>>,
    {
        let mut row = TokenRow::with_capacity(self.columns.len());
        for value in values {
            row.push(value);
        }
        self.send_row_nbc(row).await
    }

    /// Poll for an attention/cancel signal while streaming results.
    pub async fn poll_attention(&mut self) -> Result<bool> {
        self.client.poll_attention().await
    }

    /// Send a row only if no attention/cancel has been observed.
    pub async fn send_row_iter_checked<I>(&mut self, values: I) -> Result<bool>
    where
        I: IntoIterator<Item = ColumnData<'static>>,
    {
        if self.poll_attention().await? {
            return Ok(false);
        }
        self.send_row_iter(values).await?;
        Ok(true)
    }

    /// Send a row (NBCROW) only if no attention/cancel has been observed.
    pub async fn send_row_iter_nbc_checked<I>(&mut self, values: I) -> Result<bool>
    where
        I: IntoIterator<Item = ColumnData<'static>>,
    {
        if self.poll_attention().await? {
            return Ok(false);
        }
        self.send_row_iter_nbc(values).await?;
        Ok(true)
    }

    /// Send a row (NBCROW) from borrowed values without allocating a TokenRow.
    pub async fn send_row_values_nbc<'b, I>(&mut self, values: I) -> Result<()>
    where
        I: IntoIterator<Item = ColumnData<'b>>,
    {
        let mut row = TokenRow::with_capacity(self.columns.len());
        for value in values {
            row.push(value);
        }

        let mut payload = BytesMut::new();
        row.encode_nbc_with_columns(&mut payload, &self.columns)?;
        self.client
            .send(TdsBackendMessage::TokenBytesPartial(payload))
            .await
    }

    /// Send a row (NBCROW) from borrowed values only if no attention/cancel has been observed.
    pub async fn send_row_values_nbc_checked<'b, I>(&mut self, values: I) -> Result<bool>
    where
        I: IntoIterator<Item = ColumnData<'b>>,
    {
        if self.poll_attention().await? {
            return Ok(false);
        }
        self.send_row_values_nbc(values).await?;
        Ok(true)
    }

    /// Send a row from borrowed values only if no attention/cancel has been observed.
    pub async fn send_row_values_checked<'b, I>(&mut self, values: I) -> Result<bool>
    where
        I: IntoIterator<Item = ColumnData<'b>>,
    {
        if self.poll_attention().await? {
            return Ok(false);
        }
        self.send_row_values(values).await?;
        Ok(true)
    }

    /// Send a row from borrowed values without allocating a TokenRow.
    ///
    /// This is a better fit for columnar sources like Arrow because values
    /// can borrow directly from column buffers and are encoded immediately.
    pub async fn send_row_values<'b, I>(&mut self, values: I) -> Result<()>
    where
        I: IntoIterator<Item = ColumnData<'b>>,
    {
        let mut row = TokenRow::with_capacity(self.columns.len());
        for value in values {
            row.push(value);
        }

        let mut payload = BytesMut::new();
        row.encode_with_columns(&mut payload, &self.columns)?;
        self.client
            .send(TdsBackendMessage::TokenBytesPartial(payload))
            .await
    }

    /// Send a row from borrowed values, flushing chunks as the buffer grows.
    ///
    /// This avoids per-row buffering for large values by streaming chunks to the wire.
    pub async fn send_row_values_streaming<'b, I>(&mut self, values: I) -> Result<()>
    where
        I: IntoIterator<Item = ColumnData<'b>>,
    {
        let max_payload = (self.client.packet_size() as usize).saturating_sub(HEADER_BYTES);
        let chunk_size = std::cmp::max(256, max_payload);
        self.send_row_values_chunked(values, chunk_size).await
    }

    /// Send a row from borrowed values with a custom chunk size.
    pub async fn send_row_values_chunked<'b, I>(
        &mut self,
        values: I,
        chunk_size: usize,
    ) -> Result<()>
    where
        I: IntoIterator<Item = ColumnData<'b>>,
    {
        let chunk_size = std::cmp::max(1, chunk_size);
        let mut iter = values.into_iter();
        let mut payload = BytesMut::new();
        payload.put_u8(TokenType::Row as u8);

        for column in &self.columns {
            let value = iter.next().ok_or_else(|| {
                crate::Error::BulkInput(
                    format!(
                        "Expecting {} columns but fewer values were given",
                        self.columns.len()
                    )
                    .into(),
                )
            })?;
            let mut dst_ti = BytesMutWithTypeInfo::new(&mut payload).with_type_info(&column.base.ty);
            value.encode(&mut dst_ti)?;
            while payload.len() >= chunk_size {
                let chunk = payload.split_to(chunk_size);
                if !chunk.is_empty() {
                    self.client
                        .send(TdsBackendMessage::TokenBytesPartial(chunk))
                        .await?;
                }
            }
        }

        if iter.next().is_some() {
            return Err(crate::Error::BulkInput(
                format!(
                    "Expecting {} columns but more values were given",
                    self.columns.len()
                )
                .into(),
            ));
        }

        if !payload.is_empty() {
            self.client
                .send(TdsBackendMessage::TokenBytesPartial(payload))
                .await?;
        }

        Ok(())
    }

    /// Send a batch of rows using a columnar accessor.
    ///
    /// The accessor should provide a value for each (row, col) pair.
    pub async fn send_batch_rows<'b, F>(
        &mut self,
        rows: usize,
        mut value_at: F,
    ) -> Result<()>
    where
        F: FnMut(usize, usize) -> ColumnData<'b>,
    {
        let mut payload = BytesMut::new();
        for row_idx in 0..rows {
            let mut row = TokenRow::with_capacity(self.columns.len());
            for col_idx in 0..self.columns.len() {
                row.push(value_at(row_idx, col_idx));
            }
            row.encode_with_columns(&mut payload, &self.columns)?;
        }

        self.client
            .send(TdsBackendMessage::TokenBytesPartial(payload))
            .await
    }

    /// Send a batch of rows, stopping early if attention/cancel is observed.
    ///
    /// Returns the number of rows sent before attention was seen.
    pub async fn send_batch_rows_checked<'b, F>(
        &mut self,
        rows: usize,
        mut value_at: F,
    ) -> Result<usize>
    where
        F: FnMut(usize, usize) -> ColumnData<'b>,
    {
        let mut payload = BytesMut::new();
        let mut sent = 0usize;

        for row_idx in 0..rows {
            if self.poll_attention().await? {
                break;
            }
            let mut row = TokenRow::with_capacity(self.columns.len());
            for col_idx in 0..self.columns.len() {
                row.push(value_at(row_idx, col_idx));
            }
            row.encode_with_columns(&mut payload, &self.columns)?;
            sent += 1;
        }

        if sent > 0 {
            self.client
                .send(TdsBackendMessage::TokenBytesPartial(payload))
                .await?;
        }

        Ok(sent)
    }

    /// Send a batch of rows using NBCROW encoding.
    pub async fn send_batch_rows_nbc<'b, F>(
        &mut self,
        rows: usize,
        mut value_at: F,
    ) -> Result<()>
    where
        F: FnMut(usize, usize) -> ColumnData<'b>,
    {
        let mut payload = BytesMut::new();
        for row_idx in 0..rows {
            let mut row = TokenRow::with_capacity(self.columns.len());
            for col_idx in 0..self.columns.len() {
                row.push(value_at(row_idx, col_idx));
            }
            row.encode_nbc_with_columns(&mut payload, &self.columns)?;
        }

        self.client
            .send(TdsBackendMessage::TokenBytesPartial(payload))
            .await
    }

    /// Send a batch of rows using NBCROW, stopping early if attention/cancel is observed.
    ///
    /// Returns the number of rows sent before attention was seen.
    pub async fn send_batch_rows_nbc_checked<'b, F>(
        &mut self,
        rows: usize,
        mut value_at: F,
    ) -> Result<usize>
    where
        F: FnMut(usize, usize) -> ColumnData<'b>,
    {
        let mut payload = BytesMut::new();
        let mut sent = 0usize;

        for row_idx in 0..rows {
            if self.poll_attention().await? {
                break;
            }
            let mut row = TokenRow::with_capacity(self.columns.len());
            for col_idx in 0..self.columns.len() {
                row.push(value_at(row_idx, col_idx));
            }
            row.encode_nbc_with_columns(&mut payload, &self.columns)?;
            sent += 1;
        }

        if sent > 0 {
            self.client
                .send(TdsBackendMessage::TokenBytesPartial(payload))
                .await?;
        }

        Ok(sent)
    }

    /// Finish the resultset with a DONE token.
    pub async fn finish(self, rows: u64) -> Result<()> {
        let done = TokenDone::with_rows(rows);
        self.client
            .send(TdsBackendMessage::Token(BackendToken::Done(done)))
            .await
    }

    /// Finish the resultset with a custom DONE token.
    pub async fn finish_with_done(self, done: TokenDone) -> Result<()> {
        self.client
            .send(TdsBackendMessage::Token(BackendToken::Done(done)))
            .await
    }

    /// Finish the resultset indicating more results will follow.
    pub async fn finish_more(self, rows: u64) -> Result<()> {
        self.finish_with_done(TokenDone::with_more_rows(rows)).await
    }

    /// Finish the resultset with a DONEINPROC token (DONE_MORE set for a following DONEPROC).
    pub async fn finish_in_proc(self, rows: u64) -> Result<()> {
        let done = TokenDone::with_more_rows(rows);
        self.client
            .send(TdsBackendMessage::Token(BackendToken::DoneInProc(done)))
            .await
    }

    /// Finish the resultset with a DONEINPROC token indicating more results will follow.
    pub async fn finish_more_in_proc(self, rows: u64) -> Result<()> {
        let done = TokenDone::with_more_rows(rows);
        self.client
            .send(TdsBackendMessage::Token(BackendToken::DoneInProc(done)))
            .await
    }

    /// Finish the resultset with a DONE token indicating attention/cancel.
    pub async fn finish_attention(self, rows: u64) -> Result<()> {
        let done = TokenDone::with_status(DoneStatus::Attention | DoneStatus::Count, rows);
        self.finish_with_done(done).await
    }

    /// Finish the resultset with DONEATTENTION and reset attention state.
    ///
    /// The state transition to ReadyForQuery is handled automatically by the
    /// Done token encoding when it detects the Attention status bit.
    pub async fn finish_attention_and_ready(self, rows: u64) -> Result<()> {
        let done = TokenDone::with_status(DoneStatus::Attention | DoneStatus::Count, rows);
        self.client
            .send(TdsBackendMessage::Token(BackendToken::Done(done)))
            .await?;
        // Note: clear_attention() and state transition are handled in encode_done_token
        // when it detects the Attention status on the Done token.
        Ok(())
    }

    /// Finish the resultset, sending DONEATTENTION if attention/cancel was observed.
    ///
    /// Returns true if attention was handled.
    pub async fn finish_or_attention(mut self, rows: u64) -> Result<bool> {
        if self.poll_attention().await? {
            self.finish_attention_and_ready(rows).await?;
            Ok(true)
        } else {
            let done = TokenDone::with_rows(rows);
            self.client
                .send(TdsBackendMessage::Token(BackendToken::Done(done)))
                .await?;
            Ok(false)
        }
    }

    // -------------------------------------------------------------------------
    // RPC Output Parameter Support
    // -------------------------------------------------------------------------

    /// Send a single output parameter to the client.
    ///
    /// This sends a RETURNVALUE token with the parameter name, type, and value.
    /// Use this after sending any result sets but before the DONEPROC token.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use tiberius::server::{OutputParameter, ResultSetWriter};
    /// use tiberius::ColumnData;
    ///
    /// // After sending result sets...
    /// let param = OutputParameter::new("@output", ColumnData::I32(Some(42)))
    ///     .with_ordinal(1);
    /// writer.send_output_param(param).await?;
    /// ```
    pub async fn send_output_param(&mut self, param: OutputParameter<'_>) -> Result<()> {
        let token = param.into_token();
        self.client
            .send(TdsBackendMessage::TokenPartial(BackendToken::ReturnValue(
                token,
            )))
            .await
    }

    /// Send multiple output parameters to the client.
    ///
    /// This is a convenience method that sends multiple RETURNVALUE tokens.
    /// Parameters are sent in order with ordinals assigned sequentially starting from 1
    /// if not already set (ordinal == 0 is treated as "auto-assign").
    ///
    /// # Ordinal Assignment
    ///
    /// If a parameter's ordinal is 0, it will be automatically assigned based on its
    /// position in the iterator (1-based). If you need specific ordinals, set them
    /// explicitly using [`OutputParameter::with_ordinal`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// use tiberius::server::{OutputParameter, ResultSetWriter};
    /// use tiberius::ColumnData;
    ///
    /// let params = vec![
    ///     OutputParameter::new("@result", ColumnData::I32(Some(42))),
    ///     OutputParameter::new("@message", ColumnData::String(Some("Success".into()))),
    /// ];
    /// writer.send_output_params(params).await?;
    /// ```
    pub async fn send_output_params<'b, I>(&mut self, params: I) -> Result<()>
    where
        I: IntoIterator<Item = OutputParameter<'b>>,
    {
        for (idx, mut param) in params.into_iter().enumerate() {
            if param.ordinal == 0 {
                // Saturate at u16::MAX to prevent overflow (unlikely in practice)
                param.ordinal = ((idx + 1).min(u16::MAX as usize)) as u16;
            }
            self.send_output_param(param).await?;
        }
        Ok(())
    }

    /// Send a procedure return status to the client.
    ///
    /// This sends a RETURNSTATUS token indicating the return code of the stored
    /// procedure. A return status of 0 typically indicates success.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Send return status indicating success
    /// writer.send_return_status(0).await?;
    ///
    /// // Send return status indicating an error
    /// writer.send_return_status(-1).await?;
    /// ```
    pub async fn send_return_status(&mut self, status: i32) -> Result<()> {
        // ReturnStatus is encoded as u32 but represents i32
        self.client
            .send(TdsBackendMessage::TokenPartial(BackendToken::ReturnStatus(
                status as u32,
            )))
            .await
    }

    /// Finish an RPC call with a DONEPROC token.
    ///
    /// This should be called after sending all result sets, output parameters,
    /// and the return status. It signals the end of the RPC response.
    ///
    /// # Arguments
    ///
    /// * `rows` - The total number of rows affected by the procedure
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Complete the RPC response
    /// writer.send_return_status(0).await?;
    /// writer.finish_proc(10).await?;
    /// ```
    pub async fn finish_proc(self, rows: u64) -> Result<()> {
        let done = TokenDone::with_rows(rows);
        self.client
            .send(TdsBackendMessage::Token(BackendToken::DoneProc(done)))
            .await
    }

    /// Finish an RPC call with a DONEPROC token indicating more results will follow.
    ///
    /// Use this when the client has sent multiple RPC calls in a batch and this
    /// is not the last one.
    ///
    /// # Arguments
    ///
    /// * `rows` - The total number of rows affected by this procedure
    pub async fn finish_proc_more(self, rows: u64) -> Result<()> {
        let done = TokenDone::with_more_rows(rows);
        self.client
            .send(TdsBackendMessage::Token(BackendToken::DoneProc(done)))
            .await
    }

    /// Consume the writer and return the underlying client reference.
    ///
    /// This is useful when you need to send additional tokens after the result set
    /// but before finishing with a DONE token, such as output parameters or return
    /// status for RPC calls.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let writer = ResultSetWriter::start(client, columns).await?;
    /// // ... send rows ...
    /// writer.finish_in_proc(row_count).await?;
    ///
    /// // Now use standalone functions for output params
    /// send_return_status(client, 0).await?;
    /// finish_proc(client, 0).await?;
    /// ```
    pub fn into_client(self) -> &'a mut C {
        self.client
    }
}

// =============================================================================
// Standalone RPC Helper Functions
// =============================================================================
//
// These functions are useful when the ResultSetWriter has been consumed (e.g.,
// after calling finish_in_proc) and you still need to send output parameters
// or complete the RPC response.

/// Send a single output parameter to the client.
///
/// This is a standalone version of [`ResultSetWriter::send_output_param`] for use
/// when the writer has been consumed.
///
/// # Example
///
/// ```ignore
/// use tiberius::server::{send_output_param, OutputParameter};
/// use tiberius::ColumnData;
///
/// let param = OutputParameter::new("@result", ColumnData::I32(Some(42)))
///     .with_ordinal(1);
/// send_output_param(client, param).await?;
/// ```
pub async fn send_output_param<C>(client: &mut C, param: OutputParameter<'_>) -> Result<()>
where
    C: TdsClient,
{
    let token = param.into_token();
    client
        .send(TdsBackendMessage::TokenPartial(BackendToken::ReturnValue(
            token,
        )))
        .await
}

/// Send multiple output parameters to the client.
///
/// This is a standalone version of [`ResultSetWriter::send_output_params`] for use
/// when the writer has been consumed.
///
/// Parameters are sent in order with ordinals assigned sequentially starting from 1
/// if not already set (ordinal == 0 is treated as "auto-assign").
pub async fn send_output_params<'a, C, I>(client: &mut C, params: I) -> Result<()>
where
    C: TdsClient,
    I: IntoIterator<Item = OutputParameter<'a>>,
{
    for (idx, mut param) in params.into_iter().enumerate() {
        if param.ordinal == 0 {
            // Saturate at u16::MAX to prevent overflow (unlikely in practice)
            param.ordinal = ((idx + 1).min(u16::MAX as usize)) as u16;
        }
        send_output_param(client, param).await?;
    }
    Ok(())
}

/// Send a procedure return status to the client.
///
/// This is a standalone version of [`ResultSetWriter::send_return_status`] for use
/// when the writer has been consumed.
///
/// # Example
///
/// ```ignore
/// use tiberius::server::send_return_status;
///
/// // Send return status indicating success
/// send_return_status(client, 0).await?;
/// ```
pub async fn send_return_status<C>(client: &mut C, status: i32) -> Result<()>
where
    C: TdsClient,
{
    // ReturnStatus is encoded as u32 but represents i32
    client
        .send(TdsBackendMessage::TokenPartial(BackendToken::ReturnStatus(
            status as u32,
        )))
        .await
}

/// Finish an RPC call with a DONEPROC token.
///
/// This is a standalone version of [`ResultSetWriter::finish_proc`] for use
/// when the writer has been consumed.
///
/// # Arguments
///
/// * `client` - The client connection
/// * `rows` - The total number of rows affected by the procedure
///
/// # Example
///
/// ```ignore
/// use tiberius::server::finish_proc;
///
/// // After sending result sets and output params via standalone functions
/// finish_proc(client, 10).await?;
/// ```
pub async fn finish_proc<C>(client: &mut C, rows: u64) -> Result<()>
where
    C: TdsClient,
{
    let done = TokenDone::with_rows(rows);
    client
        .send(TdsBackendMessage::Token(BackendToken::DoneProc(done)))
        .await
}

/// Finish an RPC call with a DONEPROC token indicating more results will follow.
///
/// This is a standalone version of [`ResultSetWriter::finish_proc_more`] for use
/// when the writer has been consumed.
///
/// Use this when the client has sent multiple RPC calls in a batch and this
/// is not the last one.
///
/// # Arguments
///
/// * `client` - The client connection
/// * `rows` - The total number of rows affected by this procedure
pub async fn finish_proc_more<C>(client: &mut C, rows: u64) -> Result<()>
where
    C: TdsClient,
{
    let done = TokenDone::with_more_rows(rows);
    client
        .send(TdsBackendMessage::Token(BackendToken::DoneProc(done)))
        .await
}
