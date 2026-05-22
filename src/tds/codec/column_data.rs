mod binary;
mod bit;
mod bytes_mut_with_type_info;
mod date;
mod datetime2;
mod datetimen;
mod datetimeoffsetn;
mod fixed_len;
mod float;
mod guid;
mod image;
mod int;
mod money;
mod plp;
mod string;
mod text;
mod time;
mod var_len;
mod xml;

use super::{Encode, FixedLenType, TypeInfo, VarLenContext, VarLenType};
use crate::tds::time::{Date, DateTime2, DateTimeOffset, Time};
use crate::{
    tds::{time::DateTime, time::SmallDateTime, xml::XmlData, Collation, Numeric},
    SqlReadBytes,
};
use enumflags2::BitFlags;
use bytes::{Buf, BufMut, BytesMut};
pub(crate) use bytes_mut_with_type_info::BytesMutWithTypeInfo;
use std::borrow::{BorrowMut, Cow};
use std::future::Future;
use std::pin::Pin;
use std::task::Poll;
use uuid::Uuid;
use crate::tds::Context;
use futures_util::io::{AsyncRead, AsyncReadExt};

const MAX_NVARCHAR_SIZE: usize = 1 << 30;

#[derive(Clone, Debug, PartialEq)]
/// A container of a value that can be represented as a TDS value.
pub enum ColumnData<'a> {
    /// 8-bit integer, unsigned.
    U8(Option<u8>),
    /// 16-bit integer, signed.
    I16(Option<i16>),
    /// 32-bit integer, signed.
    I32(Option<i32>),
    /// 64-bit integer, signed.
    I64(Option<i64>),
    /// 32-bit floating point number.
    F32(Option<f32>),
    /// 64-bit floating point number.
    F64(Option<f64>),
    /// Boolean.
    Bit(Option<bool>),
    /// A string value.
    String(Option<Cow<'a, str>>),
    /// A Guid (UUID) value.
    Guid(Option<Uuid>),
    /// Binary data.
    Binary(Option<Cow<'a, [u8]>>),
    /// Numeric value (a decimal).
    Numeric(Option<Numeric>),
    /// XML data.
    Xml(Option<Cow<'a, XmlData>>),
    /// DateTime value.
    DateTime(Option<DateTime>),
    /// A small DateTime value.
    SmallDateTime(Option<SmallDateTime>),
    /// Time value.
    Time(Option<Time>),
    /// Date value.
    Date(Option<Date>),
    /// DateTime2 value.
    DateTime2(Option<DateTime2>),
    /// DateTime2 value with an offset.
    DateTimeOffset(Option<DateTimeOffset>),
    /// User-defined type payload.
    Udt(Option<Cow<'a, [u8]>>),
    /// SQL variant payload.
    Variant(Option<VariantData<'a>>),
    /// Table-valued parameter payload.
    Tvp(Option<TvpData<'a>>),
}

/// Opaque CLR user-defined type payload.
///
/// This is distinct from normal SQL binary data. Use it to read UDT columns
/// such as `hierarchyid` as raw serialized bytes while inspecting type
/// metadata through [`Column::udt_info`].
///
/// # Example
///
/// ```no_run
/// # use tiberius::{Client, Config, UdtData};
/// # use tokio::net::TcpStream;
/// # use tokio_util::compat::TokioAsyncWriteCompatExt;
/// # #[tokio::main]
/// # async fn main() -> anyhow::Result<()> {
/// # let config = Config::from_ado_string(
/// #     "server=tcp:localhost,1433;IntegratedSecurity=true;TrustServerCertificate=true",
/// # )?;
/// # let tcp = TcpStream::connect(config.get_addr()).await?;
/// # tcp.set_nodelay(true)?;
/// # let mut client = Client::connect(config, tcp.compat_write()).await?;
/// let row = client
///     .query("SELECT CAST('/1/2/' AS hierarchyid) AS hid", &[])
///     .await?
///     .into_row()
///     .await?
///     .unwrap();
///
/// let hid: Option<UdtData<'_>> = row.get("hid");
/// assert!(hid.as_ref().map(UdtData::as_bytes).is_some());
///
/// let info = row.columns()[0].udt_info().unwrap();
/// assert_eq!(info.type_name, "hierarchyid");
/// # Ok(())
/// # }
/// ```
///
/// [`Column::udt_info`]: crate::Column::udt_info
#[derive(Clone, Debug, PartialEq)]
pub struct UdtData<'a> {
    bytes: Cow<'a, [u8]>,
}

/// Opaque sql_variant payload (base type + prop bytes + value bytes).
#[derive(Clone, Debug, PartialEq)]
pub struct VariantData<'a> {
    payload: Cow<'a, [u8]>,
}

/// Table-valued parameter column metadata.
#[derive(Clone, Debug, PartialEq)]
pub struct TvpColumn<'a> {
    pub name: Cow<'a, str>,
    pub user_type: u32,
    pub flags: BitFlags<crate::tds::codec::ColumnFlag>,
    pub ty: TypeInfo,
}

/// Table-valued parameter payload (metadata + rows).
///
/// When used as an RPC parameter (via [`ToSql`]/[`IntoSql`]), the `type_name`
/// field must be set to the name of the table type on the server (e.g.
/// `"dbo.MyTableType"`). The `schema` and `db_name` fields are optional.
///
/// # Example
///
/// ```
/// use tiberius::{TvpData, TvpColumn, ColumnData, ColumnFlag, TypeInfo, VarLenContext, VarLenType};
/// use enumflags2::BitFlags;
/// use std::borrow::Cow;
///
/// let tvp = TvpData::new("MyTableType")
///     .schema("dbo")
///     .columns(vec![
///         TvpColumn {
///             name: Cow::Borrowed("id"),
///             user_type: 0,
///             flags: BitFlags::from(ColumnFlag::Nullable),
///             ty: TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 4, None)),
///         },
///     ])
///     .rows(vec![
///         vec![ColumnData::I32(Some(1))],
///     ]);
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct TvpData<'a> {
    /// The database name (typically empty for RPC parameters).
    pub db_name: Cow<'a, str>,
    /// The schema name (e.g. `"dbo"`).
    pub schema: Cow<'a, str>,
    /// The server-side table type name (e.g. `"MyTableType"`).
    pub type_name: Cow<'a, str>,
    /// Column definitions.
    pub columns: Vec<TvpColumn<'a>>,
    /// Row data.
    pub rows: Vec<Vec<ColumnData<'a>>>,
}

impl<'a> TvpData<'a> {
    /// Create a new TVP with the given type name (required for RPC parameters).
    pub fn new(type_name: impl Into<Cow<'a, str>>) -> Self {
        Self {
            db_name: Cow::Borrowed(""),
            schema: Cow::Borrowed(""),
            type_name: type_name.into(),
            columns: Vec::new(),
            rows: Vec::new(),
        }
    }

    /// Set the schema name.
    pub fn schema(mut self, schema: impl Into<Cow<'a, str>>) -> Self {
        self.schema = schema.into();
        self
    }

    /// Set the database name.
    pub fn db_name(mut self, db_name: impl Into<Cow<'a, str>>) -> Self {
        self.db_name = db_name.into();
        self
    }

    /// Set the column definitions.
    pub fn columns(mut self, columns: Vec<TvpColumn<'a>>) -> Self {
        self.columns = columns;
        self
    }

    /// Set the row data.
    pub fn rows(mut self, rows: Vec<Vec<ColumnData<'a>>>) -> Self {
        self.rows = rows;
        self
    }
}

impl<'a> UdtData<'a> {
    /// Create a new UDT payload from raw serialized bytes.
    pub fn new(bytes: impl Into<Cow<'a, [u8]>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    /// Return the raw serialized UDT bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// Convert the payload into an owned `'static` value.
    pub fn into_owned(self) -> UdtData<'static> {
        UdtData {
            bytes: Cow::Owned(self.bytes.into_owned()),
        }
    }
}

impl AsRef<[u8]> for UdtData<'_> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<'a> VariantData<'a> {
    pub fn new(payload: impl Into<Cow<'a, [u8]>>) -> Self {
        Self {
            payload: payload.into(),
        }
    }

    pub fn payload(&self) -> &[u8] {
        self.payload.as_ref()
    }

    /// Build a typed sql_variant payload from a base type and value.
    pub fn from_typed(
        ty: TypeInfo,
        value: ColumnData<'_>,
    ) -> crate::Result<VariantData<'static>> {
        let payload = encode_variant_payload(ty, value)?;
        Ok(VariantData::new(payload))
    }

    /// Decode the variant payload into its base type and value.
    pub async fn decode_typed(&self) -> crate::Result<(TypeInfo, ColumnData<'static>)> {
        decode_variant_payload(self.payload()).await
    }

    pub fn into_owned(self) -> VariantData<'static> {
        VariantData {
            payload: Cow::Owned(self.payload.into_owned()),
        }
    }
}

struct VariantReader {
    buf: BytesMut,
    context: Context,
}

impl VariantReader {
    fn new(buf: BytesMut) -> Self {
        Self {
            buf,
            context: Context::new(),
        }
    }

    fn remaining(&self) -> usize {
        self.buf.len()
    }
}

impl AsyncRead for VariantReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let size = buf.len();

        if this.buf.len() < size {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "sql_variant: unexpected eof",
            )));
        }

        buf.copy_from_slice(this.buf.split_to(size).as_ref());
        Poll::Ready(Ok(size))
    }
}

impl SqlReadBytes for VariantReader {
    fn debug_buffer(&self) {}

    fn context(&self) -> &Context {
        &self.context
    }

    fn context_mut(&mut self) -> &mut Context {
        &mut self.context
    }
}

fn split_variant_payload(payload: &[u8]) -> crate::Result<(u8, &[u8], &[u8])> {
    if payload.len() < 2 {
        return Err(crate::Error::Protocol(
            "sql_variant payload too short".into(),
        ));
    }

    let base_type = payload[0];
    let prop_len = payload[1] as usize;
    if payload.len() < 2 + prop_len {
        return Err(crate::Error::Protocol(
            "sql_variant payload missing property bytes".into(),
        ));
    }

    let prop_bytes = &payload[2..2 + prop_len];
    let value_bytes = &payload[2 + prop_len..];
    Ok((base_type, prop_bytes, value_bytes))
}

fn rescale_time(time: Time, target_scale: u8) -> crate::Result<Time> {
    if target_scale > 7 {
        return Err(crate::Error::Protocol(
            format!("timen: invalid scale {}", target_scale).into(),
        ));
    }
    if time.scale() == target_scale {
        return Ok(time);
    }

    let pow = target_scale as i32 - time.scale() as i32;
    let increments = (time.increments() as f64 * 10_f64.powi(pow)) as u64;
    Ok(Time::new(increments, target_scale))
}

fn rescale_datetime2(dt2: DateTime2, target_scale: u8) -> crate::Result<DateTime2> {
    if dt2.time().scale() == target_scale {
        return Ok(dt2);
    }
    let time = rescale_time(dt2.time(), target_scale)?;
    Ok(DateTime2::new(dt2.date(), time))
}

fn rescale_datetime_offset(dto: DateTimeOffset, target_scale: u8) -> crate::Result<DateTimeOffset> {
    if dto.datetime2().time().scale() == target_scale {
        return Ok(dto);
    }
    let dt2 = rescale_datetime2(dto.datetime2(), target_scale)?;
    Ok(DateTimeOffset::new(dt2, dto.offset()))
}

fn encode_variant_money_bytes(value: f64, len: usize) -> crate::Result<Vec<u8>> {
    if !value.is_finite() {
        return Err(crate::Error::BulkInput("money: invalid value".into()));
    }

    let scaled = (value * 10_000.0).round() as i64;
    let mut buf = BytesMut::new();
    match len {
        4 => {
            if scaled < i32::MIN as i64 || scaled > i32::MAX as i64 {
                return Err(crate::Error::BulkInput(
                    "money: value exceeds smallmoney range".into(),
                ));
            }
            buf.put_i32_le(scaled as i32);
        }
        8 => {
            let high = (scaled >> 32) as i32;
            let low = (scaled & 0xffff_ffff) as u32;
            buf.put_i32_le(high);
            buf.put_u32_le(low);
        }
        _ => {
            return Err(crate::Error::Protocol(
                format!("money: invalid length {}", len).into(),
            ))
        }
    }

    Ok(buf.to_vec())
}

fn encode_variant_numeric_bytes(value: Numeric) -> crate::Result<Vec<u8>> {
    let raw = value.value();
    let abs = raw.checked_abs().ok_or_else(|| {
        crate::Error::BulkInput("sql_variant: numeric overflow".into())
    })? as u128;
    let mut buf = BytesMut::with_capacity(17);
    buf.put_u8(if raw < 0 { 0 } else { 1 });
    buf.put_u128_le(abs);
    Ok(buf.to_vec())
}

fn encode_variant_non_unicode(
    value: &str,
    collation: Collation,
    max_len: usize,
) -> crate::Result<Vec<u8>> {
    let mut encoder = collation.encoding()?.new_encoder();
    let len = encoder
        .max_buffer_length_from_utf8_without_replacement(value.len())
        .unwrap();
    let mut bytes = Vec::with_capacity(len);
    let (res, _) = encoder.encode_from_utf8_to_vec_without_replacement(
        value,
        &mut bytes,
        true,
    );
    if let encoding_rs::EncoderResult::Unmappable(_) = res {
        return Err(crate::Error::Encoding(
            "sql_variant: unrepresentable character".into(),
        ));
    }
    if bytes.len() > max_len {
        return Err(crate::Error::BulkInput(
            format!(
                "Encoded string length {} exceed column limit {}",
                bytes.len(),
                max_len
            )
            .into(),
        ));
    }
    Ok(bytes)
}

fn encode_variant_unicode(value: &str, max_len: usize) -> crate::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(value.len() * 2);
    for chr in value.encode_utf16() {
        bytes.extend_from_slice(&chr.to_le_bytes());
    }
    if bytes.len() > max_len {
        return Err(crate::Error::BulkInput(
            format!(
                "Encoded string length {} exceed column limit {}",
                bytes.len(),
                max_len
            )
            .into(),
        ));
    }
    Ok(bytes)
}

fn numeric_len_from_precision(precision: u8) -> u8 {
    match precision {
        1..=9 => 5,
        10..=19 => 9,
        20..=28 => 13,
        _ => 17,
    }
}

fn encode_variant_payload(ty: TypeInfo, value: ColumnData<'_>) -> crate::Result<Vec<u8>> {
    if value.is_null() {
        return Err(crate::Error::BulkInput(
            "sql_variant: typed payload requires a non-null value".into(),
        ));
    }

    let mut prop_bytes = BytesMut::new();
    let mut value_bytes = BytesMut::new();

    let base_type = match (value, ty) {
        (ColumnData::Bit(Some(val)), TypeInfo::FixedLen(FixedLenType::Bit)) => {
            value_bytes.put_u8(val as u8);
            FixedLenType::Bit as u8
        }
        (ColumnData::Bit(Some(val)), TypeInfo::VarLenSized(ctx))
            if ctx.r#type() == VarLenType::Bitn && ctx.len() == 1 =>
        {
            value_bytes.put_u8(val as u8);
            FixedLenType::Bit as u8
        }
        (ColumnData::U8(Some(val)), TypeInfo::FixedLen(FixedLenType::Int1)) => {
            value_bytes.put_u8(val);
            FixedLenType::Int1 as u8
        }
        (ColumnData::U8(Some(val)), TypeInfo::VarLenSized(ctx))
            if ctx.r#type() == VarLenType::Intn && ctx.len() == 1 =>
        {
            value_bytes.put_u8(val);
            FixedLenType::Int1 as u8
        }
        (ColumnData::I16(Some(val)), TypeInfo::FixedLen(FixedLenType::Int2)) => {
            value_bytes.put_i16_le(val);
            FixedLenType::Int2 as u8
        }
        (ColumnData::I16(Some(val)), TypeInfo::VarLenSized(ctx))
            if ctx.r#type() == VarLenType::Intn && ctx.len() == 2 =>
        {
            value_bytes.put_i16_le(val);
            FixedLenType::Int2 as u8
        }
        (ColumnData::I32(Some(val)), TypeInfo::FixedLen(FixedLenType::Int4)) => {
            value_bytes.put_i32_le(val);
            FixedLenType::Int4 as u8
        }
        (ColumnData::I32(Some(val)), TypeInfo::VarLenSized(ctx))
            if ctx.r#type() == VarLenType::Intn && ctx.len() == 4 =>
        {
            value_bytes.put_i32_le(val);
            FixedLenType::Int4 as u8
        }
        (ColumnData::I64(Some(val)), TypeInfo::FixedLen(FixedLenType::Int8)) => {
            value_bytes.put_i64_le(val);
            FixedLenType::Int8 as u8
        }
        (ColumnData::I64(Some(val)), TypeInfo::VarLenSized(ctx))
            if ctx.r#type() == VarLenType::Intn && ctx.len() == 8 =>
        {
            value_bytes.put_i64_le(val);
            FixedLenType::Int8 as u8
        }
        (ColumnData::F32(Some(val)), TypeInfo::FixedLen(FixedLenType::Float4)) => {
            value_bytes.put_f32_le(val);
            FixedLenType::Float4 as u8
        }
        (ColumnData::F32(Some(val)), TypeInfo::VarLenSized(ctx))
            if ctx.r#type() == VarLenType::Floatn && ctx.len() == 4 =>
        {
            value_bytes.put_f32_le(val);
            FixedLenType::Float4 as u8
        }
        (ColumnData::F64(Some(val)), TypeInfo::FixedLen(FixedLenType::Float8)) => {
            value_bytes.put_f64_le(val);
            FixedLenType::Float8 as u8
        }
        (ColumnData::F64(Some(val)), TypeInfo::VarLenSized(ctx))
            if ctx.r#type() == VarLenType::Floatn && ctx.len() == 8 =>
        {
            value_bytes.put_f64_le(val);
            FixedLenType::Float8 as u8
        }
        (ColumnData::F64(Some(val)), TypeInfo::FixedLen(FixedLenType::Money)) => {
            value_bytes.extend_from_slice(&encode_variant_money_bytes(val, 8)?);
            FixedLenType::Money as u8
        }
        (ColumnData::F64(Some(val)), TypeInfo::FixedLen(FixedLenType::Money4)) => {
            value_bytes.extend_from_slice(&encode_variant_money_bytes(val, 4)?);
            FixedLenType::Money4 as u8
        }
        (ColumnData::F64(Some(val)), TypeInfo::VarLenSized(ctx))
            if ctx.r#type() == VarLenType::Money =>
        {
            value_bytes.extend_from_slice(&encode_variant_money_bytes(val, ctx.len())?);
            VarLenType::Money as u8
        }
        (ColumnData::Guid(Some(uuid)), TypeInfo::VarLenSized(ctx))
            if ctx.r#type() == VarLenType::Guid =>
        {
            let mut data = *uuid.as_bytes();
            super::guid::reorder_bytes(&mut data);
            value_bytes.extend_from_slice(&data);
            VarLenType::Guid as u8
        }
        (ColumnData::DateTime(Some(dt)), TypeInfo::FixedLen(FixedLenType::Datetime)) => {
            dt.encode(&mut value_bytes)?;
            FixedLenType::Datetime as u8
        }
        (ColumnData::SmallDateTime(Some(dt)), TypeInfo::FixedLen(FixedLenType::Datetime4)) => {
            dt.encode(&mut value_bytes)?;
            FixedLenType::Datetime4 as u8
        }
        (ColumnData::Date(Some(date)), TypeInfo::VarLenSized(ctx))
            if ctx.r#type() == VarLenType::Daten =>
        {
            date.encode(&mut value_bytes)?;
            VarLenType::Daten as u8
        }
        (ColumnData::Time(Some(time)), TypeInfo::VarLenSized(ctx))
            if ctx.r#type() == VarLenType::Timen =>
        {
            let scale = ctx.len() as u8;
            let time = rescale_time(time, scale)?;
            prop_bytes.put_u8(scale);
            time.encode(&mut value_bytes)?;
            VarLenType::Timen as u8
        }
        (ColumnData::DateTime2(Some(dt2)), TypeInfo::VarLenSized(ctx))
            if ctx.r#type() == VarLenType::Datetime2 =>
        {
            let scale = ctx.len() as u8;
            let dt2 = rescale_datetime2(dt2, scale)?;
            prop_bytes.put_u8(scale);
            dt2.encode(&mut value_bytes)?;
            VarLenType::Datetime2 as u8
        }
        (ColumnData::DateTimeOffset(Some(dto)), TypeInfo::VarLenSized(ctx))
            if ctx.r#type() == VarLenType::DatetimeOffsetn =>
        {
            let scale = ctx.len() as u8;
            let dto = rescale_datetime_offset(dto, scale)?;
            prop_bytes.put_u8(scale);
            dto.encode(&mut value_bytes)?;
            VarLenType::DatetimeOffsetn as u8
        }
        (
            ColumnData::Numeric(Some(num)),
            TypeInfo::VarLenSizedPrecision {
                ty,
                precision,
                scale,
                ..
            },
        ) if matches!(
            ty,
            VarLenType::Decimaln | VarLenType::Numericn | VarLenType::Decimal | VarLenType::Numeric
        ) => {
            if num.scale() != scale {
                return Err(crate::Error::BulkInput(
                    format!(
                        "numeric scale mismatch: expected {} got {}",
                        scale,
                        num.scale()
                    )
                    .into(),
                ));
            }
            if num.precision() != precision {
                return Err(crate::Error::BulkInput(
                    format!(
                        "numeric precision mismatch: expected {} got {}",
                        precision,
                        num.precision()
                    )
                    .into(),
                ));
            }
            prop_bytes.put_u8(precision);
            prop_bytes.put_u8(scale);
            value_bytes.extend_from_slice(&encode_variant_numeric_bytes(num)?);
            let base_ty = match ty {
                VarLenType::Decimaln | VarLenType::Decimal => VarLenType::Decimaln,
                VarLenType::Numericn | VarLenType::Numeric => VarLenType::Numericn,
                _ => ty,
            };
            base_ty as u8
        }
        (ColumnData::String(Some(value)), TypeInfo::VarLenSized(ctx))
            if matches!(ctx.r#type(), VarLenType::BigChar | VarLenType::BigVarChar) =>
        {
            let max_len = ctx.len();
            if max_len > u16::MAX as usize {
                return Err(crate::Error::BulkInput(
                    "sql_variant: char length exceeds u16".into(),
                ));
            }
            let collation = ctx.collation().ok_or_else(|| {
                crate::Error::BulkInput("sql_variant: missing collation".into())
            })?;
            let bytes = encode_variant_non_unicode(value.as_ref(), collation, max_len)?;
            prop_bytes.put_u32_le(collation.info());
            prop_bytes.put_u8(collation.sort_id());
            prop_bytes.put_u16_le(max_len as u16);
            value_bytes.extend_from_slice(&bytes);
            ctx.r#type() as u8
        }
        (ColumnData::String(Some(value)), TypeInfo::VarLenSized(ctx))
            if matches!(ctx.r#type(), VarLenType::NChar | VarLenType::NVarchar) =>
        {
            let max_len = ctx.len();
            if max_len > u16::MAX as usize {
                return Err(crate::Error::BulkInput(
                    "sql_variant: nchar length exceeds u16".into(),
                ));
            }
            let collation = ctx.collation().ok_or_else(|| {
                crate::Error::BulkInput("sql_variant: missing collation".into())
            })?;
            let bytes = encode_variant_unicode(value.as_ref(), max_len)?;
            prop_bytes.put_u32_le(collation.info());
            prop_bytes.put_u8(collation.sort_id());
            prop_bytes.put_u16_le(max_len as u16);
            value_bytes.extend_from_slice(&bytes);
            ctx.r#type() as u8
        }
        (ColumnData::Binary(Some(bytes)), TypeInfo::VarLenSized(ctx))
            if matches!(ctx.r#type(), VarLenType::BigBinary | VarLenType::BigVarBin) =>
        {
            let max_len = ctx.len();
            if max_len > u16::MAX as usize {
                return Err(crate::Error::BulkInput(
                    "sql_variant: binary length exceeds u16".into(),
                ));
            }
            if bytes.len() > max_len {
                return Err(crate::Error::BulkInput(
                    format!(
                        "Binary length {} exceed column limit {}",
                        bytes.len(),
                        max_len
                    )
                    .into(),
                ));
            }
            prop_bytes.put_u16_le(max_len as u16);
            value_bytes.extend_from_slice(bytes.as_ref());
            ctx.r#type() as u8
        }
        _ => {
            return Err(crate::Error::BulkInput(
                "sql_variant: unsupported typed payload".into(),
            ))
        }
    };

    if prop_bytes.len() > u8::MAX as usize {
        return Err(crate::Error::Protocol(
            "sql_variant: property bytes overflow".into(),
        ));
    }

    let mut payload = BytesMut::with_capacity(2 + prop_bytes.len() + value_bytes.len());
    payload.put_u8(base_type);
    payload.put_u8(prop_bytes.len() as u8);
    payload.extend_from_slice(&prop_bytes);
    payload.extend_from_slice(&value_bytes);
    Ok(payload.to_vec())
}

async fn decode_variant_payload(
    payload: &[u8],
) -> crate::Result<(TypeInfo, ColumnData<'static>)> {
    let (base_type, prop_bytes, value_bytes) = split_variant_payload(payload)?;
    let mut reader = VariantReader::new(BytesMut::from(value_bytes));

    if let Ok(fixed) = FixedLenType::try_from(base_type) {
        if !prop_bytes.is_empty() {
            return Err(crate::Error::Protocol(
                "sql_variant: unexpected property bytes".into(),
            ));
        }
        let value = match fixed {
            FixedLenType::Null => {
                return Err(crate::Error::Protocol(
                    "sql_variant: NULL base type unsupported".into(),
                ))
            }
            FixedLenType::Int1 => ColumnData::U8(Some(reader.read_u8().await?)),
            FixedLenType::Bit => ColumnData::Bit(Some(reader.read_u8().await? != 0)),
            FixedLenType::Int2 => ColumnData::I16(Some(reader.read_i16_le().await?)),
            FixedLenType::Int4 => ColumnData::I32(Some(reader.read_i32_le().await?)),
            FixedLenType::Int8 => ColumnData::I64(Some(reader.read_i64_le().await?)),
            FixedLenType::Float4 => ColumnData::F32(Some(reader.read_f32_le().await?)),
            FixedLenType::Float8 => ColumnData::F64(Some(reader.read_f64_le().await?)),
            FixedLenType::Money => money::decode(&mut reader, 8).await?,
            FixedLenType::Money4 => money::decode(&mut reader, 4).await?,
            FixedLenType::Datetime => ColumnData::DateTime(Some(DateTime::decode(&mut reader).await?)),
            FixedLenType::Datetime4 => {
                ColumnData::SmallDateTime(Some(SmallDateTime::decode(&mut reader).await?))
            }
        };

        if reader.remaining() != 0 {
            return Err(crate::Error::Protocol(
                "sql_variant payload has trailing bytes".into(),
            ));
        }

        return Ok((TypeInfo::FixedLen(fixed), value));
    }

    let var_ty = VarLenType::try_from(base_type).map_err(|_| {
        crate::Error::Protocol(format!("sql_variant: unknown base type {}", base_type).into())
    })?;

    match var_ty {
        VarLenType::Guid => {
            if !prop_bytes.is_empty() {
                return Err(crate::Error::Protocol(
                    "sql_variant: unexpected property bytes".into(),
                ));
            }
            let mut data = [0u8; 16];
            reader.read_exact(&mut data).await?;
            super::guid::reorder_bytes(&mut data);
            let value = ColumnData::Guid(Some(Uuid::from_bytes(data)));
            if reader.remaining() != 0 {
                return Err(crate::Error::Protocol(
                    "sql_variant payload has trailing bytes".into(),
                ));
            }
            let ty = TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Guid, 16, None));
            Ok((ty, value))
        }
        VarLenType::Daten => {
            if !prop_bytes.is_empty() {
                return Err(crate::Error::Protocol(
                    "sql_variant: unexpected property bytes".into(),
                ));
            }
            let value = ColumnData::Date(Some(Date::decode(&mut reader).await?));
            if reader.remaining() != 0 {
                return Err(crate::Error::Protocol(
                    "sql_variant payload has trailing bytes".into(),
                ));
            }
            let ty = TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Daten, 3, None));
            Ok((ty, value))
        }
        VarLenType::Timen => {
            if prop_bytes.len() != 1 {
                return Err(crate::Error::Protocol(
                    "sql_variant: invalid time prop bytes".into(),
                ));
            }
            let scale = prop_bytes[0];
            let value = ColumnData::Time(Some(
                Time::decode(&mut reader, scale as usize, value_bytes.len()).await?,
            ));
            if reader.remaining() != 0 {
                return Err(crate::Error::Protocol(
                    "sql_variant payload has trailing bytes".into(),
                ));
            }
            let ty = TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::Timen,
                scale as usize,
                None,
            ));
            Ok((ty, value))
        }
        VarLenType::Datetime2 => {
            if prop_bytes.len() != 1 {
                return Err(crate::Error::Protocol(
                    "sql_variant: invalid datetime2 prop bytes".into(),
                ));
            }
            let scale = prop_bytes[0];
            let value = ColumnData::DateTime2(Some(
                DateTime2::decode(&mut reader, scale as usize, value_bytes.len()).await?,
            ));
            if reader.remaining() != 0 {
                return Err(crate::Error::Protocol(
                    "sql_variant payload has trailing bytes".into(),
                ));
            }
            let ty = TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::Datetime2,
                scale as usize,
                None,
            ));
            Ok((ty, value))
        }
        VarLenType::DatetimeOffsetn => {
            if prop_bytes.len() != 1 {
                return Err(crate::Error::Protocol(
                    "sql_variant: invalid datetimeoffset prop bytes".into(),
                ));
            }
            let scale = prop_bytes[0];
            let rlen = u8::try_from(value_bytes.len()).map_err(|_| {
                crate::Error::Protocol("sql_variant: datetimeoffset length overflow".into())
            })?;
            let value = ColumnData::DateTimeOffset(Some(
                DateTimeOffset::decode(&mut reader, scale as usize, rlen).await?,
            ));
            if reader.remaining() != 0 {
                return Err(crate::Error::Protocol(
                    "sql_variant payload has trailing bytes".into(),
                ));
            }
            let ty = TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::DatetimeOffsetn,
                scale as usize,
                None,
            ));
            Ok((ty, value))
        }
        VarLenType::Decimaln | VarLenType::Numericn | VarLenType::Decimal | VarLenType::Numeric => {
            if prop_bytes.len() != 2 {
                return Err(crate::Error::Protocol(
                    "sql_variant: invalid numeric prop bytes".into(),
                ));
            }
            let precision = prop_bytes[0];
            let scale = prop_bytes[1];
            let expected_len = numeric_len_from_precision(precision) as usize;
            let mut buf = BytesMut::with_capacity(1 + value_bytes.len());
            match value_bytes.len() {
                len if len == expected_len => {
                    buf.put_u8(expected_len as u8);
                    buf.extend_from_slice(value_bytes);
                }
                len if len == expected_len + 1 => {
                    if value_bytes[0] != expected_len as u8 {
                        return Err(crate::Error::Protocol(
                            "sql_variant: numeric length prefix mismatch".into(),
                        ));
                    }
                    buf.extend_from_slice(value_bytes);
                }
                17 => {
                    buf.put_u8(17);
                    buf.extend_from_slice(value_bytes);
                }
                _ => {
                    return Err(crate::Error::Protocol(
                        "sql_variant: numeric length mismatch".into(),
                    ))
                }
            }
            let mut numeric_reader = VariantReader::new(buf);
            let numeric = Numeric::decode(&mut numeric_reader, scale)
                .await?
                .ok_or_else(|| {
                    crate::Error::Protocol("sql_variant: numeric null".into())
                })?;
            if numeric_reader.remaining() != 0 {
                return Err(crate::Error::Protocol(
                    "sql_variant payload has trailing bytes".into(),
                ));
            }
            let ty = TypeInfo::VarLenSizedPrecision {
                ty: var_ty,
                size: expected_len,
                precision,
                scale,
            };
            Ok((ty, ColumnData::Numeric(Some(numeric))))
        }
        VarLenType::BigVarChar | VarLenType::BigChar | VarLenType::VarChar | VarLenType::Char => {
            if prop_bytes.len() != 7 {
                return Err(crate::Error::Protocol(
                    "sql_variant: invalid char prop bytes".into(),
                ));
            }
            let mut prop = prop_bytes;
            let info = prop.get_u32_le();
            let sort_id = prop.get_u8();
            let max_len = prop.get_u16_le() as usize;
            let len_prefix = if matches!(var_ty, VarLenType::BigVarChar | VarLenType::BigChar) {
                2
            } else {
                1
            };
            let value_bytes = if value_bytes.len() >= len_prefix {
                let declared = if len_prefix == 2 {
                    u16::from_le_bytes([value_bytes[0], value_bytes[1]]) as usize
                } else {
                    value_bytes[0] as usize
                };
                let remaining = value_bytes.len().saturating_sub(len_prefix);
                if declared == remaining && declared <= max_len {
                    &value_bytes[len_prefix..]
                } else {
                    value_bytes
                }
            } else {
                value_bytes
            };
            if value_bytes.len() > max_len {
                return Err(crate::Error::Protocol(
                    "sql_variant: char length exceeds max".into(),
                ));
            }
            let collation = Collation::new(info, sort_id);
            let encoder = collation.encoding()?;
            let s = encoder
                .decode_without_bom_handling_and_without_replacement(value_bytes)
                .ok_or_else(|| crate::Error::Encoding("invalid sequence".into()))?
                .to_string();
            let ty = TypeInfo::VarLenSized(VarLenContext::new(var_ty, max_len, Some(collation)));
            Ok((ty, ColumnData::String(Some(s.into()))))
        }
        VarLenType::NVarchar | VarLenType::NChar => {
            if prop_bytes.len() != 7 {
                return Err(crate::Error::Protocol(
                    "sql_variant: invalid nchar prop bytes".into(),
                ));
            }
            let mut prop = prop_bytes;
            let info = prop.get_u32_le();
            let sort_id = prop.get_u8();
            let max_len = prop.get_u16_le() as usize;
            let value_bytes = if value_bytes.len() >= 2 {
                let declared = u16::from_le_bytes([value_bytes[0], value_bytes[1]]) as usize;
                let remaining = value_bytes.len().saturating_sub(2);
                if declared == remaining && declared <= max_len {
                    &value_bytes[2..]
                } else {
                    value_bytes
                }
            } else {
                value_bytes
            };
            if value_bytes.len() > max_len {
                return Err(crate::Error::Protocol(
                    "sql_variant: nchar length exceeds max".into(),
                ));
            }
            if value_bytes.len() % 2 != 0 {
                return Err(crate::Error::Protocol(
                    "sql_variant: invalid nchar length".into(),
                ));
            }
            let collation = Collation::new(info, sort_id);
            let buf: Vec<_> = value_bytes
                .chunks(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect();
            let s = String::from_utf16(&buf)?;
            let ty = TypeInfo::VarLenSized(VarLenContext::new(var_ty, max_len, Some(collation)));
            Ok((ty, ColumnData::String(Some(s.into()))))
        }
        VarLenType::BigVarBin
        | VarLenType::BigBinary
        | VarLenType::VarBinary
        | VarLenType::Binary => {
            if prop_bytes.len() != 2 {
                return Err(crate::Error::Protocol(
                    "sql_variant: invalid binary prop bytes".into(),
                ));
            }
            let mut prop = prop_bytes;
            let max_len = prop.get_u16_le() as usize;
            let len_prefix = if matches!(var_ty, VarLenType::BigVarBin | VarLenType::BigBinary) {
                2
            } else {
                1
            };
            let value_bytes = if value_bytes.len() >= len_prefix {
                let declared = if len_prefix == 2 {
                    u16::from_le_bytes([value_bytes[0], value_bytes[1]]) as usize
                } else {
                    value_bytes[0] as usize
                };
                let remaining = value_bytes.len().saturating_sub(len_prefix);
                if declared == remaining && declared <= max_len {
                    &value_bytes[len_prefix..]
                } else {
                    value_bytes
                }
            } else {
                value_bytes
            };
            if value_bytes.len() > max_len {
                return Err(crate::Error::Protocol(
                    "sql_variant: binary length exceeds max".into(),
                ));
            }
            let ty = TypeInfo::VarLenSized(VarLenContext::new(var_ty, max_len, None));
            Ok((
                ty,
                ColumnData::Binary(Some(Cow::Owned(value_bytes.to_vec()))),
            ))
        }
        VarLenType::Intn => {
            if !prop_bytes.is_empty() {
                return Err(crate::Error::Protocol(
                    "sql_variant: unexpected property bytes".into(),
                ));
            }
            let len = value_bytes.len();
            let value = match len {
                1 => ColumnData::U8(Some(reader.read_u8().await?)),
                2 => ColumnData::I16(Some(reader.read_i16_le().await?)),
                4 => ColumnData::I32(Some(reader.read_i32_le().await?)),
                8 => ColumnData::I64(Some(reader.read_i64_le().await?)),
                _ => {
                    return Err(crate::Error::Protocol(
                        "sql_variant: invalid intn length".into(),
                    ))
                }
            };
            if reader.remaining() != 0 {
                return Err(crate::Error::Protocol(
                    "sql_variant payload has trailing bytes".into(),
                ));
            }
            let ty = TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, len, None));
            Ok((ty, value))
        }
        VarLenType::Floatn => {
            if !prop_bytes.is_empty() {
                return Err(crate::Error::Protocol(
                    "sql_variant: unexpected property bytes".into(),
                ));
            }
            let len = value_bytes.len();
            let value = match len {
                4 => ColumnData::F32(Some(reader.read_f32_le().await?)),
                8 => ColumnData::F64(Some(reader.read_f64_le().await?)),
                _ => {
                    return Err(crate::Error::Protocol(
                        "sql_variant: invalid floatn length".into(),
                    ))
                }
            };
            if reader.remaining() != 0 {
                return Err(crate::Error::Protocol(
                    "sql_variant payload has trailing bytes".into(),
                ));
            }
            let ty = TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Floatn, len, None));
            Ok((ty, value))
        }
        VarLenType::Bitn => {
            if !prop_bytes.is_empty() {
                return Err(crate::Error::Protocol(
                    "sql_variant: unexpected property bytes".into(),
                ));
            }
            let len = value_bytes.len();
            if len != 1 {
                return Err(crate::Error::Protocol(
                    "sql_variant: invalid bitn length".into(),
                ));
            }
            let value = ColumnData::Bit(Some(reader.read_u8().await? != 0));
            if reader.remaining() != 0 {
                return Err(crate::Error::Protocol(
                    "sql_variant payload has trailing bytes".into(),
                ));
            }
            let ty = TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Bitn, len, None));
            Ok((ty, value))
        }
        VarLenType::Money => {
            if !prop_bytes.is_empty() {
                return Err(crate::Error::Protocol(
                    "sql_variant: unexpected property bytes".into(),
                ));
            }
            let len = value_bytes.len();
            let len_u8 = u8::try_from(len).map_err(|_| {
                crate::Error::Protocol("sql_variant: money length overflow".into())
            })?;
            let value = money::decode(&mut reader, len_u8).await?;
            if reader.remaining() != 0 {
                return Err(crate::Error::Protocol(
                    "sql_variant payload has trailing bytes".into(),
                ));
            }
            let ty = TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Money, len, None));
            Ok((ty, value))
        }
        VarLenType::Datetimen => {
            if !prop_bytes.is_empty() {
                return Err(crate::Error::Protocol(
                    "sql_variant: unexpected property bytes".into(),
                ));
            }
            let len = value_bytes.len();
            let value = match len {
                4 => ColumnData::SmallDateTime(Some(SmallDateTime::decode(&mut reader).await?)),
                8 => ColumnData::DateTime(Some(DateTime::decode(&mut reader).await?)),
                _ => {
                    return Err(crate::Error::Protocol(
                        "sql_variant: invalid datetimen length".into(),
                    ))
                }
            };
            if reader.remaining() != 0 {
                return Err(crate::Error::Protocol(
                    "sql_variant payload has trailing bytes".into(),
                ));
            }
            let ty = TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::Datetimen,
                len,
                None,
            ));
            Ok((ty, value))
        }
        _ => Err(crate::Error::Protocol(
            "sql_variant: unsupported base type".into(),
        )),
    }
}

impl<'a> ColumnData<'a> {
    pub(crate) fn type_name(&self) -> Cow<'static, str> {
        match self {
            ColumnData::U8(_) => "tinyint".into(),
            ColumnData::I16(_) => "smallint".into(),
            ColumnData::I32(_) => "int".into(),
            ColumnData::I64(_) => "bigint".into(),
            ColumnData::F32(_) => "float(24)".into(),
            ColumnData::F64(_) => "float(53)".into(),
            ColumnData::Bit(_) => "bit".into(),
            ColumnData::String(None) => "nvarchar(4000)".into(),
            ColumnData::String(Some(ref s)) if s.len() <= 4000 => "nvarchar(4000)".into(),
            ColumnData::String(Some(ref s)) if s.len() <= MAX_NVARCHAR_SIZE => {
                "nvarchar(max)".into()
            }
            ColumnData::String(_) => "ntext(max)".into(),
            ColumnData::Guid(_) => "uniqueidentifier".into(),
            ColumnData::Binary(Some(ref b)) if b.len() <= 8000 => "varbinary(8000)".into(),
            ColumnData::Binary(_) => "varbinary(max)".into(),
            ColumnData::Numeric(Some(ref n)) => {
                format!("numeric({},{})", n.precision(), n.scale()).into()
            }
            ColumnData::Numeric(None) => "numeric".into(),
            ColumnData::Xml(_) => "xml".into(),
            ColumnData::DateTime(_) => "datetime".into(),
            ColumnData::SmallDateTime(_) => "smalldatetime".into(),
            ColumnData::Time(_) => "time".into(),
            ColumnData::Date(_) => "date".into(),
            ColumnData::DateTime2(_) => "datetime2".into(),
            ColumnData::DateTimeOffset(_) => "datetimeoffset".into(),
            ColumnData::Udt(_) => "udt".into(),
            ColumnData::Variant(_) => "sql_variant".into(),
            ColumnData::Tvp(Some(ref tvp)) => {
                let mut name = String::new();
                if !tvp.schema.is_empty() {
                    name.push_str(tvp.schema.as_ref());
                    name.push('.');
                }
                name.push_str(tvp.type_name.as_ref());
                name.push_str(" READONLY");
                name.into()
            }
            ColumnData::Tvp(None) => "tvp READONLY".into(),
        }
    }

    pub(crate) fn is_null(&self) -> bool {
        match self {
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
            | ColumnData::Tvp(None) => true,
            _ => false,
        }
    }

    pub(crate) async fn decode<R>(src: &mut R, ctx: &TypeInfo) -> crate::Result<ColumnData<'a>>
    where
        R: SqlReadBytes + Unpin + Send,
    {
        let res = match ctx {
            TypeInfo::FixedLen(fixed_ty) => fixed_len::decode(src, fixed_ty).await?,
            TypeInfo::VarLenSized(cx) => var_len::decode(src, cx).await?,
            TypeInfo::VarLenSizedPrecision { ty, scale, .. } => match ty {
                VarLenType::Decimaln
                | VarLenType::Numericn
                | VarLenType::Decimal
                | VarLenType::Numeric => {
                    ColumnData::Numeric(Numeric::decode(src, *scale).await?)
                }
                _ => {
                    return Err(crate::Error::Protocol(
                        format!("unexpected precision type {:?}", ty).into(),
                    ))
                }
            },
            TypeInfo::Xml { schema, size } => xml::decode(src, *size, schema.clone()).await?,
            TypeInfo::Udt(info) => {
                let data = plp::decode(src, info.max_len as usize).await?;
                ColumnData::Udt(data.map(|d| Cow::Owned(d)))
            }
            TypeInfo::SsVariant(info) => {
                let len = src.read_u32_le().await?;
                if len == 0 || len == u32::MAX {
                    ColumnData::Variant(None)
                } else {
                    if len > info.max_len {
                        return Err(crate::Error::Protocol(
                            format!(
                                "sql_variant length {} exceed column limit {}",
                                len, info.max_len
                            )
                            .into(),
                        ));
                    }
                    let mut buf = Vec::with_capacity(len as usize);
                    for _ in 0..len {
                        buf.push(src.read_u8().await?);
                    }
                    ColumnData::Variant(Some(VariantData::new(buf)))
                }
            }
            TypeInfo::Tvp(_info) => {
                let data = decode_tvp_value(src).await?;
                ColumnData::Tvp(data)
            }
        };

        Ok(res)
    }
}

impl<'a> Encode<BytesMutWithTypeInfo<'a>> for ColumnData<'a> {
    fn encode(self, dst: &mut BytesMutWithTypeInfo<'a>) -> crate::Result<()> {
        let is_null = self.is_null();
        if let Some(TypeInfo::FixedLen(FixedLenType::Null)) = dst.type_info() {
            if is_null {
                return Ok(());
            }
            return Err(crate::Error::BulkInput(
                "fixed-length NULL expects a NULL value".into(),
            ));
        }

        match (self, dst.type_info()) {
            (ColumnData::Bit(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Bitn =>
            {
                if let Some(val) = opt {
                    dst.put_u8(1);
                    dst.put_u8(val as u8);
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::Bit(Some(val)), Some(TypeInfo::FixedLen(FixedLenType::Bit))) => {
                dst.put_u8(val as u8);
            }
            (ColumnData::Bit(Some(val)), None) => {
                // if TypeInfo was not given, encode a TypeInfo
                // the first 1 is part of TYPE_INFO
                // the second 1 is part of TYPE_VARBYTE
                let header = [VarLenType::Bitn as u8, 1, 1];
                dst.extend_from_slice(&header);
                dst.put_u8(val as u8);
            }
            (ColumnData::U8(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Intn =>
            {
                if let Some(val) = opt {
                    dst.put_u8(1);
                    dst.put_u8(val);
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::U8(Some(val)), Some(TypeInfo::FixedLen(FixedLenType::Int1))) => {
                dst.put_u8(val);
            }
            (ColumnData::U8(Some(val)), None) => {
                let header = [VarLenType::Intn as u8, 1, 1];
                dst.extend_from_slice(&header);
                dst.put_u8(val);
            }
            (ColumnData::I16(Some(val)), Some(TypeInfo::FixedLen(FixedLenType::Int2))) => {
                dst.put_i16_le(val);
            }
            (ColumnData::I16(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Intn =>
            {
                if let Some(val) = opt {
                    dst.put_u8(2);
                    dst.put_i16_le(val);
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::I16(Some(val)), None) => {
                let header = [VarLenType::Intn as u8, 2, 2];
                dst.extend_from_slice(&header);

                dst.put_i16_le(val);
            }
            (ColumnData::I32(Some(val)), Some(TypeInfo::FixedLen(FixedLenType::Int4))) => {
                dst.put_i32_le(val);
            }
            (ColumnData::I32(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Intn =>
            {
                if let Some(val) = opt {
                    dst.put_u8(4);
                    dst.put_i32_le(val);
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::I32(Some(val)), None) => {
                let header = [VarLenType::Intn as u8, 4, 4];
                dst.extend_from_slice(&header);
                dst.put_i32_le(val);
            }
            (ColumnData::I64(Some(val)), Some(TypeInfo::FixedLen(FixedLenType::Int8))) => {
                dst.put_i64_le(val);
            }
            (ColumnData::I64(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Intn =>
            {
                if let Some(val) = opt {
                    dst.put_u8(8);
                    dst.put_i64_le(val);
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::I64(Some(val)), None) => {
                let header = [VarLenType::Intn as u8, 8, 8];
                dst.extend_from_slice(&header);
                dst.put_i64_le(val);
            }
            (ColumnData::F32(Some(val)), Some(TypeInfo::FixedLen(FixedLenType::Float4))) => {
                dst.put_f32_le(val);
            }
            (ColumnData::F32(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Floatn =>
            {
                if let Some(val) = opt {
                    dst.put_u8(4);
                    dst.put_f32_le(val);
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::F32(Some(val)), None) => {
                let header = [VarLenType::Floatn as u8, 4, 4];
                dst.extend_from_slice(&header);
                dst.put_f32_le(val);
            }
            (ColumnData::F64(Some(val)), Some(TypeInfo::FixedLen(FixedLenType::Float8))) => {
                dst.put_f64_le(val);
            }
            (ColumnData::F64(Some(val)), Some(TypeInfo::FixedLen(FixedLenType::Money))) => {
                encode_money(dst, val, 8)?;
            }
            (ColumnData::F64(Some(val)), Some(TypeInfo::FixedLen(FixedLenType::Money4))) => {
                encode_money(dst, val, 4)?;
            }
            (ColumnData::F64(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Floatn =>
            {
                if let Some(val) = opt {
                    dst.put_u8(8);
                    dst.put_f64_le(val);
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::F64(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Money =>
            {
                if let Some(val) = opt {
                    let len = vlc.len();
                    dst.put_u8(len as u8);
                    encode_money(dst, val, len)?;
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::F64(Some(val)), None) => {
                let header = [VarLenType::Floatn as u8, 8, 8];
                dst.extend_from_slice(&header);
                dst.put_f64_le(val);
            }
            (ColumnData::Guid(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Guid =>
            {
                if let Some(uuid) = opt {
                    dst.put_u8(16);

                    let mut data = *uuid.as_bytes();
                    super::guid::reorder_bytes(&mut data);
                    dst.extend_from_slice(&data);
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::Guid(Some(uuid)), None) => {
                let header = [VarLenType::Guid as u8, 16, 16];
                dst.extend_from_slice(&header);

                let mut data = *uuid.as_bytes();
                super::guid::reorder_bytes(&mut data);
                dst.extend_from_slice(&data);
            }
            (ColumnData::String(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Char || vlc.r#type() == VarLenType::VarChar =>
            {
                encode_short_len_string(dst, vlc.collation(), vlc.len(), opt.as_deref())?;
            }
            (ColumnData::String(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::BigChar
                    || vlc.r#type() == VarLenType::BigVarChar =>
            {
                if let Some(str) = opt {
                    let mut encoder = vlc.collation().as_ref().unwrap().encoding()?.new_encoder();
                    let len = encoder
                        .max_buffer_length_from_utf8_without_replacement(str.len())
                        .unwrap();
                    let mut bytes = Vec::with_capacity(len);
                    let (res, _) = encoder.encode_from_utf8_to_vec_without_replacement(
                        str.as_ref(),
                        &mut bytes,
                        true,
                    );
                    if let encoding_rs::EncoderResult::Unmappable(_) = res {
                        return Err(crate::Error::Encoding("unrepresentable character".into()));
                    }

                    if bytes.len() > vlc.len() {
                        return Err(crate::Error::BulkInput(
                            format!(
                                "Encoded string length {} exceed column limit {}",
                                bytes.len(),
                                vlc.len()
                            )
                            .into(),
                        ));
                    }

                    if vlc.len() < 0xffff {
                        dst.put_u16_le(bytes.len() as u16);
                        dst.extend_from_slice(bytes.as_slice());
                    } else {
                        // unknown size
                        dst.put_u64_le(0xfffffffffffffffe);

                        assert!(
                            str.len() < 0xffffffff,
                            "if str longer than this, need to implement multiple blobs"
                        );

                        dst.put_u32_le(bytes.len() as u32);
                        dst.extend_from_slice(bytes.as_slice());

                        if !bytes.is_empty() {
                            // no next blob
                            dst.put_u32_le(0u32);
                        }
                    }
                } else if vlc.len() < 0xffff {
                    dst.put_u16_le(0xffff);
                } else {
                    dst.put_u64_le(0xffffffffffffffff)
                }
            }
            (ColumnData::String(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::NVarchar || vlc.r#type() == VarLenType::NChar =>
            {
                if let Some(str) = opt {
                    if vlc.len() < 0xffff {
                        let len_pos = dst.len();
                        dst.put_u16_le(0u16);

                        for chr in str.encode_utf16() {
                            dst.put_u16_le(chr);
                        }

                        let length = dst.len() - len_pos - 2;

                        if length > vlc.len() {
                            return Err(crate::Error::BulkInput(
                                format!(
                                    "Encoded string length {} exceed column limit {}",
                                    length,
                                    vlc.len()
                                )
                                .into(),
                            ));
                        }

                        let dst: &mut [u8] = dst.borrow_mut();
                        let mut dst = &mut dst[len_pos..];
                        dst.put_u16_le(length as u16);
                    } else {
                        // unknown size
                        dst.put_u64_le(0xfffffffffffffffe);

                        assert!(
                            str.len() < 0xffffffff,
                            "if str longer than this, need to implement multiple blobs"
                        );

                        let len_pos = dst.len();
                        dst.put_u32_le(0u32);

                        for chr in str.encode_utf16() {
                            dst.put_u16_le(chr);
                        }

                        let length = dst.len() - len_pos - 4;

                        if length > vlc.len() {
                            return Err(crate::Error::BulkInput(
                                format!(
                                    "Encoded string length {} exceed column limit {}",
                                    length,
                                    vlc.len()
                                )
                                .into(),
                            ));
                        }

                        if length > 0 {
                            // no next blob
                            dst.put_u32_le(0u32);
                        }

                        let dst: &mut [u8] = dst.borrow_mut();
                        let mut dst = &mut dst[len_pos..];
                        dst.put_u32_le(length as u32);
                    }
                } else if vlc.len() < 0xffff {
                    dst.put_u16_le(0xffff);
                } else {
                    dst.put_u64_le(0xffffffffffffffff)
                }
            }
            (ColumnData::String(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Text || vlc.r#type() == VarLenType::NText =>
            {
                encode_text_value(dst, vlc.collation(), opt.as_deref(), vlc.r#type())?;
            }
            (ColumnData::String(Some(ref s)), None) if s.len() <= 4000 => {
                dst.put_u8(VarLenType::NVarchar as u8);
                dst.put_u16_le(8000);
                dst.extend_from_slice(&[0u8; 5][..]);

                let mut length = 0u16;
                let len_pos = dst.len();

                dst.put_u16_le(length);

                for chr in s.encode_utf16() {
                    length += 1;
                    dst.put_u16_le(chr);
                }

                let dst: &mut [u8] = dst.borrow_mut();
                let bytes = (length * 2).to_le_bytes(); // u16, two bytes

                for (i, byte) in bytes.iter().enumerate() {
                    dst[len_pos + i] = *byte;
                }
            }
            (ColumnData::String(None), None) => {
                dst.put_u8(VarLenType::NVarchar as u8);
                dst.put_u16_le(8000);
                dst.extend_from_slice(&[0u8; 5][..]);
                dst.put_u16_le(0xffff);
            }
            (ColumnData::String(Some(ref s)), None) => {
                // length: 0xffff and raw collation
                dst.put_u8(VarLenType::NVarchar as u8);
                dst.extend_from_slice(&[0xff_u8; 2]);
                dst.extend_from_slice(&[0u8; 5]);

                // we cannot cheaply predetermine the length of the UCS2 string beforehand
                // (2 * bytes(UTF8) is not always right) - so just let the SQL server handle it
                dst.put_u64_le(0xfffffffffffffffe_u64);

                // Write the varchar length
                let mut length = 0u32;
                let len_pos = dst.len();

                dst.put_u32_le(length);

                for chr in s.encode_utf16() {
                    length += 1;
                    dst.put_u16_le(chr);
                }

                if length > 0 {
                    // PLP_TERMINATOR
                    dst.put_u32_le(0);
                }

                let dst: &mut [u8] = dst.borrow_mut();
                let bytes = (length * 2).to_le_bytes(); // u32, four bytes

                for (i, byte) in bytes.iter().enumerate() {
                    dst[len_pos + i] = *byte;
                }
            }
            (ColumnData::Binary(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Binary || vlc.r#type() == VarLenType::VarBinary =>
            {
                encode_short_len_binary(dst, vlc.len(), opt)?;
            }
            (ColumnData::Binary(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::BigBinary
                    || vlc.r#type() == VarLenType::BigVarBin =>
            {
                if let Some(bytes) = opt {
                    if bytes.len() > vlc.len() {
                        return Err(crate::Error::BulkInput(
                            format!(
                                "Binary length {} exceed column limit {}",
                                bytes.len(),
                                vlc.len()
                            )
                            .into(),
                        ));
                    }

                    if vlc.len() < 0xffff {
                        dst.put_u16_le(bytes.len() as u16);
                        dst.extend(bytes.into_owned());
                    } else {
                        // unknown size
                        dst.put_u64_le(0xfffffffffffffffe);
                        dst.put_u32_le(bytes.len() as u32);

                        if !bytes.is_empty() {
                            dst.extend(bytes.into_owned());
                            dst.put_u32_le(0);
                        }
                    }
                } else if vlc.len() < 0xffff {
                    dst.put_u16_le(0xffff);
                } else {
                    dst.put_u64_le(0xffffffffffffffff);
                }
            }
            (ColumnData::Binary(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Image =>
            {
                encode_image_value(dst, opt)?;
            }
            (ColumnData::Binary(Some(bytes)), None) if bytes.len() <= 8000 => {
                dst.put_u8(VarLenType::BigVarBin as u8);
                dst.put_u16_le(8000);
                dst.put_u16_le(bytes.len() as u16);
                dst.extend(bytes.into_owned());
            }
            (ColumnData::Binary(Some(bytes)), None) => {
                dst.put_u8(VarLenType::BigVarBin as u8);
                // Max length
                dst.put_u16_le(0xffff_u16);
                // Also the length is unknown
                dst.put_u64_le(0xfffffffffffffffe_u64);
                // We'll write in one chunk, length is the whole bytes length
                dst.put_u32_le(bytes.len() as u32);

                if !bytes.is_empty() {
                    // Payload
                    dst.extend(bytes.into_owned());
                    // PLP_TERMINATOR
                    dst.put_u32_le(0);
                }
            }
            (ColumnData::DateTime(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Datetimen =>
            {
                if let Some(dt) = opt {
                    dst.put_u8(8);
                    dt.encode(dst)?;
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::DateTime(Some(dt)), Some(TypeInfo::FixedLen(FixedLenType::Datetime))) => {
                dt.encode(dst)?;
            }
            (ColumnData::DateTime(Some(dt)), None) => {
                dst.extend_from_slice(&[VarLenType::Datetimen as u8, 8, 8]);
                dt.encode(&mut *dst)?;
            }
            (ColumnData::SmallDateTime(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Datetimen =>
            {
                if let Some(dt) = opt {
                    dst.put_u8(4);
                    dt.encode(dst)?;
                } else {
                    dst.put_u8(0);
                }
            }
            (
                ColumnData::SmallDateTime(Some(dt)),
                Some(TypeInfo::FixedLen(FixedLenType::Datetime4)),
            ) => {
                dt.encode(dst)?;
            }
            (ColumnData::SmallDateTime(Some(dt)), None) => {
                dst.extend_from_slice(&[VarLenType::Datetimen as u8, 4, 4]);
                dt.encode(&mut *dst)?;
            }
            (ColumnData::Date(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Daten =>
            {
                if let Some(dt) = opt {
                    dst.put_u8(3);
                    dt.encode(dst)?;
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::Date(Some(date)), None) => {
                dst.extend_from_slice(&[VarLenType::Daten as u8, 3]);
                date.encode(&mut *dst)?;
            }
            (ColumnData::Time(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Timen =>
            {
                if let Some(time) = opt {
                    dst.put_u8(time.len()?);
                    time.encode(dst)?;
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::Time(Some(time)), None) => {
                dst.extend_from_slice(&[VarLenType::Timen as u8, time.scale(), time.len()?]);
                time.encode(&mut *dst)?;
            }
            (ColumnData::DateTime2(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Datetime2 =>
            {
                if let Some(mut dt2) = opt {
                    if dt2.time().scale() != vlc.len() as u8 {
                        let time = dt2.time();
                        let increments = (time.increments() as f64
                            * 10_f64.powi(vlc.len() as i32 - time.scale() as i32))
                            as u64;
                        dt2 = DateTime2::new(dt2.date(), Time::new(increments, vlc.len() as u8));
                    }
                    dst.put_u8(dt2.time().len()? + 3);
                    dt2.encode(dst)?;
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::DateTime2(Some(dt)), None) => {
                let len = dt.time().len()? + 3;
                dst.extend_from_slice(&[VarLenType::Datetime2 as u8, dt.time().scale(), len]);
                dt.encode(&mut *dst)?;
            }
            (ColumnData::DateTimeOffset(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::DatetimeOffsetn =>
            {
                if let Some(dto) = opt {
                    dst.put_u8(dto.datetime2().time().len()? + 5);
                    dto.encode(dst)?;
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::DateTimeOffset(Some(dto)), None) => {
                let headers = [
                    VarLenType::DatetimeOffsetn as u8,
                    dto.datetime2().time().scale(),
                    dto.datetime2().time().len()? + 5,
                ];

                dst.extend_from_slice(&headers);
                dto.encode(&mut *dst)?;
            }
            (ColumnData::Xml(opt), Some(TypeInfo::Xml { .. })) => {
                if let Some(xml) = opt {
                    xml.into_owned().encode(dst)?;
                } else {
                    dst.put_u64_le(0xffffffffffffffff_u64);
                }
            }
            (ColumnData::Xml(Some(xml)), None) => {
                dst.put_u8(VarLenType::Xml as u8);
                dst.put_u8(0);
                xml.into_owned().encode(&mut *dst)?;
            }
            (ColumnData::Numeric(opt), Some(TypeInfo::VarLenSizedPrecision { ty, scale, .. }))
                if ty == &VarLenType::Numericn
                    || ty == &VarLenType::Decimaln
                    || ty == &VarLenType::Numeric
                    || ty == &VarLenType::Decimal =>
            {
                if let Some(num) = opt {
                    if scale != &num.scale() {
                        return Err(crate::Error::BulkInput(
                            format!(
                                "numeric scale mismatch: expected {} got {}",
                                scale,
                                num.scale()
                            )
                            .into(),
                        ));
                    }
                    num.encode(&mut *dst)?;
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::Numeric(Some(num)), None) => {
                let headers = &[
                    VarLenType::Numericn as u8,
                    num.len(),
                    num.precision(),
                    num.scale(),
                ];

                dst.extend_from_slice(headers);
                num.encode(&mut *dst)?;
            }
            (ColumnData::Udt(opt), Some(TypeInfo::Udt(info))) => {
                encode_var_len_bytes(dst, info.max_len as usize, opt)?;
            }
            (ColumnData::Variant(opt), Some(TypeInfo::SsVariant(info))) => {
                if let Some(payload) = opt {
                    let len = payload.payload().len();
                    if len == 0 {
                        return Err(crate::Error::BulkInput(
                            "sql_variant payload must include type info".into(),
                        ));
                    }
                    if len > info.max_len as usize {
                        return Err(crate::Error::BulkInput(
                            format!(
                                "sql_variant length {} exceed column limit {}",
                                len, info.max_len
                            )
                            .into(),
                        ));
                    }
                    if len > u32::MAX as usize {
                        return Err(crate::Error::BulkInput(
                            "sql_variant payload too large".into(),
                        ));
                    }
                    dst.put_u32_le(len as u32);
                    dst.extend_from_slice(payload.payload());
                } else {
                    dst.put_u32_le(0);
                }
            }
            (ColumnData::Tvp(opt), Some(TypeInfo::Tvp(_))) => {
                encode_tvp_value(dst, opt)?;
            }
            (ColumnData::Variant(Some(payload)), None) => {
                // Self-describe sql_variant type info for RPC parameters
                dst.put_u8(VarLenType::SSVariant as u8);
                dst.put_u32_le(8016); // standard max_len
                let len = payload.payload().len();
                if len == 0 {
                    return Err(crate::Error::BulkInput(
                        "sql_variant payload must include type info".into(),
                    ));
                }
                dst.put_u32_le(len as u32);
                dst.extend_from_slice(payload.payload());
            }
            (ColumnData::Variant(None), None) => {
                dst.put_u8(VarLenType::SSVariant as u8);
                dst.put_u32_le(8016);
                dst.put_u32_le(0); // null
            }
            (ColumnData::Tvp(Some(mut tvp)), None) => {
                // Self-describe TVP type info for RPC parameters
                dst.put_u8(VarLenType::Tvp as u8);
                crate::tds::codec::token::write_b_varchar(dst, tvp.db_name.as_ref())?;
                crate::tds::codec::token::write_b_varchar(dst, tvp.schema.as_ref())?;
                crate::tds::codec::token::write_b_varchar(dst, tvp.type_name.as_ref())?;
                // SQL Server requires empty column names for TVP parameters in RPC calls
                for col in &mut tvp.columns {
                    col.name = Cow::Borrowed("");
                }
                encode_tvp_value(dst, Some(tvp))?;
            }
            (ColumnData::Tvp(None), None) => {
                // Null TVP — write type header with empty names + null marker
                dst.put_u8(VarLenType::Tvp as u8);
                crate::tds::codec::token::write_b_varchar(dst, "")?;
                crate::tds::codec::token::write_b_varchar(dst, "")?;
                crate::tds::codec::token::write_b_varchar(dst, "")?;
                encode_tvp_value(dst, None)?;
            }
            (_, None) => {
                // None/null
                dst.put_u8(FixedLenType::Null as u8);
            }
            (v, ref ti) => {
                return Err(crate::Error::BulkInput(
                    format!("invalid data type, expecting {:?} but found {:?}", ti, v).into(),
                ));
            }
        }

        Ok(())
    }
}

fn encode_var_len_bytes<'a>(
    dst: &mut BytesMutWithTypeInfo<'a>,
    max_len: usize,
    value: Option<Cow<'a, [u8]>>,
) -> crate::Result<()> {
    if let Some(bytes) = value {
        if max_len < 0xffff {
            if bytes.len() > max_len {
                return Err(crate::Error::BulkInput(
                    format!(
                        "Binary length {} exceed column limit {}",
                        bytes.len(),
                        max_len
                    )
                    .into(),
                ));
            }
            dst.put_u16_le(bytes.len() as u16);
            dst.extend(bytes.into_owned());
        } else {
            dst.put_u64_le(0xfffffffffffffffe);
            dst.put_u32_le(bytes.len() as u32);

            if !bytes.is_empty() {
                dst.extend(bytes.into_owned());
                dst.put_u32_le(0);
            }
        }
    } else if max_len < 0xffff {
        dst.put_u16_le(0xffff);
    } else {
        dst.put_u64_le(0xffffffffffffffff);
    }

    Ok(())
}

fn decode_tvp_value<'a, R>(
    src: &'a mut R,
) -> Pin<Box<dyn Future<Output = crate::Result<Option<TvpData<'static>>>> + Send + 'a>>
where
    R: SqlReadBytes + Unpin + Send + 'a,
{
    Box::pin(async move {
        const TVP_ROW_TOKEN: u8 = 0x01;
        const TVP_END_TOKEN: u8 = 0x00;

        let column_count = src.read_u16_le().await?;
        if column_count == 0xffff {
            let meta_end = src.read_u8().await?;
            let row_end = src.read_u8().await?;
            if meta_end != TVP_END_TOKEN || row_end != TVP_END_TOKEN {
                return Err(crate::Error::Protocol(
                    "tvp: invalid null terminator".into(),
                ));
            }
            return Ok(None);
        }

        let mut columns = Vec::with_capacity(column_count as usize);
        for _ in 0..column_count {
            let user_type = src.read_u32_le().await?;
            let flags_raw = src.read_u16_le().await?;
            let flags = BitFlags::from_bits(flags_raw)
                .map_err(|_| crate::Error::Protocol("tvp: invalid column flags".into()))?;
            let ty = TypeInfo::decode(src).await?;
            let name = src.read_b_varchar().await?;
            columns.push(TvpColumn {
                name: Cow::Owned(name),
                user_type,
                flags,
                ty,
            });
        }

        let meta_end = src.read_u8().await?;
        if meta_end != TVP_END_TOKEN {
            return Err(crate::Error::Protocol(
                "tvp: missing metadata terminator".into(),
            ));
        }

        let mut rows = Vec::new();
        loop {
            let token = src.read_u8().await?;
            match token {
                TVP_END_TOKEN => break,
                TVP_ROW_TOKEN => {
                    let mut row = Vec::with_capacity(columns.len());
                    for column in &columns {
                        let value = ColumnData::decode(src, &column.ty).await?;
                        row.push(value);
                    }
                    rows.push(row);
                }
                _ => {
                    return Err(crate::Error::Protocol(
                        "tvp: invalid row token".into(),
                    ))
                }
            }
        }

        Ok(Some(TvpData {
            db_name: Cow::Borrowed(""),
            schema: Cow::Borrowed(""),
            type_name: Cow::Borrowed(""),
            columns,
            rows,
        }))
    })
}

fn encode_tvp_value<'a>(
    dst: &mut BytesMutWithTypeInfo<'a>,
    value: Option<TvpData<'a>>,
) -> crate::Result<()> {
    const TVP_ROW_TOKEN: u8 = 0x01;
    const TVP_END_TOKEN: u8 = 0x00;

    let Some(tvp) = value else {
        dst.put_u16_le(0xffff);
        dst.put_u8(TVP_END_TOKEN);
        dst.put_u8(TVP_END_TOKEN);
        return Ok(());
    };

    if tvp.columns.len() > u16::MAX as usize {
        return Err(crate::Error::BulkInput(
            "tvp: column count exceeds u16".into(),
        ));
    }

    let columns = tvp.columns;
    let rows = tvp.rows;

    dst.put_u16_le(columns.len() as u16);
    for column in &columns {
        dst.put_u32_le(column.user_type);
        dst.put_u16_le(BitFlags::bits(column.flags));
        column.ty.clone().encode(dst)?;
        crate::tds::codec::token::write_b_varchar(dst, column.name.as_ref())?;
    }

    dst.put_u8(TVP_END_TOKEN);

    for row in rows {
        if row.len() != columns.len() {
            return Err(crate::Error::BulkInput(
                "tvp: row length mismatch".into(),
            ));
        }
        dst.put_u8(TVP_ROW_TOKEN);
        for (value, column) in row.into_iter().zip(columns.iter()) {
            let mut dst_ti = BytesMutWithTypeInfo::new(dst).with_type_info(&column.ty);
            value.encode(&mut dst_ti)?;
        }
    }

    dst.put_u8(TVP_END_TOKEN);
    Ok(())
}

fn encode_money<'a>(
    dst: &mut BytesMutWithTypeInfo<'a>,
    value: f64,
    len: usize,
) -> crate::Result<()> {
    if !value.is_finite() {
        return Err(crate::Error::BulkInput("money: invalid value".into()));
    }

    let scaled = (value * 10_000.0).round() as i64;
    match len {
        4 => {
            if scaled < i32::MIN as i64 || scaled > i32::MAX as i64 {
                return Err(crate::Error::BulkInput(
                    "money: value exceeds smallmoney range".into(),
                ));
            }
            dst.put_i32_le(scaled as i32);
        }
        8 => {
            let high = (scaled >> 32) as i32;
            let low = (scaled & 0xffff_ffff) as u32;
            dst.put_i32_le(high);
            dst.put_u32_le(low);
        }
        _ => {
            return Err(crate::Error::Protocol(
                format!("money: invalid length {}", len).into(),
            ))
        }
    }

    Ok(())
}

fn encode_text_value<'a>(
    dst: &mut BytesMutWithTypeInfo<'a>,
    collation: Option<Collation>,
    value: Option<&str>,
    ty: VarLenType,
) -> crate::Result<()> {
    let Some(value) = value else {
        dst.put_u8(0);
        return Ok(());
    };

    let bytes = match ty {
        VarLenType::Text => {
            let collation = collation.ok_or_else(|| {
                crate::Error::BulkInput("text: missing collation".into())
            })?;
            let mut encoder = collation.encoding()?.new_encoder();
            let len = encoder
                .max_buffer_length_from_utf8_without_replacement(value.len())
                .unwrap();
            let mut buf = Vec::with_capacity(len);
            let (res, _) = encoder.encode_from_utf8_to_vec_without_replacement(
                value,
                &mut buf,
                true,
            );
            if let encoding_rs::EncoderResult::Unmappable(_) = res {
                return Err(crate::Error::Encoding(
                    "text: unrepresentable character".into(),
                ));
            }
            buf
        }
        VarLenType::NText => {
            let mut buf = Vec::with_capacity(value.len() * 2);
            for chr in value.encode_utf16() {
                buf.extend_from_slice(&chr.to_le_bytes());
            }
            buf
        }
        _ => {
            return Err(crate::Error::Protocol(
                "text: unsupported type".into(),
            ))
        }
    };

    if bytes.len() > u32::MAX as usize {
        return Err(crate::Error::BulkInput("text: payload too large".into()));
    }
    dst.put_u8(16);
    dst.extend_from_slice(&[0u8; 16]);
    dst.put_u64_le(0);
    dst.put_u32_le(bytes.len() as u32);
    dst.extend_from_slice(&bytes);

    Ok(())
}

fn encode_image_value<'a>(
    dst: &mut BytesMutWithTypeInfo<'a>,
    value: Option<Cow<'a, [u8]>>,
) -> crate::Result<()> {
    let Some(bytes) = value else {
        dst.put_u8(0);
        return Ok(());
    };

    if bytes.len() > u32::MAX as usize {
        return Err(crate::Error::BulkInput("image: payload too large".into()));
    }
    dst.put_u8(16);
    dst.extend_from_slice(&[0u8; 16]);
    dst.put_u64_le(0);
    dst.put_u32_le(bytes.len() as u32);
    dst.extend(bytes.into_owned());
    Ok(())
}

fn encode_short_len_string<'a>(
    dst: &mut BytesMutWithTypeInfo<'a>,
    collation: Option<Collation>,
    max_len: usize,
    value: Option<&str>,
) -> crate::Result<()> {
    let Some(value) = value else {
        dst.put_u8(0xff);
        return Ok(());
    };

    if max_len > u8::MAX as usize {
        return Err(crate::Error::BulkInput(
            format!("char/varchar length {} exceeds 1-byte limit", max_len).into(),
        ));
    }

    let collation = collation.ok_or_else(|| {
        crate::Error::BulkInput("char/varchar: missing collation".into())
    })?;
    let mut encoder = collation.encoding()?.new_encoder();
    let len = encoder
        .max_buffer_length_from_utf8_without_replacement(value.len())
        .unwrap();
    let mut bytes = Vec::with_capacity(len);
    let (res, _) =
        encoder.encode_from_utf8_to_vec_without_replacement(value, &mut bytes, true);
    if let encoding_rs::EncoderResult::Unmappable(_) = res {
        return Err(crate::Error::Encoding(
            "char/varchar: unrepresentable character".into(),
        ));
    }

    if bytes.len() > max_len {
        return Err(crate::Error::BulkInput(
            format!(
                "Encoded string length {} exceed column limit {}",
                bytes.len(),
                max_len
            )
            .into(),
        ));
    }

    if bytes.len() > u8::MAX as usize {
        return Err(crate::Error::BulkInput(
            "char/varchar payload too large".into(),
        ));
    }

    dst.put_u8(bytes.len() as u8);
    dst.extend_from_slice(bytes.as_slice());
    Ok(())
}

fn encode_short_len_binary<'a>(
    dst: &mut BytesMutWithTypeInfo<'a>,
    max_len: usize,
    value: Option<Cow<'a, [u8]>>,
) -> crate::Result<()> {
    let Some(bytes) = value else {
        dst.put_u8(0xff);
        return Ok(());
    };

    if max_len > u8::MAX as usize {
        return Err(crate::Error::BulkInput(
            format!("binary length {} exceeds 1-byte limit", max_len).into(),
        ));
    }

    if bytes.len() > max_len {
        return Err(crate::Error::BulkInput(
            format!(
                "Binary length {} exceed column limit {}",
                bytes.len(),
                max_len
            )
            .into(),
        ));
    }

    if bytes.len() > u8::MAX as usize {
        return Err(crate::Error::BulkInput("binary payload too large".into()));
    }

    dst.put_u8(bytes.len() as u8);
    dst.extend(bytes.into_owned());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use crate::tds::Collation;
    use crate::{ColumnFlag, Error, FixedLenType, SsVariantInfo, TvpInfo, UdtInfo, VarLenContext};
    use bytes::BytesMut;

    async fn test_round_trip(ti: TypeInfo, d: ColumnData<'_>) {
        let mut buf = BytesMut::new();
        let mut buf_with_ti = BytesMutWithTypeInfo::new(&mut buf).with_type_info(&ti);

        d.clone()
            .encode(&mut buf_with_ti)
            .expect("encode must succeed");

        let reader = &mut buf.into_sql_read_bytes();
        let nd = ColumnData::decode(reader, &ti)
            .await
            .expect("decode must succeed");

        assert_eq!(nd, d);

        reader
            .read_u8()
            .await
            .expect_err("decode must consume entire buffer");
    }

    #[tokio::test]
    async fn i32_with_varlen_int() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 4, None)),
            ColumnData::I32(Some(42)),
        )
        .await;
    }

    #[tokio::test]
    async fn tvp_round_trip() {
        let collation = Some(Collation::new(13632521, 52));
        let columns = vec![
            TvpColumn {
                name: "id".into(),
                user_type: 0,
                flags: ColumnFlag::Nullable.into(),
                ty: TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 4, None)),
            },
            TvpColumn {
                name: "label".into(),
                user_type: 0,
                flags: ColumnFlag::Nullable.into(),
                ty: TypeInfo::VarLenSized(VarLenContext::new(
                    VarLenType::NVarchar,
                    40,
                    collation,
                )),
            },
        ];
        let rows = vec![
            vec![
                ColumnData::I32(Some(1)),
                ColumnData::String(Some("one".into())),
            ],
            vec![ColumnData::I32(None), ColumnData::String(None)],
        ];
        // Type name/schema/db_name live in the TypeInfo header, not the TVP data
        // payload, so round-tripped TvpData always has empty names.
        let tvp = TvpData::new("")
            .columns(columns)
            .rows(rows);
        test_round_trip(
            TypeInfo::Tvp(TvpInfo {
                db_name: "db".into(),
                schema: "dbo".into(),
                type_name: "tvp_type".into(),
            }),
            ColumnData::Tvp(Some(tvp)),
        )
        .await;
    }

    #[tokio::test]
    async fn none_with_varlen_int() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 4, None)),
            ColumnData::I32(None),
        )
        .await;
    }

    #[tokio::test]
    async fn i32_with_fixedlen_int() {
        test_round_trip(
            TypeInfo::FixedLen(FixedLenType::Int4),
            ColumnData::I32(Some(42)),
        )
        .await;
    }

    #[tokio::test]
    async fn bit_with_varlen_bit() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Bitn, 1, None)),
            ColumnData::Bit(Some(true)),
        )
        .await;
    }

    #[tokio::test]
    async fn none_with_varlen_bit() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Bitn, 1, None)),
            ColumnData::Bit(None),
        )
        .await;
    }

    #[tokio::test]
    async fn bit_with_fixedlen_bit() {
        test_round_trip(
            TypeInfo::FixedLen(FixedLenType::Bit),
            ColumnData::Bit(Some(true)),
        )
        .await;
    }

    #[tokio::test]
    async fn u8_with_varlen_int() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 1, None)),
            ColumnData::U8(Some(8u8)),
        )
        .await;
    }

    #[tokio::test]
    async fn none_u8_with_varlen_int() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 1, None)),
            ColumnData::U8(None),
        )
        .await;
    }

    #[tokio::test]
    async fn u8_with_fixedlen_int() {
        test_round_trip(
            TypeInfo::FixedLen(FixedLenType::Int1),
            ColumnData::U8(Some(8u8)),
        )
        .await;
    }

    #[tokio::test]
    async fn i16_with_varlen_intn() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 2, None)),
            ColumnData::I16(Some(8i16)),
        )
        .await;
    }

    #[tokio::test]
    async fn none_i16_with_varlen_intn() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 2, None)),
            ColumnData::I16(None),
        )
        .await;
    }

    #[tokio::test]
    async fn none_with_varlen_intn() {
        test_round_trip(
            TypeInfo::FixedLen(FixedLenType::Int2),
            ColumnData::I16(Some(8i16)),
        )
        .await;
    }

    #[tokio::test]
    async fn i64_with_varlen_intn() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 8, None)),
            ColumnData::I64(Some(8i64)),
        )
        .await;
    }

    #[tokio::test]
    async fn i64_none_with_varlen_intn() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 8, None)),
            ColumnData::I64(None),
        )
        .await;
    }

    #[tokio::test]
    async fn i64_with_fixedlen_int8() {
        test_round_trip(
            TypeInfo::FixedLen(FixedLenType::Int8),
            ColumnData::I64(Some(8i64)),
        )
        .await;
    }

    #[tokio::test]
    async fn f32_with_varlen_floatn() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Floatn, 4, None)),
            ColumnData::F32(Some(8f32)),
        )
        .await;
    }

    #[tokio::test]
    async fn null_f32_with_varlen_floatn() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Floatn, 4, None)),
            ColumnData::F32(None),
        )
        .await;
    }

    #[tokio::test]
    async fn f32_with_fixedlen_float4() {
        test_round_trip(
            TypeInfo::FixedLen(FixedLenType::Float4),
            ColumnData::F32(Some(8f32)),
        )
        .await;
    }

    #[tokio::test]
    async fn f64_with_varlen_floatn() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Floatn, 8, None)),
            ColumnData::F64(Some(8f64)),
        )
        .await;
    }

    #[tokio::test]
    async fn none_f64_with_varlen_floatn() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Floatn, 8, None)),
            ColumnData::F64(None),
        )
        .await;
    }

    #[tokio::test]
    async fn f64_with_fixedlen_float8() {
        test_round_trip(
            TypeInfo::FixedLen(FixedLenType::Float8),
            ColumnData::F64(Some(8f64)),
        )
        .await;
    }

    #[tokio::test]
    async fn guid_with_varlen_guid() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Guid, 16, None)),
            ColumnData::Guid(Some(Uuid::new_v4())),
        )
        .await;
    }

    #[tokio::test]
    async fn none_guid_with_varlen_guid() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Guid, 16, None)),
            ColumnData::Guid(None),
        )
        .await;
    }

    #[tokio::test]
    async fn numeric_with_varlen_sized_precision() {
        test_round_trip(
            TypeInfo::VarLenSizedPrecision {
                ty: VarLenType::Numericn,
                size: 17,
                precision: 18,
                scale: 0,
            },
            ColumnData::Numeric(Some(Numeric::new_with_scale(23, 0))),
        )
        .await;
    }

    #[tokio::test]
    async fn none_numeric_with_varlen_sized_precision() {
        test_round_trip(
            TypeInfo::VarLenSizedPrecision {
                ty: VarLenType::Numericn,
                size: 17,
                precision: 18,
                scale: 0,
            },
            ColumnData::Numeric(None),
        )
        .await;
    }

    #[tokio::test]
    async fn string_with_varlen_bigchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::BigChar,
                40,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(Some("aaa".into())),
        )
        .await;
    }

    #[tokio::test]
    async fn long_string_with_varlen_bigchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::BigChar,
                0x8ffff,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(Some("aaa".into())),
        )
        .await;
    }

    #[tokio::test]
    async fn none_long_string_with_varlen_bigchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::BigChar,
                0x8ffff,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(None),
        )
        .await;
    }

    #[tokio::test]
    async fn none_string_with_varlen_bigchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::BigChar,
                40,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(None),
        )
        .await;
    }

    #[tokio::test]
    async fn string_with_varlen_bigvarchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::BigVarChar,
                40,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(Some("aaa".into())),
        )
        .await;
    }

    #[tokio::test]
    async fn none_string_with_varlen_bigvarchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::BigVarChar,
                40,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(None),
        )
        .await;
    }

    #[tokio::test]
    async fn empty_string_with_varlen_bigvarchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::BigVarChar,
                0x8ffff,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(Some("".into())),
        )
        .await;
    }

    #[tokio::test]
    async fn string_with_varlen_nvarchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::NVarchar,
                40,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(Some("hhh".into())),
        )
        .await;
    }

    #[tokio::test]
    async fn none_string_with_varlen_nvarchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::NVarchar,
                40,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(None),
        )
        .await;
    }

    #[tokio::test]
    async fn empty_string_with_varlen_nvarchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::NVarchar,
                0x8ffff,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(Some("".into())),
        )
        .await;
    }

    #[tokio::test]
    async fn string_with_varlen_nchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::NChar,
                40,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(Some("hhh".into())),
        )
        .await;
    }

    #[tokio::test]
    async fn long_string_with_varlen_nchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::NChar,
                0x8ffff,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(Some("hhh".into())),
        )
        .await;
    }

    #[tokio::test]
    async fn none_long_string_with_varlen_nchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::NChar,
                0x8ffff,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(None),
        )
        .await;
    }

    #[tokio::test]
    async fn none_string_with_varlen_nchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::NChar,
                40,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(None),
        )
        .await;
    }

    #[tokio::test]
    async fn binary_with_varlen_bigbinary() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigBinary, 40, None)),
            ColumnData::Binary(Some(b"aaa".as_slice().into())),
        )
        .await;
    }

    #[tokio::test]
    async fn long_binary_with_varlen_bigbinary() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigBinary, 0x8ffff, None)),
            ColumnData::Binary(Some(b"aaa".as_slice().into())),
        )
        .await;
    }

    #[tokio::test]
    async fn none_binary_with_varlen_bigbinary() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigBinary, 40, None)),
            ColumnData::Binary(None),
        )
        .await;
    }

    #[tokio::test]
    async fn none_long_binary_with_varlen_bigbinary() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigBinary, 0x8ffff, None)),
            ColumnData::Binary(None),
        )
        .await;
    }

    #[tokio::test]
    async fn binary_with_varlen_bigvarbin() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigVarBin, 40, None)),
            ColumnData::Binary(Some(b"aaa".as_slice().into())),
        )
        .await;
    }

    #[tokio::test]
    async fn none_binary_with_varlen_bigvarbin() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigVarBin, 40, None)),
            ColumnData::Binary(None),
        )
        .await;
    }

    #[tokio::test]
    async fn empty_binary_with_varlen_bigvarbin() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::BigVarBin,
                0x8ffff,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::Binary(Some(b"".as_slice().into())),
        )
        .await;
    }

    #[tokio::test]
    async fn datetime_with_varlen_datetimen() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Datetimen, 8, None)),
            ColumnData::DateTime(Some(DateTime::new(200, 3000))),
        )
        .await;
    }

    // this is inconsistent: decode will decode any None datetime to smalldatetime, ignoring size
    // but it's non-critical, so let it be here
    #[tokio::test]
    async fn none_datetime_with_varlen_datetimen() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Datetimen, 8, None)),
            ColumnData::DateTime(None),
        )
        .await;
    }

    #[tokio::test]
    async fn datetime_with_fixedlen_datetime() {
        test_round_trip(
            TypeInfo::FixedLen(FixedLenType::Datetime),
            ColumnData::DateTime(Some(DateTime::new(200, 3000))),
        )
        .await;
    }

    #[tokio::test]
    async fn smalldatetime_with_varlen_datetimen() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Datetimen, 4, None)),
            ColumnData::SmallDateTime(Some(SmallDateTime::new(200, 3000))),
        )
        .await;
    }

    #[tokio::test]
    async fn none_smalldatetime_with_varlen_datetimen() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Datetimen, 4, None)),
            ColumnData::SmallDateTime(None),
        )
        .await;
    }

    #[tokio::test]
    async fn smalldatetime_with_fixedlen_datetime4() {
        test_round_trip(
            TypeInfo::FixedLen(FixedLenType::Datetime4),
            ColumnData::SmallDateTime(Some(SmallDateTime::new(200, 3000))),
        )
        .await;
    }

    #[tokio::test]
    async fn date_with_varlen_daten() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Daten, 3, None)),
            ColumnData::Date(Some(Date::new(200))),
        )
        .await;
    }

    #[tokio::test]
    async fn none_date_with_varlen_daten() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Daten, 3, None)),
            ColumnData::Date(None),
        )
        .await;
    }

    #[tokio::test]
    async fn time_with_varlen_timen() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Timen, 7, None)),
            ColumnData::Time(Some(Time::new(55, 7))),
        )
        .await;
    }

    #[tokio::test]
    async fn none_time_with_varlen_timen() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Timen, 7, None)),
            ColumnData::Time(None),
        )
        .await;
    }

    #[tokio::test]
    async fn datetime2_with_varlen_datetime2() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Datetime2, 7, None)),
            ColumnData::DateTime2(Some(DateTime2::new(Date::new(55), Time::new(222, 7)))),
        )
        .await;
    }

    #[tokio::test]
    async fn none_datetime2_with_varlen_datetime2() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Datetime2, 7, None)),
            ColumnData::DateTime2(None),
        )
        .await;
    }

    #[tokio::test]
    async fn datetimeoffset_with_varlen_datetimeoffsetn() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::DatetimeOffsetn, 7, None)),
            ColumnData::DateTimeOffset(Some(DateTimeOffset::new(
                DateTime2::new(Date::new(55), Time::new(222, 7)),
                -8,
            ))),
        )
        .await;
    }

    #[tokio::test]
    async fn none_datetimeoffset_with_varlen_datetimeoffsetn() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::DatetimeOffsetn, 7, None)),
            ColumnData::DateTimeOffset(None),
        )
        .await;
    }

    #[tokio::test]
    async fn money_with_varlen_money() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Money, 8, None)),
            ColumnData::F64(Some(12.3456)),
        )
        .await;
    }

    #[tokio::test]
    async fn text_with_varlen_text() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::Text,
                20,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(Some("hello".into())),
        )
        .await;
    }

    #[tokio::test]
    async fn ntext_with_varlen_ntext() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::NText,
                20,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(Some("hello".into())),
        )
        .await;
    }

    #[tokio::test]
    async fn image_with_varlen_image() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Image, 12, None)),
            ColumnData::Binary(Some(vec![1, 2, 3, 4].into())),
        )
        .await;
    }

    #[tokio::test]
    async fn udt_with_type_info() {
        test_round_trip(
            TypeInfo::Udt(UdtInfo {
                max_len: 32,
                db_name: "db".into(),
                schema: "dbo".into(),
                type_name: "t".into(),
                assembly_name: "asm".into(),
            }),
            ColumnData::Udt(Some(vec![9, 8, 7].into())),
        )
        .await;
    }

    #[tokio::test]
    async fn ssvariant_with_type_info() {
        test_round_trip(
            TypeInfo::SsVariant(SsVariantInfo { max_len: 16 }),
            ColumnData::Variant(Some(VariantData::new(vec![
                0x38, 0x00, 0x2a, 0x00, 0x00, 0x00,
            ]))),
        )
        .await;
    }

    #[tokio::test]
    async fn ssvariant_typed_payload_round_trip() {
        let ty = TypeInfo::FixedLen(FixedLenType::Int4);
        let value = ColumnData::I32(Some(42));
        let payload = VariantData::from_typed(ty.clone(), value.clone())
            .expect("typed variant payload");
        let (decoded_ty, decoded_value) = payload
            .decode_typed()
            .await
            .expect("decode typed variant");
        assert_eq!(decoded_ty, ty);
        assert_eq!(decoded_value, value);
    }

    #[tokio::test]
    async fn xml_with_xml() {
        test_round_trip(
            TypeInfo::Xml {
                schema: None,
                size: 0xfffffffffffffffe_usize,
            },
            ColumnData::Xml(Some(Cow::Owned(XmlData::new("<a>ddd</a>")))),
        )
        .await;
    }

    #[tokio::test]
    async fn none_xml_with_xml() {
        test_round_trip(
            TypeInfo::Xml {
                schema: None,
                size: 0xfffffffffffffffe_usize,
            },
            ColumnData::Xml(None),
        )
        .await;
    }

    #[tokio::test]
    async fn invalid_type_fails() {
        let data = vec![
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Floatn, 4, None)),
                ColumnData::I32(Some(42)),
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Floatn, 4, None)),
                ColumnData::I32(None),
            ),
            (
                TypeInfo::FixedLen(FixedLenType::Int4),
                ColumnData::I32(None),
            ),
        ];

        for (ti, d) in data {
            let mut buf = BytesMut::new();
            let mut buf_ti = BytesMutWithTypeInfo::new(&mut buf).with_type_info(&ti);

            let err = d.encode(&mut buf_ti).expect_err("encode should fail");

            if let Error::BulkInput(_) = err {
            } else {
                panic!("Expected: Error::BulkInput, got: {:?}", err);
            }
        }
    }

    /// Test that sql_variant encodes correctly when no TypeInfo is provided
    /// (the RPC parameter path).
    #[tokio::test]
    async fn ssvariant_self_describing_encode() {
        // Build a typed variant payload
        let variant = VariantData::from_typed(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 4, None)),
            ColumnData::I32(Some(42)),
        )
        .unwrap();

        let mut buf = BytesMut::new();
        let mut dst = BytesMutWithTypeInfo::new(&mut buf);
        ColumnData::Variant(Some(variant.clone()))
            .encode(&mut dst)
            .expect("encode must succeed");

        // Decode: first read the TypeInfo header, then decode the value
        let reader = &mut buf.into_sql_read_bytes();
        let ti = TypeInfo::decode(reader).await.expect("TypeInfo decode");
        assert!(matches!(ti, TypeInfo::SsVariant(SsVariantInfo { max_len: 8016 })));

        let decoded = ColumnData::decode(reader, &ti)
            .await
            .expect("ColumnData decode");
        assert_eq!(decoded, ColumnData::Variant(Some(variant)));
    }

    /// Test that null sql_variant encodes correctly with no TypeInfo.
    #[tokio::test]
    async fn ssvariant_null_self_describing_encode() {
        let mut buf = BytesMut::new();
        let mut dst = BytesMutWithTypeInfo::new(&mut buf);
        ColumnData::Variant(None)
            .encode(&mut dst)
            .expect("encode must succeed");

        let reader = &mut buf.into_sql_read_bytes();
        let ti = TypeInfo::decode(reader).await.expect("TypeInfo decode");
        assert!(matches!(ti, TypeInfo::SsVariant(_)));

        let decoded = ColumnData::decode(reader, &ti)
            .await
            .expect("ColumnData decode");
        assert_eq!(decoded, ColumnData::Variant(None));
    }

    /// Test that TVP encodes correctly when no TypeInfo is provided
    /// (the RPC parameter path).
    #[tokio::test]
    async fn tvp_self_describing_encode() {
        let collation = Some(Collation::new(13632521, 52));
        let tvp = TvpData::new("MyTableType")
            .schema("dbo")
            .columns(vec![
                TvpColumn {
                    name: Cow::Borrowed("id"),
                    user_type: 0,
                    flags: ColumnFlag::Nullable.into(),
                    ty: TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 4, None)),
                },
                TvpColumn {
                    name: Cow::Borrowed("label"),
                    user_type: 0,
                    flags: ColumnFlag::Nullable.into(),
                    ty: TypeInfo::VarLenSized(VarLenContext::new(
                        VarLenType::NVarchar,
                        40,
                        collation,
                    )),
                },
            ])
            .rows(vec![
                vec![
                    ColumnData::I32(Some(1)),
                    ColumnData::String(Some("hello".into())),
                ],
            ]);

        let mut buf = BytesMut::new();
        let mut dst = BytesMutWithTypeInfo::new(&mut buf);
        ColumnData::Tvp(Some(tvp))
            .encode(&mut dst)
            .expect("encode must succeed");

        // Decode: first read the TypeInfo header, then decode the TVP value
        let reader = &mut buf.into_sql_read_bytes();
        let ti = TypeInfo::decode(reader).await.expect("TypeInfo decode");
        match &ti {
            TypeInfo::Tvp(info) => {
                assert_eq!(info.type_name, "MyTableType");
                assert_eq!(info.schema, "dbo");
            }
            other => panic!("expected TVP TypeInfo, got {:?}", other),
        }

        let decoded = ColumnData::decode(reader, &ti)
            .await
            .expect("ColumnData decode");

        match decoded {
            ColumnData::Tvp(Some(tvp)) => {
                assert_eq!(tvp.columns.len(), 2);
                assert_eq!(tvp.rows.len(), 1);
                assert_eq!(tvp.rows[0][0], ColumnData::I32(Some(1)));
                assert_eq!(
                    tvp.rows[0][1],
                    ColumnData::String(Some(Cow::Borrowed("hello")))
                );
            }
            other => panic!("expected TVP, got {:?}", other),
        }
    }

    /// Test that null TVP encodes correctly with no TypeInfo.
    #[tokio::test]
    async fn tvp_null_self_describing_encode() {
        let mut buf = BytesMut::new();
        let mut dst = BytesMutWithTypeInfo::new(&mut buf);
        ColumnData::Tvp(None)
            .encode(&mut dst)
            .expect("encode must succeed");

        let reader = &mut buf.into_sql_read_bytes();
        let ti = TypeInfo::decode(reader).await.expect("TypeInfo decode");
        assert!(matches!(ti, TypeInfo::Tvp(_)));

        let decoded = ColumnData::decode(reader, &ti)
            .await
            .expect("ColumnData decode");
        assert_eq!(decoded, ColumnData::Tvp(None));
    }

    /// Test ToSql / IntoSql for VariantData.
    #[tokio::test]
    async fn variant_to_sql_into_sql() {
        use crate::{IntoSql, ToSql};

        let variant = VariantData::from_typed(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 4, None)),
            ColumnData::I32(Some(99)),
        )
        .unwrap();

        // ToSql (by-ref)
        let cd = variant.to_sql();
        assert!(matches!(cd, ColumnData::Variant(Some(_))));

        // IntoSql (by-value)
        let cd = variant.clone().into_sql();
        assert!(matches!(cd, ColumnData::Variant(Some(_))));

        // Option<VariantData> None
        let none: Option<VariantData<'_>> = None;
        let cd = none.into_sql();
        assert!(matches!(cd, ColumnData::Variant(None)));
    }

    /// Test ToSql / IntoSql for TvpData.
    #[tokio::test]
    async fn tvp_to_sql_into_sql() {
        use crate::{IntoSql, ToSql};

        let tvp = TvpData::new("TestType")
            .schema("dbo")
            .columns(vec![TvpColumn {
                name: Cow::Borrowed("col1"),
                user_type: 0,
                flags: ColumnFlag::Nullable.into(),
                ty: TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 4, None)),
            }])
            .rows(vec![vec![ColumnData::I32(Some(1))]]);

        // ToSql
        let cd = tvp.to_sql();
        assert!(matches!(cd, ColumnData::Tvp(Some(_))));

        // IntoSql
        let cd = tvp.into_sql();
        assert!(matches!(cd, ColumnData::Tvp(Some(_))));
    }

    /// Test FromSql / FromSqlOwned for UdtData.
    #[tokio::test]
    async fn udt_from_sql() {
        use crate::{FromSql, FromSqlOwned, UdtData};

        let cd = ColumnData::Udt(Some(vec![9, 8, 7].into()));

        let result: Option<UdtData<'_>> = UdtData::from_sql(&cd).unwrap();
        assert_eq!(result.unwrap().as_bytes(), &[9, 8, 7]);

        let result: Option<UdtData<'static>> = UdtData::from_sql_owned(cd).unwrap();
        assert_eq!(result.unwrap().as_bytes(), &[9, 8, 7]);

        let null = ColumnData::Udt(None);
        let result: Option<UdtData<'_>> = UdtData::from_sql(&null).unwrap();
        assert!(result.is_none());

        let bytes = ColumnData::Udt(Some(vec![1, 2, 3].into()));
        assert!(<&[u8]>::from_sql(&bytes).is_err());
        assert!(Vec::<u8>::from_sql_owned(bytes).is_err());
    }

    /// Test FromSql / FromSqlOwned for VariantData.
    #[tokio::test]
    async fn variant_from_sql() {
        use crate::{FromSql, FromSqlOwned};

        let variant = VariantData::from_typed(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 4, None)),
            ColumnData::I32(Some(42)),
        )
        .unwrap();

        let cd = ColumnData::Variant(Some(variant.clone()));

        // FromSql (borrowed)
        let result: Option<&VariantData<'static>> =
            <&VariantData<'static>>::from_sql(&cd).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().payload(), variant.payload());

        // FromSqlOwned
        let result: Option<VariantData<'static>> =
            VariantData::from_sql_owned(cd).unwrap();
        assert!(result.is_some());
    }

    /// Test FromSql / FromSqlOwned for TvpData.
    #[tokio::test]
    async fn tvp_from_sql() {
        use crate::{FromSql, FromSqlOwned};

        let tvp = TvpData::new("")
            .columns(vec![TvpColumn {
                name: Cow::Borrowed("x"),
                user_type: 0,
                flags: ColumnFlag::Nullable.into(),
                ty: TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 4, None)),
            }])
            .rows(vec![vec![ColumnData::I32(Some(7))]]);

        let cd = ColumnData::Tvp(Some(tvp));

        // FromSql (borrowed)
        let result: Option<&TvpData<'static>> =
            <&TvpData<'static>>::from_sql(&cd).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().rows.len(), 1);

        // FromSqlOwned
        let result: Option<TvpData<'static>> =
            TvpData::from_sql_owned(cd).unwrap();
        assert!(result.is_some());
    }
}
