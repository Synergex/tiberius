use crate::{
    error::Error,
    tds::{
        codec::{
            ColumnData, ColumnFlag, FixedLenType, MetaDataColumn, SsVariantInfo, TokenRow,
            TypeInfo, UdtInfo, VarLenType,
        },
        xml::XmlSchema,
    },
    FromSql,
};
use enumflags2::BitFlags;
use std::{fmt::Display, sync::Arc};

/// A column of data from a query.
#[derive(Debug, Clone)]
pub struct Column {
    pub(crate) name: String,
    pub(crate) column_type: ColumnType,
    pub(crate) type_info: Option<TypeInfo>,
    pub(crate) flags: BitFlags<ColumnFlag>,
    pub(crate) ordinal: Option<usize>,
}

impl Column {
    /// Construct a new Column.
    pub fn new(name: String, column_type: ColumnType) -> Self {
        Self {
            name,
            column_type,
            type_info: None,
            flags: BitFlags::empty(),
            ordinal: None,
        }
    }

    pub(crate) fn from_metadata(ordinal: usize, metadata: &MetaDataColumn<'_>) -> Self {
        Self {
            name: metadata.col_name.to_string(),
            column_type: ColumnType::from(&metadata.base.ty),
            type_info: Some(metadata.base.ty.clone()),
            flags: metadata.base.flags,
            ordinal: Some(ordinal),
        }
    }

    /// The name of the column.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The type of the column.
    pub fn column_type(&self) -> ColumnType {
        self.column_type
    }

    /// The zero-based result-set ordinal decoded from `COLMETADATA`.
    ///
    /// Returns `None` for columns constructed manually with [`Column::new`].
    pub fn ordinal(&self) -> Option<usize> {
        self.ordinal
    }

    /// The full TDS type information decoded from `COLMETADATA`.
    ///
    /// Returns `None` for columns constructed manually with [`Column::new`].
    pub fn type_info(&self) -> Option<&TypeInfo> {
        self.type_info.as_ref()
    }

    /// The raw column flags decoded from `COLMETADATA`.
    pub fn flags(&self) -> BitFlags<ColumnFlag> {
        self.flags
    }

    /// Whether the server reported that this column can contain null values.
    pub fn is_nullable(&self) -> bool {
        self.flags.contains(ColumnFlag::Nullable)
    }

    /// Whether the server reported that this column's nullability is unknown.
    pub fn is_nullable_unknown(&self) -> bool {
        self.flags.contains(ColumnFlag::NullableUnknown)
    }

    /// The fixed-length TDS type, if this column has one.
    pub fn fixed_len_type(&self) -> Option<FixedLenType> {
        match self.type_info.as_ref()? {
            TypeInfo::FixedLen(ty) => Some(*ty),
            _ => None,
        }
    }

    /// The variable-length TDS type marker, if this column has one.
    pub fn var_len_type(&self) -> Option<VarLenType> {
        match self.type_info.as_ref()? {
            TypeInfo::FixedLen(_) => None,
            TypeInfo::VarLenSized(cx) => Some(cx.r#type()),
            TypeInfo::VarLenSizedPrecision { ty, .. } => Some(*ty),
            TypeInfo::Xml { .. } => Some(VarLenType::Xml),
            TypeInfo::Udt(_) => Some(VarLenType::Udt),
            TypeInfo::SsVariant(_) => Some(VarLenType::SSVariant),
            TypeInfo::Tvp(_) => Some(VarLenType::Tvp),
        }
    }

    /// The bounded declared length decoded from `COLMETADATA`.
    ///
    /// Returns `None` for unbounded `max`/PLP/LOB-like metadata and for types
    /// whose metadata does not carry a declared length.
    pub fn declared_length(&self) -> Option<usize> {
        match self.type_info.as_ref()? {
            TypeInfo::VarLenSized(cx) if is_unlimited_var_len(cx.r#type(), cx.len()) => None,
            TypeInfo::VarLenSized(cx) => Some(cx.len()),
            TypeInfo::VarLenSizedPrecision { size, .. } => Some(*size),
            TypeInfo::Udt(info) if info.max_len == u16::MAX => None,
            TypeInfo::Udt(info) => Some(info.max_len as usize),
            TypeInfo::SsVariant(info) => Some(info.max_len as usize),
            TypeInfo::FixedLen(_) | TypeInfo::Xml { .. } | TypeInfo::Tvp(_) => None,
        }
    }

    /// Whether this column uses unbounded `max`, PLP/XML, or LOB-like storage.
    pub fn is_unlimited_length(&self) -> bool {
        match self.type_info.as_ref() {
            Some(TypeInfo::VarLenSized(cx)) => is_unlimited_var_len(cx.r#type(), cx.len()),
            Some(TypeInfo::Xml { .. }) => true,
            Some(TypeInfo::Udt(info)) => info.max_len == u16::MAX,
            _ => false,
        }
    }

    /// Decimal/numeric precision decoded from `COLMETADATA`.
    pub fn precision(&self) -> Option<u8> {
        match self.type_info.as_ref()? {
            TypeInfo::VarLenSizedPrecision { precision, .. } => Some(*precision),
            _ => None,
        }
    }

    /// Decimal/numeric scale decoded from `COLMETADATA`.
    pub fn scale(&self) -> Option<u8> {
        match self.type_info.as_ref()? {
            TypeInfo::VarLenSizedPrecision { scale, .. } => Some(*scale),
            _ => None,
        }
    }

    /// Fractional seconds scale for `time`, `datetime2`, and `datetimeoffset`.
    pub fn fractional_scale(&self) -> Option<u8> {
        match self.type_info.as_ref()? {
            TypeInfo::VarLenSized(cx)
                if matches!(
                    cx.r#type(),
                    VarLenType::Timen | VarLenType::Datetime2 | VarLenType::DatetimeOffsetn
                ) =>
            {
                Some(cx.len() as u8)
            }
            _ => None,
        }
    }

    /// Whether this column is XML.
    pub fn is_xml(&self) -> bool {
        matches!(self.type_info, Some(TypeInfo::Xml { .. }))
    }

    /// XML schema metadata, if the XML column is schema-bound.
    #[allow(clippy::option_as_ref_deref)]
    pub fn xml_schema(&self) -> Option<&XmlSchema> {
        match self.type_info.as_ref()? {
            TypeInfo::Xml { schema, .. } => schema.as_ref().map(|schema| &**schema),
            _ => None,
        }
    }

    /// XML PLP size decoded from `COLMETADATA`.
    pub fn xml_size(&self) -> Option<usize> {
        match self.type_info.as_ref()? {
            TypeInfo::Xml { size, .. } => Some(*size),
            _ => None,
        }
    }

    /// Whether this column is a CLR user-defined type.
    pub fn is_udt(&self) -> bool {
        matches!(self.type_info, Some(TypeInfo::Udt(_)))
    }

    /// CLR user-defined type metadata.
    pub fn udt_info(&self) -> Option<&UdtInfo> {
        match self.type_info.as_ref()? {
            TypeInfo::Udt(info) => Some(info),
            _ => None,
        }
    }

    /// Whether this column is `sql_variant`.
    pub fn is_sql_variant(&self) -> bool {
        matches!(self.type_info, Some(TypeInfo::SsVariant(_)))
    }

    /// `sql_variant` metadata.
    pub fn sql_variant_info(&self) -> Option<&SsVariantInfo> {
        match self.type_info.as_ref()? {
            TypeInfo::SsVariant(info) => Some(info),
            _ => None,
        }
    }
}

fn is_unlimited_var_len(ty: VarLenType, len: usize) -> bool {
    match ty {
        VarLenType::BigVarBin | VarLenType::BigVarChar | VarLenType::NVarchar => {
            len == u16::MAX as usize
        }
        VarLenType::Text | VarLenType::NText | VarLenType::Image | VarLenType::Xml => true,
        _ => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The type of the column.
pub enum ColumnType {
    /// The column doesn't have a specified type.
    Null,
    /// A bit or boolean value.
    Bit,
    /// An 8-bit integer value.
    Int1,
    /// A 16-bit integer value.
    Int2,
    /// A 32-bit integer value.
    Int4,
    /// A 64-bit integer value.
    Int8,
    /// A 32-bit datetime value.
    Datetime4,
    /// A 32-bit floating point value.
    Float4,
    /// A 64-bit floating point value.
    Float8,
    /// Money value.
    Money,
    /// A TDS 7.2 datetime value.
    Datetime,
    /// A 32-bit money value.
    Money4,
    /// A unique identifier, UUID.
    Guid,
    /// N-bit integer value (variable).
    Intn,
    /// A bit value in a variable-length type.
    Bitn,
    /// A decimal value (same as `Numericn`).
    Decimaln,
    /// A legacy decimal value.
    Decimal,
    /// A numeric value (same as `Decimaln`).
    Numericn,
    /// A legacy numeric value.
    Numeric,
    /// A n-bit floating point value.
    Floatn,
    /// A n-bit datetime value (TDS 7.2).
    Datetimen,
    /// A n-bit date value (TDS 7.3).
    Daten,
    /// A n-bit time value (TDS 7.3).
    Timen,
    /// A n-bit datetime2 value (TDS 7.3).
    Datetime2,
    /// A n-bit datetime value with an offset (TDS 7.3).
    DatetimeOffsetn,
    /// A variable binary value.
    BigVarBin,
    /// A large variable string value.
    BigVarChar,
    /// A binary value.
    BigBinary,
    /// A string value.
    BigChar,
    /// A variable binary value with 1-byte length.
    VarBinary,
    /// A variable string value with 1-byte length.
    VarChar,
    /// A binary value with 1-byte length.
    Binary,
    /// A string value with 1-byte length.
    Char,
    /// A variable string value with UTF-16 encoding.
    NVarchar,
    /// A string value with UTF-16 encoding.
    NChar,
    /// A XML value.
    Xml,
    /// User-defined type.
    Udt,
    /// A text value (deprecated).
    Text,
    /// A image value (deprecated).
    Image,
    /// A text value with UTF-16 encoding (deprecated).
    NText,
    /// An SQL variant type.
    SSVariant,
    /// A table-valued parameter.
    Tvp,
}

impl From<&TypeInfo> for ColumnType {
    fn from(ti: &TypeInfo) -> Self {
        match ti {
            TypeInfo::FixedLen(flt) => match flt {
                FixedLenType::Int1 => Self::Int1,
                FixedLenType::Bit => Self::Bit,
                FixedLenType::Int2 => Self::Int2,
                FixedLenType::Int4 => Self::Int4,
                FixedLenType::Datetime4 => Self::Datetime4,
                FixedLenType::Float4 => Self::Float4,
                FixedLenType::Money => Self::Money,
                FixedLenType::Datetime => Self::Datetime,
                FixedLenType::Float8 => Self::Float8,
                FixedLenType::Money4 => Self::Money4,
                FixedLenType::Int8 => Self::Int8,
                FixedLenType::Null => Self::Null,
            },
            TypeInfo::VarLenSized(cx) => match cx.r#type() {
                VarLenType::Guid => Self::Guid,
                VarLenType::Intn => match cx.len() {
                    1 => Self::Int1,
                    2 => Self::Int2,
                    4 => Self::Int4,
                    8 => Self::Int8,
                    _ => Self::Intn,
                },
                VarLenType::Bitn => Self::Bitn,
                VarLenType::Decimaln => Self::Decimaln,
                VarLenType::Decimal => Self::Decimal,
                VarLenType::Numericn => Self::Numericn,
                VarLenType::Numeric => Self::Numeric,
                VarLenType::Floatn => match cx.len() {
                    4 => Self::Float4,
                    8 => Self::Float8,
                    _ => Self::Floatn,
                },
                VarLenType::Money => Self::Money,
                VarLenType::Datetimen => Self::Datetimen,
                VarLenType::Daten => Self::Daten,
                VarLenType::Timen => Self::Timen,
                VarLenType::Datetime2 => Self::Datetime2,
                VarLenType::DatetimeOffsetn => Self::DatetimeOffsetn,
                VarLenType::BigVarBin => Self::BigVarBin,
                VarLenType::BigVarChar => Self::BigVarChar,
                VarLenType::BigBinary => Self::BigBinary,
                VarLenType::BigChar => Self::BigChar,
                VarLenType::VarBinary => Self::VarBinary,
                VarLenType::VarChar => Self::VarChar,
                VarLenType::Binary => Self::Binary,
                VarLenType::Char => Self::Char,
                VarLenType::NVarchar => Self::NVarchar,
                VarLenType::NChar => Self::NChar,
                VarLenType::Xml => Self::Xml,
                VarLenType::Udt => Self::Udt,
                VarLenType::Text => Self::Text,
                VarLenType::Image => Self::Image,
                VarLenType::NText => Self::NText,
                VarLenType::SSVariant => Self::SSVariant,
                VarLenType::Tvp => Self::Tvp,
            },
            TypeInfo::VarLenSizedPrecision { ty, .. } => match ty {
                VarLenType::Guid => Self::Guid,
                VarLenType::Intn => Self::Intn,
                VarLenType::Bitn => Self::Bitn,
                VarLenType::Decimaln => Self::Decimaln,
                VarLenType::Decimal => Self::Decimal,
                VarLenType::Numericn => Self::Numericn,
                VarLenType::Numeric => Self::Numeric,
                VarLenType::Floatn => Self::Floatn,
                VarLenType::Money => Self::Money,
                VarLenType::Datetimen => Self::Datetimen,
                VarLenType::Daten => Self::Daten,
                VarLenType::Timen => Self::Timen,
                VarLenType::Datetime2 => Self::Datetime2,
                VarLenType::DatetimeOffsetn => Self::DatetimeOffsetn,
                VarLenType::BigVarBin => Self::BigVarBin,
                VarLenType::BigVarChar => Self::BigVarChar,
                VarLenType::BigBinary => Self::BigBinary,
                VarLenType::BigChar => Self::BigChar,
                VarLenType::VarBinary => Self::VarBinary,
                VarLenType::VarChar => Self::VarChar,
                VarLenType::Binary => Self::Binary,
                VarLenType::Char => Self::Char,
                VarLenType::NVarchar => Self::NVarchar,
                VarLenType::NChar => Self::NChar,
                VarLenType::Xml => Self::Xml,
                VarLenType::Udt => Self::Udt,
                VarLenType::Text => Self::Text,
                VarLenType::Image => Self::Image,
                VarLenType::NText => Self::NText,
                VarLenType::SSVariant => Self::SSVariant,
                VarLenType::Tvp => Self::Tvp,
            },
            TypeInfo::Xml { .. } => Self::Xml,
            TypeInfo::Udt(_) => Self::Udt,
            TypeInfo::SsVariant(_) => Self::SSVariant,
            TypeInfo::Tvp(_) => Self::Tvp,
        }
    }
}

/// A row of data from a query.
///
/// Data can be accessed either by copying through [`get`] or [`try_get`]
/// methods, or moving by value using the [`IntoIterator`] implementation.
///
/// ```
/// # use tiberius::{Config, FromSqlOwned};
/// # use tokio_util::compat::TokioAsyncWriteCompatExt;
/// # use std::env;
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let c_str = env::var("TIBERIUS_TEST_CONNECTION_STRING").unwrap_or(
/// #     "server=tcp:localhost,1433;integratedSecurity=true;TrustServerCertificate=true".to_owned(),
/// # );
/// # let config = Config::from_ado_string(&c_str)?;
/// # let tcp = tokio::net::TcpStream::connect(config.get_addr()).await?;
/// # tcp.set_nodelay(true)?;
/// # let mut client = tiberius::Client::connect(config, tcp.compat_write()).await?;
/// // by-reference
/// let row = client
///     .query("SELECT @P1 AS col1", &[&"test"])
///     .await?
///     .into_row()
///     .await?
///     .unwrap();
///
/// assert_eq!(Some("test"), row.get("col1"));
///
/// // ...or by-value
/// let row = client
///     .query("SELECT @P1 AS col1", &[&"test"])
///     .await?
///     .into_row()
///     .await?
///     .unwrap();
///
/// for val in row.into_iter() {
///     assert_eq!(
///         Some(String::from("test")),
///         String::from_sql_owned(val)?
///     )
/// }
/// # Ok(())
/// # }
/// ```
///
/// [`get`]: #method.get
/// [`try_get`]: #method.try_get
/// [`IntoIterator`]: #impl-IntoIterator
#[derive(Debug)]
pub struct Row {
    pub(crate) columns: Arc<Vec<Column>>,
    pub(crate) data: TokenRow<'static>,
    pub(crate) result_index: usize,
}

pub trait QueryIdx
where
    Self: Display,
{
    fn idx(&self, row: &Row) -> Option<usize>;
}

impl QueryIdx for usize {
    fn idx(&self, _row: &Row) -> Option<usize> {
        Some(*self)
    }
}

impl QueryIdx for &str {
    fn idx(&self, row: &Row) -> Option<usize> {
        row.columns.iter().position(|c| c.name() == *self)
    }
}

impl Row {
    /// Columns defining the row data. Columns listed here are in the same order
    /// as the resulting data.
    ///
    /// # Example
    ///
    /// ```
    /// # use tiberius::Config;
    /// # use tokio_util::compat::TokioAsyncWriteCompatExt;
    /// # use std::env;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let c_str = env::var("TIBERIUS_TEST_CONNECTION_STRING").unwrap_or(
    /// #     "server=tcp:localhost,1433;integratedSecurity=true;TrustServerCertificate=true".to_owned(),
    /// # );
    /// # let config = Config::from_ado_string(&c_str)?;
    /// # let tcp = tokio::net::TcpStream::connect(config.get_addr()).await?;
    /// # tcp.set_nodelay(true)?;
    /// # let mut client = tiberius::Client::connect(config, tcp.compat_write()).await?;
    /// let row = client
    ///     .query("SELECT 1 AS foo, 2 AS bar", &[])
    ///     .await?
    ///     .into_row()
    ///     .await?
    ///     .unwrap();
    ///
    /// assert_eq!("foo", row.columns()[0].name());
    /// assert_eq!("bar", row.columns()[1].name());
    /// # Ok(())
    /// # }
    /// ```
    pub fn columns(&self) -> &[Column] {
        &self.columns
    }

    /// Return an iterator over row column-value pairs.
    pub fn cells(&self) -> impl Iterator<Item = (&Column, &ColumnData<'static>)> {
        self.columns().iter().zip(self.data.iter())
    }

    /// The result set number, starting from zero and increasing if the stream
    /// has results from more than one query.
    pub fn result_index(&self) -> usize {
        self.result_index
    }

    /// Returns the number of columns in the row.
    ///
    /// # Example
    ///
    /// ```
    /// # use tiberius::Config;
    /// # use tokio_util::compat::TokioAsyncWriteCompatExt;
    /// # use std::env;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let c_str = env::var("TIBERIUS_TEST_CONNECTION_STRING").unwrap_or(
    /// #     "server=tcp:localhost,1433;integratedSecurity=true;TrustServerCertificate=true".to_owned(),
    /// # );
    /// # let config = Config::from_ado_string(&c_str)?;
    /// # let tcp = tokio::net::TcpStream::connect(config.get_addr()).await?;
    /// # tcp.set_nodelay(true)?;
    /// # let mut client = tiberius::Client::connect(config, tcp.compat_write()).await?;
    /// let row = client
    ///     .query("SELECT 1, 2", &[])
    ///     .await?
    ///     .into_row()
    ///     .await?
    ///     .unwrap();
    ///
    /// assert_eq!(2, row.len());
    /// # Ok(())
    /// # }
    /// ```
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Retrieve a column value for a given column index, which can either be
    /// the zero-indexed position or the name of the column.
    ///
    /// # Example
    ///
    /// ```
    /// # use tiberius::Config;
    /// # use tokio_util::compat::TokioAsyncWriteCompatExt;
    /// # use std::env;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let c_str = env::var("TIBERIUS_TEST_CONNECTION_STRING").unwrap_or(
    /// #     "server=tcp:localhost,1433;integratedSecurity=true;TrustServerCertificate=true".to_owned(),
    /// # );
    /// # let config = Config::from_ado_string(&c_str)?;
    /// # let tcp = tokio::net::TcpStream::connect(config.get_addr()).await?;
    /// # tcp.set_nodelay(true)?;
    /// # let mut client = tiberius::Client::connect(config, tcp.compat_write()).await?;
    /// let row = client
    ///     .query("SELECT @P1 AS col1", &[&1i32])
    ///     .await?
    ///     .into_row()
    ///     .await?
    ///     .unwrap();
    ///
    /// assert_eq!(Some(1i32), row.get(0));
    /// assert_eq!(Some(1i32), row.get("col1"));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Panics
    ///
    /// - The requested type conversion (SQL->Rust) is not possible.
    /// - The given index is out of bounds (column does not exist).
    ///
    /// Use [`try_get`] for a non-panicking version of the function.
    ///
    /// [`try_get`]: #method.try_get
    #[track_caller]
    pub fn get<'a, R, I>(&'a self, idx: I) -> Option<R>
    where
        R: FromSql<'a>,
        I: QueryIdx,
    {
        self.try_get(idx).unwrap()
    }

    /// Retrieve a column's value for a given column index.
    #[track_caller]
    pub fn try_get<'a, R, I>(&'a self, idx: I) -> crate::Result<Option<R>>
    where
        R: FromSql<'a>,
        I: QueryIdx,
    {
        let idx = idx.idx(self).ok_or_else(|| {
            Error::Conversion(format!("Could not find column with index {}", idx).into())
        })?;

        let data = self.data.get(idx).unwrap();

        R::from_sql(data)
    }
}

impl IntoIterator for Row {
    type Item = ColumnData<'static>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        tds::{
            codec::{BaseMetaDataColumn, SsVariantInfo, TvpInfo, UdtInfo, VarLenContext},
            Collation,
        },
        xml::XmlSchema,
    };
    use std::{borrow::Cow, sync::Arc};

    fn column(
        name: &'static str,
        flags: BitFlags<ColumnFlag>,
        ty: TypeInfo,
    ) -> MetaDataColumn<'static> {
        MetaDataColumn {
            base: BaseMetaDataColumn {
                user_type: 0,
                flags,
                ty,
                table_name: None,
            },
            col_name: Cow::Borrowed(name),
        }
    }

    #[test]
    fn manual_column_has_legacy_metadata_shape() {
        let col = Column::new("manual".to_owned(), ColumnType::Int4);

        assert_eq!(col.name(), "manual");
        assert_eq!(col.column_type(), ColumnType::Int4);
        assert_eq!(col.ordinal(), None);
        assert_eq!(col.type_info(), None);
        assert!(col.flags().is_empty());
        assert_eq!(col.fixed_len_type(), None);
        assert_eq!(col.var_len_type(), None);
    }

    #[test]
    fn metadata_column_preserves_name_ordinal_flags_and_fixed_type() {
        let flags = ColumnFlag::Nullable | ColumnFlag::NullableUnknown;
        let meta = column("id", flags, TypeInfo::FixedLen(FixedLenType::Int4));
        let col = Column::from_metadata(3, &meta);

        assert_eq!(col.name(), "id");
        assert_eq!(col.ordinal(), Some(3));
        assert_eq!(col.column_type(), ColumnType::Int4);
        assert_eq!(
            col.type_info(),
            Some(&TypeInfo::FixedLen(FixedLenType::Int4))
        );
        assert_eq!(col.flags(), flags);
        assert!(col.is_nullable());
        assert!(col.is_nullable_unknown());
        assert_eq!(col.fixed_len_type(), Some(FixedLenType::Int4));
        assert_eq!(col.var_len_type(), None);
    }

    #[test]
    fn metadata_column_reports_bounded_and_max_variable_lengths() {
        let collation = Some(Collation::new(13632521, 52));
        let varchar = Column::from_metadata(
            0,
            &column(
                "varchar",
                BitFlags::empty(),
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigVarChar, 42, collation)),
            ),
        );
        assert_eq!(varchar.var_len_type(), Some(VarLenType::BigVarChar));
        assert_eq!(varchar.declared_length(), Some(42));
        assert!(!varchar.is_unlimited_length());

        let varchar_max = Column::from_metadata(
            1,
            &column(
                "varchar_max",
                BitFlags::empty(),
                TypeInfo::VarLenSized(VarLenContext::new(
                    VarLenType::BigVarChar,
                    u16::MAX as usize,
                    collation,
                )),
            ),
        );
        assert_eq!(varchar_max.var_len_type(), Some(VarLenType::BigVarChar));
        assert_eq!(varchar_max.declared_length(), None);
        assert!(varchar_max.is_unlimited_length());

        let nvarchar_max = Column::from_metadata(
            2,
            &column(
                "nvarchar_max",
                BitFlags::empty(),
                TypeInfo::VarLenSized(VarLenContext::new(
                    VarLenType::NVarchar,
                    u16::MAX as usize,
                    collation,
                )),
            ),
        );
        assert_eq!(nvarchar_max.var_len_type(), Some(VarLenType::NVarchar));
        assert_eq!(nvarchar_max.declared_length(), None);
        assert!(nvarchar_max.is_unlimited_length());

        let varbinary = Column::from_metadata(
            3,
            &column(
                "varbinary",
                BitFlags::empty(),
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigVarBin, 128, None)),
            ),
        );
        assert_eq!(varbinary.var_len_type(), Some(VarLenType::BigVarBin));
        assert_eq!(varbinary.declared_length(), Some(128));

        let varbinary_max = Column::from_metadata(
            4,
            &column(
                "varbinary_max",
                BitFlags::empty(),
                TypeInfo::VarLenSized(VarLenContext::new(
                    VarLenType::BigVarBin,
                    u16::MAX as usize,
                    None,
                )),
            ),
        );
        assert_eq!(varbinary_max.var_len_type(), Some(VarLenType::BigVarBin));
        assert_eq!(varbinary_max.declared_length(), None);
        assert!(varbinary_max.is_unlimited_length());

        let image = Column::from_metadata(
            5,
            &column(
                "image",
                BitFlags::empty(),
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Image, 16, None)),
            ),
        );
        assert_eq!(image.declared_length(), None);
        assert!(image.is_unlimited_length());
    }

    #[test]
    fn metadata_column_reports_decimal_precision_scale_and_fractional_scale() {
        let decimal = Column::from_metadata(
            0,
            &column(
                "amount",
                BitFlags::empty(),
                TypeInfo::VarLenSizedPrecision {
                    ty: VarLenType::Decimaln,
                    size: 9,
                    precision: 18,
                    scale: 4,
                },
            ),
        );
        assert_eq!(decimal.var_len_type(), Some(VarLenType::Decimaln));
        assert_eq!(decimal.declared_length(), Some(9));
        assert_eq!(decimal.precision(), Some(18));
        assert_eq!(decimal.scale(), Some(4));
        assert_eq!(decimal.fractional_scale(), None);

        for ty in [
            VarLenType::Timen,
            VarLenType::Datetime2,
            VarLenType::DatetimeOffsetn,
        ] {
            let col = Column::from_metadata(
                0,
                &column(
                    "temporal",
                    BitFlags::empty(),
                    TypeInfo::VarLenSized(VarLenContext::new(ty, 7, None)),
                ),
            );
            assert_eq!(col.fractional_scale(), Some(7));
        }
    }

    #[test]
    fn metadata_column_reports_xml_udt_and_sql_variant_markers() {
        let schema = Arc::new(XmlSchema::new("db", "dbo", "collection"));
        let xml = Column::from_metadata(
            0,
            &column(
                "payload",
                BitFlags::empty(),
                TypeInfo::Xml {
                    schema: Some(schema),
                    size: 0xfffffffffffffffe_usize,
                },
            ),
        );
        assert!(xml.is_xml());
        assert_eq!(xml.var_len_type(), Some(VarLenType::Xml));
        assert_eq!(xml.xml_schema().unwrap().collection(), "collection");
        assert_eq!(xml.xml_size(), Some(0xfffffffffffffffe_usize));
        assert_eq!(xml.declared_length(), None);
        assert!(xml.is_unlimited_length());

        let udt = Column::from_metadata(
            1,
            &column(
                "udt",
                BitFlags::empty(),
                TypeInfo::Udt(UdtInfo {
                    max_len: 512,
                    db_name: "db".into(),
                    schema: "dbo".into(),
                    type_name: "point".into(),
                    assembly_name: "assembly".into(),
                }),
            ),
        );
        assert!(udt.is_udt());
        assert_eq!(udt.var_len_type(), Some(VarLenType::Udt));
        assert_eq!(udt.udt_info().unwrap().type_name, "point");
        assert_eq!(udt.declared_length(), Some(512));

        let sql_variant = Column::from_metadata(
            2,
            &column(
                "variant",
                BitFlags::empty(),
                TypeInfo::SsVariant(SsVariantInfo { max_len: 8016 }),
            ),
        );
        assert!(sql_variant.is_sql_variant());
        assert_eq!(sql_variant.var_len_type(), Some(VarLenType::SSVariant));
        assert_eq!(sql_variant.sql_variant_info().unwrap().max_len, 8016);
        assert_eq!(sql_variant.declared_length(), Some(8016));

        let tvp = Column::from_metadata(
            3,
            &column(
                "tvp",
                BitFlags::empty(),
                TypeInfo::Tvp(TvpInfo {
                    db_name: "db".into(),
                    schema: "dbo".into(),
                    type_name: "table_type".into(),
                }),
            ),
        );
        assert_eq!(tvp.var_len_type(), Some(VarLenType::Tvp));
        assert_eq!(tvp.declared_length(), None);
    }
}
