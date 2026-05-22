use crate::tds::codec::{AltMetaDataColumn, ColumnData, Encode};
use crate::{Error, SqlReadBytes, TokenType};
use bytes::{BufMut, BytesMut};

/// Alternate row (compute row) token.
#[derive(Debug, Default, Clone)]
pub struct TokenAltRow<'a> {
    pub id: u16,
    data: Vec<ColumnData<'a>>,
}

impl<'a> TokenAltRow<'a> {
    pub fn with_capacity(id: u16, capacity: usize) -> Self {
        Self {
            id,
            data: Vec::with_capacity(capacity),
        }
    }

    pub fn push(&mut self, value: ColumnData<'a>) {
        self.data.push(value);
    }

    pub(crate) fn encode_with_columns<'b>(
        self,
        dst: &mut BytesMut,
        columns: &'b [AltMetaDataColumn<'b>],
    ) -> crate::Result<()> {
        dst.put_u8(TokenType::AltRow as u8);
        dst.put_u16_le(self.id);

        if self.data.len() != columns.len() {
            return Err(crate::Error::BulkInput(
                format!(
                    "Expecting {} columns but {} were given",
                    columns.len(),
                    self.data.len()
                )
                .into(),
            ));
        }

        for (value, column) in self.data.into_iter().zip(columns.iter()) {
            let mut dst_ti =
                crate::BytesMutWithTypeInfo::new(dst).with_type_info(&column.column.base.ty);
            value.encode(&mut dst_ti)?;
        }

        Ok(())
    }
}

impl TokenAltRow<'static> {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin + Send,
    {
        let id = src.read_u16_le().await?;
        let meta = src
            .context()
            .alt_meta(id)
            .ok_or_else(|| Error::Protocol("missing alt metadata".into()))?;

        let mut row = Self {
            id,
            data: Vec::with_capacity(meta.columns.len()),
        };

        for column in meta.columns.iter() {
            let data = ColumnData::decode(src, &column.column.base.ty).await?;
            row.data.push(data);
        }

        Ok(row)
    }
}
