use crate::tds::codec::{BaseMetaDataColumn, Encode, MetaDataColumn};
use crate::{SqlReadBytes, TokenType};
use bytes::{BufMut, BytesMut};

/// Alternate metadata (compute result) token.
#[derive(Debug, Clone)]
pub struct TokenAltMetaData<'a> {
    pub id: u16,
    pub by_cols: Vec<u16>,
    pub columns: Vec<AltMetaDataColumn<'a>>,
}

#[derive(Debug, Clone)]
pub struct AltMetaDataColumn<'a> {
    pub operator: u8,
    pub operand: u16,
    pub column: MetaDataColumn<'a>,
}

impl TokenAltMetaData<'static> {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let column_count = src.read_u16_le().await?;
        let id = src.read_u16_le().await?;
        let by_cols_len = src.read_u8().await? as usize;

        let mut by_cols = Vec::with_capacity(by_cols_len);
        for _ in 0..by_cols_len {
            by_cols.push(src.read_u16_le().await?);
        }

        let mut columns = Vec::with_capacity(column_count as usize);
        for _ in 0..column_count {
            let operator = src.read_u8().await?;
            let operand = src.read_u16_le().await?;
            let base = BaseMetaDataColumn::decode(src).await?;
            let col_name = std::borrow::Cow::from(src.read_b_varchar().await?);

            columns.push(AltMetaDataColumn {
                operator,
                operand,
                column: MetaDataColumn { base, col_name },
            });
        }

        Ok(TokenAltMetaData {
            id,
            by_cols,
            columns,
        })
    }
}

impl<'a> Encode<BytesMut> for TokenAltMetaData<'a> {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        dst.put_u8(TokenType::AltMetaData as u8);
        dst.put_u16_le(self.columns.len() as u16);
        dst.put_u16_le(self.id);
        dst.put_u8(self.by_cols.len() as u8);
        for col in self.by_cols {
            dst.put_u16_le(col);
        }
        for column in self.columns {
            dst.put_u8(column.operator);
            dst.put_u16_le(column.operand);
            column.column.encode(dst)?;
        }

        Ok(())
    }
}
