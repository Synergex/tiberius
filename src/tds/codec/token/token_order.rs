use crate::{tds::codec::Encode, Error, SqlReadBytes, TokenType};
use bytes::{BufMut, BytesMut};

#[allow(dead_code)] // we might want to debug the values
#[derive(Debug)]
pub struct TokenOrder {
    pub(crate) column_indexes: Vec<u16>,
}

impl TokenOrder {
    pub fn new(column_indexes: Vec<u16>) -> Self {
        Self { column_indexes }
    }

    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let len = src.read_u16_le().await? / 2;

        let mut column_indexes = Vec::with_capacity(len as usize);

        for _ in 0..len {
            column_indexes.push(src.read_u16_le().await?);
        }

        Ok(TokenOrder { column_indexes })
    }
}

impl Encode<BytesMut> for TokenOrder {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        if self.column_indexes.len() > (u16::MAX as usize / 2) {
            return Err(Error::Protocol("order: too many columns".into()));
        }
        dst.put_u8(TokenType::Order as u8);
        dst.put_u16_le((self.column_indexes.len() * 2) as u16);
        for idx in self.column_indexes {
            dst.put_u16_le(idx);
        }
        Ok(())
    }
}
