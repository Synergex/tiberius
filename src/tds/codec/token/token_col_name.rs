use crate::{tds::codec::Encode, Error, SqlReadBytes, TokenType};
use byteorder::{LittleEndian, ReadBytesExt};
use bytes::{BufMut, BytesMut};
use futures_util::io::AsyncReadExt;
use std::io::Cursor;

/// Column name token (TDS 4.2+ legacy metadata).
#[derive(Debug, Clone)]
pub struct TokenColName {
    pub names: Vec<String>,
}

impl TokenColName {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let len = src.read_u16_le().await? as usize;
        let mut bytes = vec![0u8; len];
        src.read_exact(&mut bytes).await?;

        let mut cursor = Cursor::new(bytes);
        let mut names = Vec::new();

        while (cursor.position() as usize) < len {
            let name_len = cursor.read_u8()? as usize;
            let mut units = Vec::with_capacity(name_len);
            for _ in 0..name_len {
                units.push(cursor.read_u16::<LittleEndian>()?);
            }
            let name = String::from_utf16(&units)?;
            names.push(name);
        }

        Ok(TokenColName { names })
    }
}

impl Encode<BytesMut> for TokenColName {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        let mut payload = BytesMut::new();

        for name in self.names {
            crate::tds::codec::write_b_varchar(&mut payload, &name)?;
        }

        if payload.len() > u16::MAX as usize {
            return Err(Error::Protocol("colname payload too long".into()));
        }

        dst.put_u8(TokenType::ColName as u8);
        dst.put_u16_le(payload.len() as u16);
        dst.extend(payload);
        Ok(())
    }
}
