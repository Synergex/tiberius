use crate::{tds::codec::Encode, Error, SqlReadBytes, TokenType};
use byteorder::{LittleEndian, ReadBytesExt};
use bytes::{BufMut, BytesMut};
use futures_util::io::AsyncReadExt;
use std::io::Cursor;

/// Table name token used with browse mode metadata.
#[derive(Debug, Clone)]
pub struct TokenTabName {
    pub tables: Vec<Vec<String>>,
}

impl TokenTabName {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let len = src.read_u16_le().await? as usize;
        let mut bytes = vec![0u8; len];
        src.read_exact(&mut bytes).await?;

        let mut cursor = Cursor::new(bytes);
        let mut tables = Vec::new();

        while (cursor.position() as usize) < len {
            let parts = cursor.read_u8()? as usize;
            let mut components = Vec::with_capacity(parts);
            for _ in 0..parts {
                let part_len = cursor.read_u16::<LittleEndian>()? as usize;
                let mut units = Vec::with_capacity(part_len);
                for _ in 0..part_len {
                    units.push(cursor.read_u16::<LittleEndian>()?);
                }
                let part = String::from_utf16(&units)?;
                components.push(part);
            }
            tables.push(components);
        }

        Ok(TokenTabName { tables })
    }
}

impl Encode<BytesMut> for TokenTabName {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        let mut payload = BytesMut::new();

        for table in self.tables {
            if table.len() > u8::MAX as usize {
                return Err(Error::Protocol("tabname has too many components".into()));
            }
            payload.put_u8(table.len() as u8);
            for component in table {
                crate::tds::codec::write_us_varchar(&mut payload, &component)?;
            }
        }

        if payload.len() > u16::MAX as usize {
            return Err(Error::Protocol("tabname payload too long".into()));
        }

        dst.put_u8(TokenType::TabName as u8);
        dst.put_u16_le(payload.len() as u16);
        dst.extend(payload);
        Ok(())
    }
}
