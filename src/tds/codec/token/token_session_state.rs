use crate::{Error, SqlReadBytes, TokenType};
use bytes::{BufMut, BytesMut};
use byteorder::{LittleEndian, ReadBytesExt};
use futures_util::io::AsyncReadExt;
use std::io::{Cursor, Read};

#[derive(Debug, Clone)]
pub struct SessionStateEntry {
    pub id: u8,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TokenSessionState {
    pub sequence_number: u32,
    pub status: u8,
    pub entries: Vec<SessionStateEntry>,
}

impl TokenSessionState {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let len = src.read_u32_le().await? as usize;
        let mut bytes = vec![0u8; len];
        src.read_exact(&mut bytes).await?;

        if len < 5 {
            return Err(Error::Protocol("sessionstate payload too short".into()));
        }

        let mut cursor = Cursor::new(bytes);
        let sequence_number = cursor.read_u32::<LittleEndian>()?;
        let status = cursor.read_u8()?;

        let mut entries = Vec::new();
        while (cursor.position() as usize) < len {
            let id = cursor.read_u8()?;
            let mut entry_len = cursor.read_u8()? as usize;
            if entry_len == 0xFF {
                entry_len = cursor.read_u32::<LittleEndian>()? as usize;
            }
            let mut data = vec![0u8; entry_len];
            cursor.read_exact(&mut data)?;
            entries.push(SessionStateEntry { id, data });
        }

        Ok(TokenSessionState {
            sequence_number,
            status,
            entries,
        })
    }
}

impl crate::tds::codec::Encode<BytesMut> for TokenSessionState {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        let mut payload = BytesMut::new();

        payload.put_u32_le(self.sequence_number);
        payload.put_u8(self.status);

        for entry in self.entries {
            payload.put_u8(entry.id);
            if entry.data.len() >= 0xFF {
                payload.put_u8(0xFF);
                payload.put_u32_le(entry.data.len() as u32);
            } else {
                payload.put_u8(entry.data.len() as u8);
            }
            payload.extend_from_slice(&entry.data);
        }

        dst.put_u8(TokenType::SessionState as u8);
        dst.put_u32_le(payload.len() as u32);
        dst.extend(payload);
        Ok(())
    }
}
