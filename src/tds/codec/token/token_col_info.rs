use crate::{tds::codec::Encode, Error, SqlReadBytes, TokenType};
use bytes::{BufMut, BytesMut};
use futures_util::AsyncReadExt;

/// Raw COLINFO token payload.
#[derive(Debug, Clone)]
pub struct TokenColInfo {
    pub data: BytesMut,
}

impl TokenColInfo {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let len = src.read_u16_le().await? as usize;
        let mut data = BytesMut::with_capacity(len);
        if len > 0 {
            let mut buf = vec![0u8; len];
            src.read_exact(&mut buf).await?;
            data.extend_from_slice(&buf);
        }
        Ok(TokenColInfo { data })
    }
}

impl Encode<BytesMut> for TokenColInfo {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        if self.data.len() > u16::MAX as usize {
            return Err(Error::Protocol("colinfo: payload too large".into()));
        }
        dst.put_u8(TokenType::ColInfo as u8);
        dst.put_u16_le(self.data.len() as u16);
        dst.extend_from_slice(&self.data);
        Ok(())
    }
}
