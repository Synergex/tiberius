use crate::{tds::codec::Encode, Error, FeatureLevel, SqlReadBytes, TokenType};
use bytes::BytesMut;
use bytes::BufMut;
use crate::tds::codec::token::write_b_varchar;
use std::convert::TryFrom;

#[allow(dead_code)] // we might want to debug the values
#[derive(Debug)]
pub struct TokenLoginAck {
    /// The type of interface with which the server will accept client requests
    /// 0: SQL_DFLT (server confirms that whatever is sent by the client is acceptable. If the client
    ///    requested SQL_DFLT, SQL_TSQL will be used)
    /// 1: SQL_TSQL (TSQL is accepted)
    pub(crate) interface: u8,
    pub(crate) tds_version: FeatureLevel,
    pub(crate) prog_name: String,
    /// major.minor.buildhigh.buildlow
    pub(crate) version: u32,
}

impl TokenLoginAck {
    pub fn new(
        interface: u8,
        tds_version: FeatureLevel,
        prog_name: impl Into<String>,
        version: u32,
    ) -> Self {
        Self {
            interface,
            tds_version,
            prog_name: prog_name.into(),
            version,
        }
    }

    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let _length = src.read_u16_le().await?;

        let interface = src.read_u8().await?;

        let tds_version = FeatureLevel::try_from(src.read_u32().await?)
            .map_err(|_| Error::Protocol("Login ACK: Invalid TDS version".into()))?;

        let prog_name = src.read_b_varchar().await?;
        let version = src.read_u32_le().await?;

        Ok(TokenLoginAck {
            interface,
            tds_version,
            prog_name,
            version,
        })
    }
}

impl Encode<BytesMut> for TokenLoginAck {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        let mut payload = BytesMut::new();
        payload.put_u8(self.interface);
        // TDS version is encoded big-endian in LOGINACK.
        payload.put_u32(self.tds_version as u32);
        write_b_varchar(&mut payload, &self.prog_name)?;
        payload.put_u32_le(self.version);

        dst.put_u8(TokenType::LoginAck as u8);
        dst.put_u16_le(payload.len() as u16);
        dst.extend(payload);
        Ok(())
    }
}
