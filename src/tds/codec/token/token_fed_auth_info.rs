use crate::{Error, SqlReadBytes, TokenType};
use bytes::{BufMut, BytesMut};
use byteorder::{LittleEndian, ReadBytesExt};
use futures_util::io::AsyncReadExt;
use std::io::Cursor;

const FEDAUTH_INFO_ID_STSURL: u8 = 0x01;
const FEDAUTH_INFO_ID_SPN: u8 = 0x02;

#[derive(Debug, Clone)]
pub enum FedAuthInfoOption {
    StsUrl(String),
    Spn(String),
    Unknown { id: u8, data: Vec<u8> },
}

#[derive(Debug, Clone)]
pub struct TokenFedAuthInfo {
    pub options: Vec<FedAuthInfoOption>,
}

impl TokenFedAuthInfo {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let len = src.read_u32_le().await? as usize;
        if len < 4 {
            return Err(Error::Protocol("fedauthinfo payload too short".into()));
        }

        let count = src.read_u32_le().await? as usize;
        let remaining = len - 4;
        let mut bytes = vec![0u8; remaining];
        src.read_exact(&mut bytes).await?;

        let mut cursor = Cursor::new(bytes);
        let mut option_defs = Vec::with_capacity(count);
        for _ in 0..count {
            let id = cursor.read_u8()?;
            let data_len = cursor.read_u32::<LittleEndian>()? as usize;
            let data_offset = cursor.read_u32::<LittleEndian>()? as usize;
            option_defs.push((id, data_len, data_offset));
        }

        let option_bytes = count * 9;
        let mut options = Vec::with_capacity(count);
        let raw = cursor.into_inner();

        for (id, data_len, data_offset) in option_defs {
            if data_offset < 4 {
                return Err(Error::Protocol("fedauthinfo offset before payload".into()));
            }
            let offset = data_offset - 4;
            if offset < option_bytes || offset + data_len > raw.len() {
                return Err(Error::Protocol("fedauthinfo invalid offset".into()));
            }
            let data = &raw[offset..offset + data_len];
            match id {
                FEDAUTH_INFO_ID_STSURL => {
                    let text = decode_utf16(data)?;
                    options.push(FedAuthInfoOption::StsUrl(text));
                }
                FEDAUTH_INFO_ID_SPN => {
                    let text = decode_utf16(data)?;
                    options.push(FedAuthInfoOption::Spn(text));
                }
                _ => options.push(FedAuthInfoOption::Unknown {
                    id,
                    data: data.to_vec(),
                }),
            }
        }

        Ok(TokenFedAuthInfo { options })
    }
}

impl crate::tds::codec::Encode<BytesMut> for TokenFedAuthInfo {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        let mut payload = BytesMut::new();
        payload.put_u32_le(self.options.len() as u32);

        let option_bytes = self.options.len() * 9;
        let mut data_offset = 4 + option_bytes as u32;
        let mut data_blobs = Vec::with_capacity(self.options.len());

        for option in &self.options {
            let (id, data) = match option {
                FedAuthInfoOption::StsUrl(value) => (FEDAUTH_INFO_ID_STSURL, encode_utf16(value)),
                FedAuthInfoOption::Spn(value) => (FEDAUTH_INFO_ID_SPN, encode_utf16(value)),
                FedAuthInfoOption::Unknown { id, data } => (*id, data.clone()),
            };

            payload.put_u8(id);
            payload.put_u32_le(data.len() as u32);
            payload.put_u32_le(data_offset);
            data_offset += data.len() as u32;
            data_blobs.push(data);
        }

        for data in data_blobs {
            payload.extend_from_slice(&data);
        }

        dst.put_u8(TokenType::FedAuthInfo as u8);
        dst.put_u32_le(payload.len() as u32);
        dst.extend(payload);
        Ok(())
    }
}

fn decode_utf16(data: &[u8]) -> crate::Result<String> {
    if data.len() % 2 != 0 {
        return Err(Error::Protocol("fedauthinfo utf16 length invalid".into()));
    }
    let mut units = Vec::with_capacity(data.len() / 2);
    for chunk in data.chunks_exact(2) {
        units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    String::from_utf16(&units).map_err(|_| Error::Utf16)
}

fn encode_utf16(value: &str) -> Vec<u8> {
    value
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect()
}
