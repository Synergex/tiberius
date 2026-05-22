use crate::{tds::codec::Encode, SqlReadBytes, TokenType, FEA_EXT_FEDAUTH, FEA_EXT_TERMINATOR};
use bytes::{BufMut, BytesMut};
use futures_util::AsyncReadExt;

#[derive(Debug)]
pub struct TokenFeatureExtAck {
    pub features: Vec<FeatureAck>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum FedAuthAck {
    SecurityToken { nonce: Option<[u8; 32]> },
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum FeatureAck {
    FedAuth(FedAuthAck),
    Unknown { feature_id: u8, data: Vec<u8> },
}

impl TokenFeatureExtAck {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let mut features = Vec::new();
        loop {
            let feature_id = src.read_u8().await?;

            if feature_id == FEA_EXT_TERMINATOR {
                break;
            } else if feature_id == FEA_EXT_FEDAUTH {
                let data_len = src.read_u32_le().await?;

                let nonce = if data_len == 32 {
                    let mut n = [0u8; 32];
                    src.read_exact(&mut n).await?;
                    Some(n)
                } else if data_len == 0 {
                    None
                } else {
                    let mut raw = vec![0u8; data_len as usize];
                    src.read_exact(&mut raw).await?;
                    features.push(FeatureAck::Unknown {
                        feature_id,
                        data: raw,
                    });
                    continue;
                };

                features.push(FeatureAck::FedAuth(FedAuthAck::SecurityToken { nonce }));
            } else {
                let data_len = src.read_u32_le().await?;
                let mut raw = vec![0u8; data_len as usize];
                src.read_exact(&mut raw).await?;
                features.push(FeatureAck::Unknown {
                    feature_id,
                    data: raw,
                });
            }
        }

        Ok(TokenFeatureExtAck { features })
    }
}

impl Encode<BytesMut> for TokenFeatureExtAck {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        dst.put_u8(TokenType::FeatureExtAck as u8);
        for feature in self.features {
            match feature {
                FeatureAck::FedAuth(FedAuthAck::SecurityToken { nonce }) => {
                    dst.put_u8(FEA_EXT_FEDAUTH);
                    let len = nonce.map(|_| 32).unwrap_or(0);
                    dst.put_u32_le(len);
                    if let Some(n) = nonce {
                        dst.extend_from_slice(&n);
                    }
                }
                FeatureAck::Unknown { feature_id, data } => {
                    dst.put_u8(feature_id);
                    dst.put_u32_le(data.len() as u32);
                    dst.extend_from_slice(&data);
                }
            }
        }
        dst.put_u8(FEA_EXT_TERMINATOR);
        Ok(())
    }
}
