use crate::{tds::codec::Encode, tds::Collation, Error, SqlReadBytes, TokenType};
use bytes::{BufMut, BytesMut};
use byteorder::{LittleEndian, ReadBytesExt};
use fmt::Debug;
use futures_util::io::AsyncReadExt;
use std::{
    convert::TryFrom,
    fmt,
    io::{Cursor, Read},
};

uint_enum! {
    #[repr(u8)]
    pub enum EnvChangeTy {
        Database = 1,
        Language = 2,
        CharacterSet = 3,
        PacketSize = 4,
        UnicodeDataSortingLID = 5,
        UnicodeDataSortingCFL = 6,
        SqlCollation = 7,
        /// below here: >= TDSv7.2
        BeginTransaction = 8,
        CommitTransaction = 9,
        RollbackTransaction = 10,
        EnlistDTCTransaction = 11,
        DefectTransaction = 12,
        Rtls = 13,
        PromoteTransaction = 15,
        TransactionManagerAddress = 16,
        TransactionEnded = 17,
        ResetConnection = 18,
        UserName = 19,
        /// below here: TDS v7.4
        Routing = 20,
    }
}

impl fmt::Display for EnvChangeTy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnvChangeTy::Database => write!(f, "Database"),
            EnvChangeTy::Language => write!(f, "Language"),
            EnvChangeTy::CharacterSet => write!(f, "CharacterSet"),
            EnvChangeTy::PacketSize => write!(f, "PacketSize"),
            EnvChangeTy::UnicodeDataSortingLID => write!(f, "UnicodeDataSortingLID"),
            EnvChangeTy::UnicodeDataSortingCFL => write!(f, "UnicodeDataSortingCFL"),
            EnvChangeTy::SqlCollation => write!(f, "SqlCollation"),
            EnvChangeTy::BeginTransaction => write!(f, "BeginTransaction"),
            EnvChangeTy::CommitTransaction => write!(f, "CommitTransaction"),
            EnvChangeTy::RollbackTransaction => write!(f, "RollbackTransaction"),
            EnvChangeTy::EnlistDTCTransaction => write!(f, "EnlistDTCTransaction"),
            EnvChangeTy::DefectTransaction => write!(f, "DefectTransaction"),
            EnvChangeTy::Rtls => write!(f, "RTLS"),
            EnvChangeTy::PromoteTransaction => write!(f, "PromoteTransaction"),
            EnvChangeTy::TransactionManagerAddress => write!(f, "TransactionManagerAddress"),
            EnvChangeTy::TransactionEnded => write!(f, "TransactionEnded"),
            EnvChangeTy::ResetConnection => write!(f, "ResetConnection"),
            EnvChangeTy::UserName => write!(f, "UserName"),
            EnvChangeTy::Routing => write!(f, "Routing"),
        }
    }
}

#[derive(Debug)]
pub enum TokenEnvChange {
    Database(String, String),
    Language(String, String),
    CharacterSet(String, String),
    PacketSize(u32, u32),
    UnicodeDataSortingLID(String, String),
    UnicodeDataSortingCFL(String, String),
    SqlCollation {
        old: Option<Collation>,
        new: Option<Collation>,
    },
    BeginTransaction([u8; 8]),
    CommitTransaction {
        new: Vec<u8>,
        old: Vec<u8>,
    },
    RollbackTransaction {
        new: Vec<u8>,
        old: Vec<u8>,
    },
    EnlistDtcTransaction([u8; 8]),
    DefectTransaction {
        new: Vec<u8>,
        old: Vec<u8>,
    },
    PromoteTransaction {
        old: Vec<u8>,
        dtc: Vec<u8>,
    },
    TransactionManagerAddress {
        old: Vec<u8>,
        address: Vec<u8>,
    },
    TransactionEnded {
        old: Vec<u8>,
        new: Vec<u8>,
    },
    ResetConnection,
    UserName(String, String),
    Routing {
        host: String,
        port: u16,
    },
    ChangeMirror(String),
    Ignored(EnvChangeTy),
}

impl fmt::Display for TokenEnvChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(ref old, ref new) => {
                write!(f, "Database change from '{}' to '{}'", old, new)
            }
            Self::Language(ref old, ref new) => {
                write!(f, "Language change from '{}' to '{}'", old, new)
            }
            Self::CharacterSet(ref old, ref new) => {
                write!(f, "Character set change from '{}' to '{}'", old, new)
            }
            Self::PacketSize(old, new) => {
                write!(f, "Packet size change from '{}' to '{}'", old, new)
            }
            Self::UnicodeDataSortingLID(ref old, ref new) => {
                write!(f, "Sorting LID change from '{}' to '{}'", old, new)
            }
            Self::UnicodeDataSortingCFL(ref old, ref new) => {
                write!(f, "Sorting CFL change from '{}' to '{}'", old, new)
            }
            Self::SqlCollation { old, new } => match (old, new) {
                (Some(old), Some(new)) => write!(f, "SQL collation change from {} to {}", old, new),
                (_, Some(new)) => write!(f, "SQL collation changed to {}", new),
                (_, _) => write!(f, "SQL collation change"),
            },
            Self::BeginTransaction(_) => write!(f, "Begin transaction"),
            Self::CommitTransaction { .. } => write!(f, "Commit transaction"),
            Self::RollbackTransaction { .. } => write!(f, "Rollback transaction"),
            Self::EnlistDtcTransaction(_) => write!(f, "Enlist DTC transaction"),
            Self::DefectTransaction { .. } => write!(f, "Defect transaction"),
            Self::PromoteTransaction { .. } => write!(f, "Promote transaction"),
            Self::TransactionManagerAddress { .. } => write!(f, "Transaction manager address"),
            Self::TransactionEnded { .. } => write!(f, "Transaction ended"),
            Self::ResetConnection => write!(f, "Reset connection"),
            Self::UserName(ref old, ref new) => {
                write!(f, "User name change from '{}' to '{}'", old, new)
            }
            Self::Routing { host, port } => write!(
                f,
                "Server requested routing to a new address: {}:{}",
                host, port
            ),
            Self::ChangeMirror(ref mirror) => write!(f, "Fallback mirror server: `{}`", mirror),
            Self::Ignored(ty) => write!(f, "Ignored env change: `{}`", ty),
        }
    }
}

impl TokenEnvChange {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let len = src.read_u16_le().await? as usize;

        // We read all the bytes now, due to whatever environment change tokens
        // we read, they might contain padding zeroes in the end we must
        // discard.
        let mut bytes = vec![0; len];
        src.read_exact(&mut bytes[0..len]).await?;

        let mut buf = Cursor::new(bytes);
        let ty_byte = buf.read_u8()?;

        let ty = EnvChangeTy::try_from(ty_byte)
            .map_err(|_| Error::Protocol(format!("invalid envchange type {:x}", ty_byte).into()))?;

        let token = match ty {
            EnvChangeTy::Database => {
                let new_value = read_b_varchar(&mut buf)?;
                let old_value = read_b_varchar(&mut buf)?;
                TokenEnvChange::Database(new_value, old_value)
            }
            EnvChangeTy::Language => {
                let new_value = read_b_varchar(&mut buf)?;
                let old_value = read_b_varchar(&mut buf)?;
                TokenEnvChange::Language(new_value, old_value)
            }
            EnvChangeTy::CharacterSet => {
                let new_value = read_b_varchar(&mut buf)?;
                let old_value = read_b_varchar(&mut buf)?;
                TokenEnvChange::CharacterSet(new_value, old_value)
            }
            EnvChangeTy::PacketSize => {
                let new_value = read_b_varchar(&mut buf)?;
                let old_value = read_b_varchar(&mut buf)?;
                TokenEnvChange::PacketSize(new_value.parse()?, old_value.parse()?)
            }
            EnvChangeTy::UnicodeDataSortingLID => {
                let new_value = read_b_varchar(&mut buf)?;
                let old_value = read_b_varchar(&mut buf)?;
                TokenEnvChange::UnicodeDataSortingLID(new_value, old_value)
            }
            EnvChangeTy::UnicodeDataSortingCFL => {
                let new_value = read_b_varchar(&mut buf)?;
                let old_value = read_b_varchar(&mut buf)?;
                TokenEnvChange::UnicodeDataSortingCFL(new_value, old_value)
            }
            EnvChangeTy::SqlCollation => {
                let len = buf.read_u8()? as usize;
                let mut new_value = vec![0; len];
                buf.read_exact(&mut new_value[0..len])?;

                let new = if len == 5 {
                    let new_sortid = new_value[4];
                    let new_info = u32::from_le_bytes([
                        new_value[0],
                        new_value[1],
                        new_value[2],
                        new_value[3],
                    ]);

                    Some(Collation::new(new_info, new_sortid))
                } else {
                    None
                };

                let len = buf.read_u8()? as usize;
                let mut old_value = vec![0; len];
                buf.read_exact(&mut old_value[0..len])?;

                let old = if len == 5 {
                    let old_sortid = old_value[4];
                    let old_info = u32::from_le_bytes([
                        old_value[0],
                        old_value[1],
                        old_value[2],
                        old_value[3],
                    ]);

                    Some(Collation::new(old_info, old_sortid))
                } else {
                    None
                };

                TokenEnvChange::SqlCollation { new, old }
            }
            EnvChangeTy::BeginTransaction => {
                let new_value = read_b_varbyte(&mut buf)?;
                let _old_value = read_b_varbyte(&mut buf)?;
                TokenEnvChange::BeginTransaction(parse_tx_descriptor(new_value)?)
            }
            EnvChangeTy::EnlistDTCTransaction => {
                let new_value = read_b_varbyte(&mut buf)?;
                let _old_value = read_b_varbyte(&mut buf)?;
                TokenEnvChange::EnlistDtcTransaction(parse_tx_descriptor(new_value)?)
            }
            EnvChangeTy::CommitTransaction => {
                let new = read_b_varbyte(&mut buf)?;
                let old = read_b_varbyte(&mut buf)?;
                TokenEnvChange::CommitTransaction { new, old }
            }
            EnvChangeTy::RollbackTransaction => {
                let new = read_b_varbyte(&mut buf)?;
                let old = read_b_varbyte(&mut buf)?;
                TokenEnvChange::RollbackTransaction { new, old }
            }
            EnvChangeTy::DefectTransaction => {
                let new = read_b_varbyte(&mut buf)?;
                let old = read_b_varbyte(&mut buf)?;
                TokenEnvChange::DefectTransaction { new, old }
            }
            EnvChangeTy::PromoteTransaction => {
                let old = read_b_varbyte(&mut buf)?;
                let dtc = read_b_varbyte(&mut buf)?;
                TokenEnvChange::PromoteTransaction { old, dtc }
            }
            EnvChangeTy::TransactionManagerAddress => {
                let old = read_b_varbyte(&mut buf)?;
                let address = read_b_varbyte(&mut buf)?;
                TokenEnvChange::TransactionManagerAddress { old, address }
            }
            EnvChangeTy::TransactionEnded => {
                let old = read_b_varbyte(&mut buf)?;
                let new = read_b_varbyte(&mut buf)?;
                TokenEnvChange::TransactionEnded { old, new }
            }
            EnvChangeTy::ResetConnection => {
                let _old = read_b_varbyte(&mut buf)?;
                let _new = read_b_varbyte(&mut buf)?;
                TokenEnvChange::ResetConnection
            }
            EnvChangeTy::UserName => {
                let new_value = read_b_varchar(&mut buf)?;
                let old_value = read_b_varchar(&mut buf)?;
                TokenEnvChange::UserName(new_value, old_value)
            }

            EnvChangeTy::Routing => {
                buf.read_u16::<LittleEndian>()?; // routing data value length
                buf.read_u8()?; // routing protocol, always 0 (tcp)

                let port = buf.read_u16::<LittleEndian>()?;

                let len = buf.read_u16::<LittleEndian>()? as usize; // hostname string length
                let mut bytes = vec![0; len];

                for item in bytes.iter_mut().take(len) {
                    *item = buf.read_u16::<LittleEndian>()?;
                }

                let host = String::from_utf16(&bytes[..])?;

                TokenEnvChange::Routing { host, port }
            }
            EnvChangeTy::Rtls => {
                let mirror_name = read_b_varchar(&mut buf)?;
                let _old = read_b_varchar(&mut buf)?;

                TokenEnvChange::ChangeMirror(mirror_name)
            }
        };

        Ok(token)
    }
}

impl Encode<BytesMut> for TokenEnvChange {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        let mut payload = BytesMut::new();

        match self {
            TokenEnvChange::Database(new, old) => {
                payload.put_u8(EnvChangeTy::Database as u8);
                write_len_prefixed_utf16(&mut payload, &new)?;
                write_len_prefixed_utf16(&mut payload, &old)?;
            }
            TokenEnvChange::Language(new, old) => {
                payload.put_u8(EnvChangeTy::Language as u8);
                write_len_prefixed_utf16(&mut payload, &new)?;
                write_len_prefixed_utf16(&mut payload, &old)?;
            }
            TokenEnvChange::CharacterSet(new, old) => {
                payload.put_u8(EnvChangeTy::CharacterSet as u8);
                write_len_prefixed_utf16(&mut payload, &new)?;
                write_len_prefixed_utf16(&mut payload, &old)?;
            }
            TokenEnvChange::PacketSize(new, old) => {
                payload.put_u8(EnvChangeTy::PacketSize as u8);
                write_len_prefixed_utf16(&mut payload, &new.to_string())?;
                write_len_prefixed_utf16(&mut payload, &old.to_string())?;
            }
            TokenEnvChange::UnicodeDataSortingLID(new, old) => {
                payload.put_u8(EnvChangeTy::UnicodeDataSortingLID as u8);
                write_len_prefixed_utf16(&mut payload, &new)?;
                write_len_prefixed_utf16(&mut payload, &old)?;
            }
            TokenEnvChange::UnicodeDataSortingCFL(new, old) => {
                payload.put_u8(EnvChangeTy::UnicodeDataSortingCFL as u8);
                write_len_prefixed_utf16(&mut payload, &new)?;
                write_len_prefixed_utf16(&mut payload, &old)?;
            }
            TokenEnvChange::SqlCollation { old, new } => {
                payload.put_u8(EnvChangeTy::SqlCollation as u8);
                write_collation(&mut payload, new)?;
                write_collation(&mut payload, old)?;
            }
            TokenEnvChange::BeginTransaction(desc) => {
                payload.put_u8(EnvChangeTy::BeginTransaction as u8);
                write_b_varbyte(&mut payload, &desc)?;
                write_b_varbyte(&mut payload, &[])?;
            }
            TokenEnvChange::CommitTransaction { new, old } => {
                payload.put_u8(EnvChangeTy::CommitTransaction as u8);
                write_b_varbyte(&mut payload, &new)?;
                write_b_varbyte(&mut payload, &old)?;
            }
            TokenEnvChange::RollbackTransaction { new, old } => {
                payload.put_u8(EnvChangeTy::RollbackTransaction as u8);
                write_b_varbyte(&mut payload, &new)?;
                write_b_varbyte(&mut payload, &old)?;
            }
            TokenEnvChange::EnlistDtcTransaction(desc) => {
                payload.put_u8(EnvChangeTy::EnlistDTCTransaction as u8);
                write_b_varbyte(&mut payload, &desc)?;
                write_b_varbyte(&mut payload, &[])?;
            }
            TokenEnvChange::DefectTransaction { new, old } => {
                payload.put_u8(EnvChangeTy::DefectTransaction as u8);
                write_b_varbyte(&mut payload, &new)?;
                write_b_varbyte(&mut payload, &old)?;
            }
            TokenEnvChange::PromoteTransaction { old, dtc } => {
                payload.put_u8(EnvChangeTy::PromoteTransaction as u8);
                write_b_varbyte(&mut payload, &old)?;
                write_b_varbyte(&mut payload, &dtc)?;
            }
            TokenEnvChange::TransactionManagerAddress { old, address } => {
                payload.put_u8(EnvChangeTy::TransactionManagerAddress as u8);
                write_b_varbyte(&mut payload, &old)?;
                write_b_varbyte(&mut payload, &address)?;
            }
            TokenEnvChange::TransactionEnded { old, new } => {
                payload.put_u8(EnvChangeTy::TransactionEnded as u8);
                write_b_varbyte(&mut payload, &old)?;
                write_b_varbyte(&mut payload, &new)?;
            }
            TokenEnvChange::ResetConnection => {
                payload.put_u8(EnvChangeTy::ResetConnection as u8);
                write_b_varbyte(&mut payload, &[])?;
                write_b_varbyte(&mut payload, &[])?;
            }
            TokenEnvChange::UserName(new, old) => {
                payload.put_u8(EnvChangeTy::UserName as u8);
                write_len_prefixed_utf16(&mut payload, &new)?;
                write_len_prefixed_utf16(&mut payload, &old)?;
            }
            TokenEnvChange::Routing { host, port } => {
                payload.put_u8(EnvChangeTy::Routing as u8);
                let units: Vec<u16> = host.encode_utf16().collect();
                let data_len = 1u32 + 2 + 2 + (units.len() as u32 * 2);
                if data_len > u16::MAX as u32 {
                    return Err(Error::Protocol("routing host too long".into()));
                }
                payload.put_u16_le(data_len as u16);
                payload.put_u8(0); // tcp protocol
                payload.put_u16_le(port);
                write_us_len_prefixed_utf16(&mut payload, &units)?;
            }
            TokenEnvChange::ChangeMirror(mirror) => {
                payload.put_u8(EnvChangeTy::Rtls as u8);
                write_len_prefixed_utf16(&mut payload, &mirror)?;
                write_len_prefixed_utf16(&mut payload, "")?;
            }
            TokenEnvChange::Ignored(_) => {
                return Err(Error::Protocol("env change encode unsupported".into()));
            }
        }

        dst.put_u8(TokenType::EnvChange as u8);
        dst.put_u16_le(payload.len() as u16);
        dst.extend(payload);
        Ok(())
    }
}

fn write_len_prefixed_utf16(dst: &mut BytesMut, value: &str) -> crate::Result<()> {
    let units: Vec<u16> = value.encode_utf16().collect();
    if units.len() > u8::MAX as usize {
        return Err(Error::Protocol("env change string too long".into()));
    }
    dst.put_u8(units.len() as u8);
    for unit in units {
        dst.put_u16_le(unit);
    }
    Ok(())
}

fn write_us_len_prefixed_utf16(dst: &mut BytesMut, units: &[u16]) -> crate::Result<()> {
    if units.len() > u16::MAX as usize {
        return Err(Error::Protocol("env change string too long".into()));
    }
    dst.put_u16_le(units.len() as u16);
    for unit in units {
        dst.put_u16_le(*unit);
    }
    Ok(())
}

fn write_collation(dst: &mut BytesMut, collation: Option<Collation>) -> crate::Result<()> {
    match collation {
        Some(c) => {
            dst.put_u8(5);
            dst.put_u32_le(c.info());
            dst.put_u8(c.sort_id());
        }
        None => {
            dst.put_u8(0);
        }
    }
    Ok(())
}

fn read_b_varchar(buf: &mut Cursor<Vec<u8>>) -> crate::Result<String> {
    let len = buf.read_u8()? as usize;
    let mut units = Vec::with_capacity(len);
    for _ in 0..len {
        units.push(buf.read_u16::<LittleEndian>()?);
    }
    String::from_utf16(&units).map_err(|_| Error::Utf16)
}

fn read_b_varbyte(buf: &mut Cursor<Vec<u8>>) -> crate::Result<Vec<u8>> {
    let len = buf.read_u8()? as usize;
    let mut bytes = vec![0u8; len];
    buf.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn parse_tx_descriptor(bytes: Vec<u8>) -> crate::Result<[u8; 8]> {
    if bytes.len() != 8 {
        return Err(Error::Protocol("invalid transaction descriptor length".into()));
    }
    let mut desc = [0u8; 8];
    desc.copy_from_slice(&bytes);
    Ok(desc)
}

fn write_b_varbyte(dst: &mut BytesMut, value: &[u8]) -> crate::Result<()> {
    if value.len() > u8::MAX as usize {
        return Err(Error::Protocol("env change byte array too long".into()));
    }
    dst.put_u8(value.len() as u8);
    dst.extend_from_slice(value);
    Ok(())
}
