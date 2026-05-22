use super::{AllHeaderTy, Encode, ALL_HEADERS_LEN_TX};
use crate::{tds::codec::ColumnData, BytesMutWithTypeInfo, Result};
use bytes::{BufMut, BytesMut};
use enumflags2::{bitflags, BitFlags};
use std::borrow::BorrowMut;
use std::borrow::Cow;

#[bitflags]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RpcStatus {
    ByRefValue = 1 << 0,
    DefaultValue = 1 << 1,
    // reserved
    Encrypted = 1 << 3,
}

#[bitflags]
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RpcOption {
    WithRecomp = 1 << 0,
    NoMeta = 1 << 1,
    ReuseMeta = 1 << 2,
}

#[derive(Debug)]
pub struct TokenRpcRequest<'a> {
    proc_id: RpcProcIdValue<'a>,
    flags: BitFlags<RpcOption>,
    params: Vec<RpcParam<'a>>,
    transaction_desc: [u8; 8],
}

impl<'a> TokenRpcRequest<'a> {
    pub fn new<I>(proc_id: I, params: Vec<RpcParam<'a>>, transaction_desc: [u8; 8]) -> Self
    where
        I: Into<RpcProcIdValue<'a>>,
    {
        Self {
            proc_id: proc_id.into(),
            flags: BitFlags::empty(),
            params,
            transaction_desc,
        }
    }
}

#[derive(Debug)]
pub struct RpcParam<'a> {
    pub name: Cow<'a, str>,
    pub flags: BitFlags<RpcStatus>,
    pub value: ColumnData<'a>,
}

/// 2.2.6.6 RPC Request
#[allow(dead_code)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcProcId {
    CursorOpen = 2,
    CursorPrepExec = 5,
    CursorUnprepare = 6,
    CursorFetch = 7,
    CursorClose = 9,
    ExecuteSQL = 10,
    Prepare = 11,
    Execute = 12,
    PrepExec = 13,
    Unprepare = 15,
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum RpcProcIdValue<'a> {
    Name(Cow<'a, str>),
    Id(RpcProcId),
}

impl<'a, S> From<S> for RpcProcIdValue<'a>
where
    S: Into<Cow<'a, str>>,
{
    fn from(s: S) -> Self {
        Self::Name(s.into())
    }
}

impl<'a> From<RpcProcId> for RpcProcIdValue<'a> {
    fn from(id: RpcProcId) -> Self {
        Self::Id(id)
    }
}

impl<'a> Encode<BytesMut> for TokenRpcRequest<'a> {
    fn encode(self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u32_le(ALL_HEADERS_LEN_TX as u32);
        dst.put_u32_le(ALL_HEADERS_LEN_TX as u32 - 4);
        dst.put_u16_le(AllHeaderTy::TransactionDescriptor as u16);
        dst.put_slice(&self.transaction_desc);
        dst.put_u32_le(1);

        match self.proc_id {
            RpcProcIdValue::Id(ref id) => {
                let val = (0xffff_u32) | ((*id as u16) as u32) << 16;
                dst.put_u32_le(val);
            }
            RpcProcIdValue::Name(ref name) => {
                // NameLenProcID.NameLen: u16 length in UCS-2 code units.
                // A value of 0xFFFF signals "by ID"; anything else is the
                // length of the following UTF-16 LE procedure name.
                let codepoints: Vec<u16> = name.encode_utf16().collect();
                if codepoints.len() > u16::MAX as usize - 1 {
                    return Err(crate::Error::Protocol(
                        format!(
                            "RPC proc name too long ({} code units, max {})",
                            codepoints.len(),
                            u16::MAX - 1
                        )
                        .into(),
                    ));
                }
                dst.put_u16_le(codepoints.len() as u16);
                for cp in codepoints {
                    dst.put_u16_le(cp);
                }
            }
        }

        dst.put_u16_le(self.flags.bits());

        for param in self.params.into_iter() {
            param.encode(dst)?;
        }

        Ok(())
    }
}

impl<'a> Encode<BytesMut> for RpcParam<'a> {
    fn encode(self, dst: &mut BytesMut) -> Result<()> {
        let len_pos = dst.len();
        let mut length = 0u8;

        dst.put_u8(length);

        for codepoint in self.name.encode_utf16() {
            length += 1;
            dst.put_u16_le(codepoint);
        }

        dst.put_u8(self.flags.bits());

        let mut dst_fi = BytesMutWithTypeInfo::new(dst);
        self.value.encode(&mut dst_fi)?;

        let dst: &mut [u8] = dst.borrow_mut();
        dst[len_pos] = length;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_proc_id_uses_ffff_sentinel() {
        let req = TokenRpcRequest::new(RpcProcId::ExecuteSQL, Vec::new(), [0; 8]);
        let mut buf = BytesMut::new();
        req.encode(&mut buf).unwrap();

        let proc_id_word = &buf[ALL_HEADERS_LEN_TX..ALL_HEADERS_LEN_TX + 4];
        assert_eq!(
            proc_id_word,
            &[0xff, 0xff, RpcProcId::ExecuteSQL as u8, 0x00]
        );
    }

    #[test]
    fn encode_named_proc_writes_utf16_length_prefixed() {
        let req = TokenRpcRequest::new(
            Cow::Borrowed("my_sp"),
            Vec::new(),
            [0; 8],
        );
        let mut buf = BytesMut::new();
        req.encode(&mut buf).unwrap();

        let start = ALL_HEADERS_LEN_TX;
        let name_len = u16::from_le_bytes([buf[start], buf[start + 1]]);
        assert_eq!(name_len, 5);

        let chars_start = start + 2;
        let mut got = Vec::<u16>::new();
        for i in 0..(name_len as usize) {
            got.push(u16::from_le_bytes([
                buf[chars_start + i * 2],
                buf[chars_start + i * 2 + 1],
            ]));
        }
        let expected: Vec<u16> = "my_sp".encode_utf16().collect();
        assert_eq!(got, expected);

        // Flags follow the name.
        let flags_off = chars_start + name_len as usize * 2;
        assert_eq!(u16::from_le_bytes([buf[flags_off], buf[flags_off + 1]]), 0);
    }

    #[test]
    fn encode_named_proc_handles_non_ascii() {
        let req = TokenRpcRequest::new(Cow::Borrowed("spö"), Vec::new(), [0; 8]);
        let mut buf = BytesMut::new();
        req.encode(&mut buf).unwrap();

        let start = ALL_HEADERS_LEN_TX;
        let name_len = u16::from_le_bytes([buf[start], buf[start + 1]]);
        let expected: Vec<u16> = "spö".encode_utf16().collect();
        assert_eq!(name_len as usize, expected.len());
    }
}
