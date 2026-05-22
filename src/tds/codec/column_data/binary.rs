use std::borrow::Cow;

use crate::{error::Error, sql_read_bytes::SqlReadBytes, ColumnData};

pub(crate) async fn decode<R>(src: &mut R, len: usize) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    let data = super::plp::decode(src, len).await?.map(Cow::from);

    Ok(ColumnData::Binary(data))
}

pub(crate) async fn decode_short<R>(
    src: &mut R,
    max_len: usize,
) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    let len = src.read_u8().await? as usize;
    if len == 0xff {
        return Ok(ColumnData::Binary(None));
    }

    if len > max_len {
        return Err(Error::Protocol(
            format!("varbinary: length {} exceeds column limit {}", len, max_len).into(),
        ));
    }

    let mut buf = Vec::with_capacity(len);
    for _ in 0..len {
        buf.push(src.read_u8().await?);
    }

    Ok(ColumnData::Binary(Some(Cow::Owned(buf))))
}
