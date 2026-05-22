use crate::{sql_read_bytes::SqlReadBytes, ColumnData};
use futures_util::AsyncReadExt;

pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    let text_ptr_len = src.read_u8().await?;
    if text_ptr_len == 0 {
        return Ok(ColumnData::Binary(None));
    }
    let mut text_ptr = vec![0u8; text_ptr_len as usize];
    src.read_exact(&mut text_ptr).await?;
    let _timestamp = src.read_u64_le().await?;
    let len = src.read_u32_le().await?;
    if len == u32::MAX {
        return Ok(ColumnData::Binary(None));
    }
    let len = len as usize;
    let mut buf = Vec::with_capacity(len);

    for _ in 0..len {
        buf.push(src.read_u8().await?);
    }

    Ok(ColumnData::Binary(Some(buf.into())))
}
