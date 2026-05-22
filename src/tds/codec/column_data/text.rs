use crate::{error::Error, sql_read_bytes::SqlReadBytes, tds::Collation, ColumnData};
use futures_util::AsyncReadExt;

pub(crate) async fn decode<R>(
    src: &mut R,
    collation: Option<Collation>,
) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    let text_ptr_len = src.read_u8().await?;
    if text_ptr_len == 0 {
        return Ok(ColumnData::String(None));
    }
    let mut text_ptr = vec![0u8; text_ptr_len as usize];
    src.read_exact(&mut text_ptr).await?;
    let _timestamp = src.read_u64_le().await?;
    let text_len = src.read_u32_le().await?;
    if text_len == u32::MAX {
        return Ok(ColumnData::String(None));
    }

    let text = match collation {
        // TEXT
        Some(collation) => {
            let encoder = collation.encoding()?;
            let text_len = text_len as usize;
            let mut buf = Vec::with_capacity(text_len);

            for _ in 0..text_len {
                buf.push(src.read_u8().await?);
            }

            encoder
                .decode_without_bom_handling_and_without_replacement(buf.as_ref())
                .ok_or_else(|| Error::Encoding("invalid sequence".into()))?
                .to_string()
        }
        // NTEXT
        None => {
            if text_len % 2 != 0 {
                return Err(Error::Protocol("ntext: odd byte length".into()));
            }
            let text_len = text_len as usize / 2;
            let mut buf = Vec::with_capacity(text_len);

            for _ in 0..text_len {
                buf.push(src.read_u16_le().await?);
            }

            String::from_utf16(&buf[..])?
        }
    };

    Ok(ColumnData::String(Some(text.into())))
}
