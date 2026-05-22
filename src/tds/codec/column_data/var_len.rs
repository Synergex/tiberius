use crate::{
    sql_read_bytes::SqlReadBytes, tds::codec::VarLenContext, ColumnData, Error, VarLenType,
};

pub(crate) async fn decode<R>(
    src: &mut R,
    ctx: &VarLenContext,
) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    use VarLenType::*;

    let ty = ctx.r#type();
    let len = ctx.len();
    let collation = ctx.collation();

    let res = match ty {
        Bitn => super::bit::decode(src).await?,
        Intn => super::int::decode(src, len).await?,
        Floatn => super::float::decode(src, len).await?,
        Guid => super::guid::decode(src).await?,
        Char | VarChar => {
            ColumnData::String(super::string::decode_short(src, ty, len, collation).await?)
        }
        BigChar | BigVarChar | NChar | NVarchar => {
            ColumnData::String(super::string::decode(src, ty, len, collation).await?)
        }
        Money => {
            let len = src.read_u8().await?;
            super::money::decode(src, len).await?
        }
        Datetimen => {
            let rlen = src.read_u8().await?;
            super::datetimen::decode(src, rlen, len as u8).await?
        }
        Daten => super::date::decode(src).await?,
        Timen => super::time::decode(src, len).await?,
        Datetime2 => super::datetime2::decode(src, len).await?,
        DatetimeOffsetn => super::datetimeoffsetn::decode(src, len).await?,
        Binary | VarBinary => super::binary::decode_short(src, len).await?,
        BigBinary | BigVarBin => super::binary::decode(src, len).await?,
        Text => super::text::decode(src, collation).await?,
        NText => super::text::decode(src, None).await?,
        Image => super::image::decode(src).await?,
        t => {
            return Err(Error::Protocol(
                format!("varlen: unsupported type {:?}", t).into(),
            ))
        }
    };

    Ok(res)
}
