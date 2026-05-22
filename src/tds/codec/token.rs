mod token_col_metadata;
mod token_col_info;
mod token_col_name;
mod token_done;
mod token_env_change;
mod token_error;
mod token_fed_auth_info;
mod token_feature_ext_ack;
mod token_info;
mod token_login_ack;
mod token_order;
mod token_alt_metadata;
mod token_alt_row;
mod token_return_value;
mod token_row;
mod token_sspi;
mod token_session_state;
mod token_tab_name;
mod token_type;

pub use token_col_metadata::*;
pub use token_col_info::*;
pub use token_col_name::*;
pub use token_done::*;
pub use token_env_change::*;
pub use token_error::*;
pub use token_fed_auth_info::*;
pub use token_feature_ext_ack::*;
pub use token_info::*;
pub use token_login_ack::*;
pub use token_order::*;
pub use token_alt_metadata::*;
pub use token_alt_row::*;
pub use token_return_value::*;
pub use token_row::*;
pub use token_sspi::*;
pub use token_session_state::*;
pub use token_tab_name::*;
pub use token_type::*;

use bytes::{BufMut, BytesMut};

pub(crate) fn write_b_varchar(dst: &mut BytesMut, s: &str) -> crate::Result<()> {
    let units: Vec<u16> = s.encode_utf16().collect();
    if units.len() > u8::MAX as usize {
        return Err(crate::Error::Protocol("b_varchar too long".into()));
    }
    dst.put_u8(units.len() as u8);
    for unit in units {
        dst.put_u16_le(unit);
    }
    Ok(())
}

pub(crate) fn write_us_varchar(dst: &mut BytesMut, s: &str) -> crate::Result<()> {
    let units: Vec<u16> = s.encode_utf16().collect();
    if units.len() > u16::MAX as usize {
        return Err(crate::Error::Protocol("us_varchar too long".into()));
    }
    dst.put_u16_le(units.len() as u16);
    for unit in units {
        dst.put_u16_le(unit);
    }
    Ok(())
}
