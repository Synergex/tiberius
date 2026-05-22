use crate::{tds::codec::Encode, tds::codec::FeatureLevel, SqlReadBytes, TokenType};
use bytes::{BufMut, BytesMut};
use crate::tds::codec::token::{write_b_varchar, write_us_varchar};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
/// An error token returned from the server.
pub struct TokenError {
    /// ErrorCode
    pub(crate) code: u32,
    /// ErrorState (describing code)
    pub(crate) state: u8,
    /// The class (severity) of the error
    pub(crate) class: u8,
    /// The error message
    pub(crate) message: String,
    pub(crate) server: String,
    pub(crate) procedure: String,
    pub(crate) line: u32,
}

impl TokenError {
    pub fn new(
        code: u32,
        state: u8,
        class: u8,
        message: impl Into<String>,
        server: impl Into<String>,
        procedure: impl Into<String>,
        line: u32,
    ) -> Self {
        Self {
            code,
            state,
            class,
            message: message.into(),
            server: server.into(),
            procedure: procedure.into(),
            line,
        }
    }

    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let _length = src.read_u16_le().await? as usize;

        let code = src.read_u32_le().await?;
        let state = src.read_u8().await?;
        let class = src.read_u8().await?;

        let message = src.read_us_varchar().await?;
        let server = src.read_b_varchar().await?;
        let procedure = src.read_b_varchar().await?;

        let line = if src.context().version() > FeatureLevel::SqlServer2005 {
            src.read_u32_le().await?
        } else {
            src.read_u16_le().await? as u32
        };

        let token = TokenError {
            code,
            state,
            class,
            message,
            server,
            procedure,
            line,
        };

        Ok(token)
    }

    /// The error code, see descriptions from [the manual].
    ///
    /// [the manual]: https://docs.microsoft.com/en-us/sql/relational-databases/errors-events/database-engine-events-and-errors?view=sql-server-ver15
    pub fn code(&self) -> u32 {
        self.code
    }

    /// The error state, used as a modifier to the error number.
    pub fn state(&self) -> u8 {
        self.state
    }

    /// The class (severity) of the error. A class of less than 10 indicates an
    /// informational message.
    pub fn class(&self) -> u8 {
        self.class
    }

    /// The error message returned from the server.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The server name.
    pub fn server(&self) -> &str {
        &self.server
    }

    /// The name of the stored procedure causing the error.
    pub fn procedure(&self) -> &str {
        &self.procedure
    }

    /// The line number in the SQL batch or stored procedure that caused the
    /// error. Line numbers begin at 1. If the line number is not applicable to
    /// the message, the value is 0.
    pub fn line(&self) -> u32 {
        self.line
    }
}

impl Encode<BytesMut> for TokenError {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        let mut payload = BytesMut::new();
        payload.put_u32_le(self.code);
        payload.put_u8(self.state);
        payload.put_u8(self.class);
        write_us_varchar(&mut payload, &self.message)?;
        write_b_varchar(&mut payload, &self.server)?;
        write_b_varchar(&mut payload, &self.procedure)?;
        payload.put_u32_le(self.line);

        dst.put_u8(TokenType::Error as u8);
        dst.put_u16_le(payload.len() as u16);
        dst.extend(payload);
        Ok(())
    }
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "'{}' on server {} executing {} on line {} (code: {}, state: {}, class: {})",
            self.message, self.server, self.procedure, self.line, self.code, self.state, self.class
        )
    }
}
