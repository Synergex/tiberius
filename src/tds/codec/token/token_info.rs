use crate::{tds::codec::Encode, SqlReadBytes, TokenType};
use bytes::{BufMut, BytesMut};
use crate::tds::codec::token::{write_b_varchar, write_us_varchar};

/// An informational message from the server (`PRINT`, `RAISERROR` with
/// severity <= 10, and similar).
#[derive(Debug)]
pub struct TokenInfo {
    /// info number
    pub(crate) number: u32,
    /// error state
    pub(crate) state: u8,
    /// severity (<10: Info)
    pub(crate) class: u8,
    pub(crate) message: String,
    pub(crate) server: String,
    pub(crate) procedure: String,
    pub(crate) line: u32,
}

impl TokenInfo {
    /// Create a new info token for server responses.
    pub fn new(
        number: u32,
        state: u8,
        class: u8,
        message: impl Into<String>,
        server: impl Into<String>,
        procedure: impl Into<String>,
        line: u32,
    ) -> Self {
        Self {
            number,
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
        let _length = src.read_u16_le().await?;

        let number = src.read_u32_le().await?;
        let state = src.read_u8().await?;
        let class = src.read_u8().await?;
        let message = src.read_us_varchar().await?;
        let server = src.read_b_varchar().await?;
        let procedure = src.read_b_varchar().await?;
        let line = src.read_u32_le().await?;

        Ok(TokenInfo {
            number,
            state,
            class,
            message,
            server,
            procedure,
            line,
        })
    }

    /// The message number.
    pub fn number(&self) -> u32 {
        self.number
    }

    /// The error state, used as a modifier to the message number.
    pub fn state(&self) -> u8 {
        self.state
    }

    /// The class (severity) of the message. A class of less than 10
    /// indicates a purely informational message.
    pub fn class(&self) -> u8 {
        self.class
    }

    /// The message text.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The server name.
    pub fn server(&self) -> &str {
        &self.server
    }

    /// The name of the stored procedure that emitted the message, if any.
    pub fn procedure(&self) -> &str {
        &self.procedure
    }

    /// The line number in the SQL batch or stored procedure that emitted
    /// the message. Line numbers begin at 1. If not applicable, the value
    /// is 0.
    pub fn line(&self) -> u32 {
        self.line
    }
}

impl Encode<BytesMut> for TokenInfo {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        let mut payload = BytesMut::new();
        payload.put_u32_le(self.number);
        payload.put_u8(self.state);
        payload.put_u8(self.class);
        write_us_varchar(&mut payload, &self.message)?;
        write_b_varchar(&mut payload, &self.server)?;
        write_b_varchar(&mut payload, &self.procedure)?;
        payload.put_u32_le(self.line);

        dst.put_u8(TokenType::Info as u8);
        dst.put_u16_le(payload.len() as u16);
        dst.extend(payload);
        Ok(())
    }
}
