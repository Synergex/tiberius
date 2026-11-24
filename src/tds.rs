pub mod codec;
mod collation;
mod context;
pub mod numeric;
pub mod stream;
#[cfg(feature = "server-rustls")]
pub(crate) mod tls;
pub mod time;
pub mod xml;

pub use collation::Collation;
pub(crate) use context::*;
pub(crate) use numeric::*;

/// The amount of bytes a packet header consists of
pub(crate) const HEADER_BYTES: usize = 8;

uint_enum! {
    /// The configured encryption level specifying if encryption is required
    #[repr(u8)]
    pub enum EncryptionLevel {
        /// Require TLS for the login and use it for the full session if the
        /// server selects it. A server that declines TLS is rejected before login;
        /// use `NotSupported` to allow an unencrypted login.
        Off = 0,
        /// Encrypt everything if possible
        On = 1,
        /// Do not encrypt anything
        NotSupported = 2,
        /// Encrypt everything and fail if not possible
        Required = 3,
    }

}
