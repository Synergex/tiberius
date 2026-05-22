//! TDS server message enums.

use bytes::BytesMut;

use crate::tds::codec::{
    Packet, PreloginMessage, RpcOption, RpcProcId, TokenAltMetaData, TokenAltRow, TokenColInfo,
    TokenColMetaData, TokenColName, TokenDone, TokenEnvChange, TokenError, TokenFedAuthInfo,
    TokenFeatureExtAck, TokenInfo, TokenLoginAck, TokenOrder, TokenReturnValue, TokenRow,
    TokenSessionState, TokenSspi, TokenTabName,
};
use enumflags2::BitFlags;

/// Packet status flags carried by the request.
#[derive(Debug, Clone, Copy, Default)]
pub struct RequestFlags {
    pub reset_connection: bool,
    pub reset_connection_skip_tran: bool,
}

impl RequestFlags {
    pub(crate) fn from_status_bits(bits: u8) -> Self {
        Self {
            reset_connection: (bits & crate::tds::codec::PacketStatus::ResetConnection as u8) != 0,
            reset_connection_skip_tran: (bits
                & crate::tds::codec::PacketStatus::ResetConnectionSkipTran as u8)
                != 0,
        }
    }
}

/// A TDS transaction descriptor (8 bytes).
///
/// Transaction descriptors are opaque 8-byte values that identify active
/// transactions. A zero descriptor indicates no active transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct TransactionDescriptor([u8; 8]);

impl TransactionDescriptor {
    /// A zero transaction descriptor indicating no active transaction.
    pub const NONE: Self = Self([0; 8]);

    /// Create a new transaction descriptor from raw bytes.
    pub fn new(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    /// Create a transaction descriptor from a slice.
    ///
    /// Returns `None` if the slice is not exactly 8 bytes.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 8 {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(bytes);
            Some(Self(arr))
        } else {
            None
        }
    }

    /// Get the raw bytes of the transaction descriptor.
    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }

    /// Convert to the raw byte array.
    pub fn into_bytes(self) -> [u8; 8] {
        self.0
    }

    /// Check if this is the zero (no transaction) descriptor.
    pub fn is_none(&self) -> bool {
        self.0 == [0; 8]
    }
}

impl From<[u8; 8]> for TransactionDescriptor {
    fn from(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }
}

impl From<TransactionDescriptor> for [u8; 8] {
    fn from(desc: TransactionDescriptor) -> Self {
        desc.0
    }
}

impl AsRef<[u8; 8]> for TransactionDescriptor {
    fn as_ref(&self) -> &[u8; 8] {
        &self.0
    }
}

/// ALL_HEADERS metadata parsed from SQL batch / RPC requests.
#[derive(Debug, Clone, Default)]
pub struct AllHeaders {
    pub transaction_descriptor: Option<TransactionDescriptorHeader>,
    pub query_descriptor: Option<Vec<u8>>,
    pub trace_activity: Option<TraceActivityHeader>,
    pub unknown: Vec<UnknownHeader>,
}

/// Transaction descriptor header from ALL_HEADERS.
#[derive(Debug, Clone)]
pub struct TransactionDescriptorHeader {
    /// The transaction descriptor value.
    pub descriptor: TransactionDescriptor,
    /// Number of outstanding requests in this transaction.
    pub outstanding_requests: u32,
}

#[derive(Debug, Clone)]
pub struct TraceActivityHeader {
    pub activity_id: [u8; 16],
    pub sequence_number: u32,
}

#[derive(Debug, Clone)]
pub struct UnknownHeader {
    pub header_type: u16,
    pub data: Vec<u8>,
}

/// Parsed SQL batch request.
#[derive(Debug)]
pub struct SqlBatchMessage {
    pub batch: String,
    pub headers: AllHeaders,
    pub request_flags: RequestFlags,
}

/// Frontend messages understood by the server.
#[derive(Debug)]
pub enum TdsFrontendMessage {
    Prelogin(PreloginMessage),
    Login(crate::tds::codec::LoginMessage<'static>),
    Sspi(TokenSspi),
    SqlBatch(SqlBatchMessage),
    Attention,
    BulkLoad(BytesMut),
    Rpc(RpcMessage),
    Packet(Packet),
}

impl TdsFrontendMessage {
    /// Returns a human-readable name for the message type.
    pub fn message_type_name(&self) -> &'static str {
        match self {
            Self::Prelogin(_) => "Prelogin",
            Self::Login(_) => "Login",
            Self::Sspi(_) => "SSPI",
            Self::SqlBatch(_) => "SqlBatch",
            Self::Attention => "Attention",
            Self::BulkLoad(_) => "BulkLoad",
            Self::Rpc(_) => "RPC",
            Self::Packet(_) => "Packet",
        }
    }
}

#[derive(Debug)]
pub struct RpcMessage {
    pub proc_id: Option<RpcProcId>,
    pub proc_name: Option<String>,
    pub flags: BitFlags<RpcOption>,
    pub params: BytesMut,
    pub headers: AllHeaders,
    pub request_flags: RequestFlags,
}

impl RpcMessage {
    /// Decode parameters from a clone of the raw params buffer.
    ///
    /// This method clones the internal buffer, allowing the message to be reused.
    /// For a consuming version, see [`into_params`](Self::into_params).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let params = rpc_message.decode_params().await?;
    /// for param in &params {
    ///     println!("{}: {:?}", param.name, param.value);
    /// }
    /// ```
    pub async fn decode_params(&self) -> crate::Result<Vec<crate::server::codec::DecodedRpcParam>> {
        crate::server::codec::decode_rpc_params(self.params.clone()).await
    }

    /// Consume the message and decode parameters from the raw params buffer.
    ///
    /// This method takes ownership of the message to avoid cloning the buffer.
    /// For a non-consuming version, see [`decode_params`](Self::decode_params).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let params = rpc_message.into_params().await?;
    /// for param in params {
    ///     println!("{}: {:?}", param.name, param.value);
    /// }
    /// ```
    pub async fn into_params(self) -> crate::Result<Vec<crate::server::codec::DecodedRpcParam>> {
        crate::server::codec::decode_rpc_params(self.params).await
    }

    /// Decode parameters into an [`RpcParamSet`] from a clone of the raw params buffer.
    ///
    /// Returns a wrapper struct with convenient access methods for parameters.
    /// This method clones the internal buffer, allowing the message to be reused.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let params = rpc_message.param_set().await?;
    /// if let Some(id) = params.by_name("@id") {
    ///     println!("id = {:?}", id.value);
    /// }
    /// ```
    pub async fn param_set(&self) -> crate::Result<crate::server::codec::RpcParamSet> {
        let params = self.decode_params().await?;
        Ok(crate::server::codec::RpcParamSet::new(params))
    }

    /// Consume the message and decode parameters into an [`RpcParamSet`].
    ///
    /// Returns a wrapper struct with convenient access methods for parameters.
    /// This method takes ownership of the message to avoid cloning the buffer.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let params = rpc_message.into_param_set().await?;
    /// for output in params.outputs() {
    ///     println!("Output param: {}", output.name);
    /// }
    /// ```
    pub async fn into_param_set(self) -> crate::Result<crate::server::codec::RpcParamSet> {
        let params = self.into_params().await?;
        Ok(crate::server::codec::RpcParamSet::new(params))
    }
}

/// Token stream elements produced by the server.
#[derive(Debug)]
pub enum BackendToken {
    LoginAck(TokenLoginAck),
    EnvChange(TokenEnvChange),
    Info(TokenInfo),
    Error(TokenError),
    FeatureExtAck(TokenFeatureExtAck),
    ColName(TokenColName),
    TabName(TokenTabName),
    ColInfo(TokenColInfo),
    ColMetaData(TokenColMetaData<'static>),
    AltMetaData(TokenAltMetaData<'static>),
    Row(TokenRow<'static>),
    NbcRow(TokenRow<'static>),
    AltRow(TokenAltRow<'static>),
    Order(TokenOrder),
    Done(TokenDone),
    DoneProc(TokenDone),
    DoneInProc(TokenDone),
    ReturnStatus(u32),
    ReturnValue(TokenReturnValue),
    SessionState(TokenSessionState),
    FedAuthInfo(TokenFedAuthInfo),
    Sspi(TokenSspi),
}

/// Backend messages emitted by the server.
#[derive(Debug)]
pub enum TdsBackendMessage {
    Prelogin(PreloginMessage),
    Token(BackendToken),
    TokenPartial(BackendToken),
    Tokens(Vec<BackendToken>),
    TokenBytes(BytesMut),
    TokenBytesPartial(BytesMut),
    Packet(Packet),
}
