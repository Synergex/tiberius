//! Connection state for the TDS server.
//!
//! This module defines the connection state machine used by the TDS server.
//! The state determines which protocol messages are valid at any given time.

/// Connection state for a TDS client connection.
///
/// The state machine governs valid protocol transitions:
///
/// ```text
/// ┌─────────────────────────────────────────────────────────────────┐
/// │                          State Machine                          │
/// ├─────────────────────────────────────────────────────────────────┤
/// │                                                                 │
/// │  AwaitingPrelogin ──[Prelogin]──► AwaitingLogin                │
/// │                                         │                       │
/// │                                    [Login7]                     │
/// │                                         ▼                       │
/// │                          ┌── AuthenticationInProgress ◄─┐      │
/// │                          │              │               │      │
/// │                          │         [SSPI Token]         │      │
/// │                          │              └───────────────┘      │
/// │                          │                                     │
/// │                          └──────► ReadyForQuery ◄───────┐     │
/// │                                         │               │      │
/// │                               [SqlBatch/RPC]            │      │
/// │                                         ▼               │      │
/// │                                  QueryInProgress ───────┘      │
/// │                                         │                       │
/// │                                   [Attention]                   │
/// │                                         ▼                       │
/// │                                  AttentionPending               │
/// │                                                                 │
/// │                        Any State ──[Error/Close]──► Closed     │
/// │                                                                 │
/// └─────────────────────────────────────────────────────────────────┘
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TdsConnectionState {
    /// Waiting for the client's prelogin message.
    ///
    /// This is the initial state when a connection is established.
    AwaitingPrelogin,

    /// Prelogin complete, waiting for Login7 message.
    ///
    /// TLS upgrade (if negotiated) happens between Prelogin and Login7.
    AwaitingLogin,

    /// Multi-step authentication in progress (e.g., SSPI/Kerberos).
    ///
    /// In this state, the server expects SSPI continuation tokens.
    AuthenticationInProgress,

    /// Authentication complete, ready to process queries.
    ///
    /// The connection will remain in this state between requests.
    ReadyForQuery,

    /// A query or RPC request is being processed.
    ///
    /// Transitions back to `ReadyForQuery` when the request completes.
    QueryInProgress,

    /// Bulk load operation in progress.
    ///
    /// Waiting for bulk data packets or end-of-bulk-load signal.
    BulkLoadInProgress,

    /// An attention signal has been received and needs to be acknowledged.
    ///
    /// The current operation should be aborted and a DONE token with
    /// the Attention flag sent to the client.
    AttentionPending,

    /// Connection is closed and should be terminated.
    ///
    /// No further messages should be processed.
    Closed,
}

impl std::fmt::Display for TdsConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AwaitingPrelogin => write!(f, "AwaitingPrelogin"),
            Self::AwaitingLogin => write!(f, "AwaitingLogin"),
            Self::AuthenticationInProgress => write!(f, "AuthenticationInProgress"),
            Self::ReadyForQuery => write!(f, "ReadyForQuery"),
            Self::QueryInProgress => write!(f, "QueryInProgress"),
            Self::BulkLoadInProgress => write!(f, "BulkLoadInProgress"),
            Self::AttentionPending => write!(f, "AttentionPending"),
            Self::Closed => write!(f, "Closed"),
        }
    }
}
