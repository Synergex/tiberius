use super::codec::*;
use std::collections::HashMap;
use std::sync::Arc;

/// Minimum valid TDS packet size (per MS-TDS specification).
pub const MIN_PACKET_SIZE: u32 = 512;

/// Maximum valid TDS packet size (per MS-TDS specification for modern clients).
pub const MAX_PACKET_SIZE: u32 = 32767;

/// Default packet size.
pub const DEFAULT_PACKET_SIZE: u32 = 4096;

/// Context, that might be required to make sure we understand and are understood by the server
#[derive(Debug)]
pub(crate) struct Context {
    version: FeatureLevel,
    packet_size: u32,
    packet_id: u8,
    transaction_desc: [u8; 8],
    transaction_end: Option<TransactionOutcome>,
    last_meta: Option<Arc<TokenColMetaData<'static>>>,
    alt_meta: HashMap<u16, Arc<TokenAltMetaData<'static>>>,
    spn: Option<String>,
    spid: Option<u16>,
    server_version: Option<String>,
    database: Option<String>,
}

impl Context {
    pub fn new() -> Context {
        Context {
            version: FeatureLevel::SqlServerN,
            packet_size: 4096,
            packet_id: 0,
            transaction_desc: [0; 8],
            transaction_end: None,
            last_meta: None,
            alt_meta: HashMap::new(),
            spn: None,
            spid: None,
            server_version: None,
            database: None,
        }
    }

    pub fn next_packet_id(&mut self) -> u8 {
        let id = self.packet_id;
        self.packet_id = self.packet_id.wrapping_add(1);
        id
    }

    pub fn reset_packet_id(&mut self) {
        self.packet_id = 1;
    }

    pub fn set_last_meta(&mut self, meta: Arc<TokenColMetaData<'static>>) {
        self.last_meta.replace(meta);
    }

    pub fn last_meta(&self) -> Option<Arc<TokenColMetaData<'static>>> {
        self.last_meta.clone()
    }

    pub fn set_alt_meta(&mut self, meta: Arc<TokenAltMetaData<'static>>) {
        self.alt_meta.insert(meta.id, meta);
    }

    pub fn alt_meta(&self, id: u16) -> Option<Arc<TokenAltMetaData<'static>>> {
        self.alt_meta.get(&id).cloned()
    }

    pub fn packet_size(&self) -> u32 {
        self.packet_size
    }

    /// Set the packet size, clamping to valid TDS range.
    /// Returns the actual size that was set.
    pub fn set_packet_size(&mut self, new_size: u32) -> u32 {
        self.packet_size = if new_size < MIN_PACKET_SIZE {
            MIN_PACKET_SIZE
        } else if new_size > MAX_PACKET_SIZE {
            MAX_PACKET_SIZE
        } else {
            new_size
        };
        self.packet_size
    }

    /// Validate a packet size is within TDS protocol bounds.
    pub fn validate_packet_size(size: u32) -> bool {
        size >= MIN_PACKET_SIZE && size <= MAX_PACKET_SIZE
    }

    pub fn transaction_descriptor(&self) -> [u8; 8] {
        self.transaction_desc
    }

    pub fn set_transaction_descriptor(&mut self, desc: [u8; 8]) {
        self.transaction_desc = desc;
    }

    /// How the server last reported a transaction ending, until it reports
    /// one beginning or a commit or rollback call reads its own response. A
    /// call dropped before then leaves the end for the next one to report.
    pub fn transaction_end(&self) -> Option<TransactionOutcome> {
        self.transaction_end
    }

    pub fn set_transaction_end(&mut self, end: Option<TransactionOutcome>) {
        self.transaction_end = end;
    }

    /// Records what an ENVCHANGE token changed in the session. Every reader
    /// of response tokens applies them here, so the transaction descriptor
    /// later requests carry is the server's current one.
    pub fn apply_env_change(&mut self, change: &TokenEnvChange) {
        match change {
            TokenEnvChange::PacketSize(new_size, _) => {
                self.set_packet_size(*new_size);
            }
            TokenEnvChange::BeginTransaction(desc) | TokenEnvChange::EnlistDtcTransaction(desc) => {
                self.transaction_desc = *desc;
                self.transaction_end = None;
            }
            TokenEnvChange::CommitTransaction { new, .. } => {
                self.update_transaction_descriptor(new);
                self.transaction_end = Some(TransactionOutcome::Commit);
            }
            TokenEnvChange::RollbackTransaction { new, .. } => {
                self.update_transaction_descriptor(new);
                self.transaction_end = Some(TransactionOutcome::Rollback);
            }
            TokenEnvChange::DefectTransaction { new, .. }
            | TokenEnvChange::PromoteTransaction { dtc: new, .. }
            | TokenEnvChange::TransactionEnded { new, .. } => {
                self.update_transaction_descriptor(new);
            }
            TokenEnvChange::ResetConnection => {
                self.transaction_desc = [0; 8];
                self.transaction_end = None;
            }
            TokenEnvChange::Database(new, _) => {
                self.set_database(new.clone());
            }
            _ => (),
        }
    }

    fn update_transaction_descriptor(&mut self, bytes: &[u8]) {
        self.transaction_desc = <[u8; 8]>::try_from(bytes).unwrap_or([0; 8]);
    }

    pub fn version(&self) -> FeatureLevel {
        self.version
    }

    pub fn set_version(&mut self, version: FeatureLevel) {
        self.version = version;
    }

    pub fn spid(&self) -> Option<u16> {
        self.spid
    }

    pub fn set_spid(&mut self, spid: u16) {
        self.spid = Some(spid);
    }

    pub fn server_version(&self) -> Option<&str> {
        self.server_version.as_deref()
    }

    pub fn set_server_version(&mut self, version: String) {
        self.server_version = Some(version);
    }

    pub fn database(&self) -> Option<&str> {
        self.database.as_deref()
    }

    pub fn set_database(&mut self, database: String) {
        self.database = Some(database);
    }

    pub fn set_spn(&mut self, host: impl AsRef<str>, port: u16) {
        self.spn = Some(format!("MSSQLSvc/{}:{}", host.as_ref(), port));
    }

    #[cfg(any(windows, all(unix, feature = "integrated-auth-gssapi")))]
    pub fn spn(&self) -> &str {
        self.spn.as_deref().unwrap_or("")
    }
}
