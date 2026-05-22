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
    last_meta: Option<Arc<TokenColMetaData<'static>>>,
    alt_meta: HashMap<u16, Arc<TokenAltMetaData<'static>>>,
    spn: Option<String>,
}

impl Context {
    pub fn new() -> Context {
        Context {
            version: FeatureLevel::SqlServerN,
            packet_size: 4096,
            packet_id: 0,
            transaction_desc: [0; 8],
            last_meta: None,
            alt_meta: HashMap::new(),
            spn: None,
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

    pub fn version(&self) -> FeatureLevel {
        self.version
    }

    pub fn set_version(&mut self, version: FeatureLevel) {
        self.version = version;
    }

    pub fn set_spn(&mut self, host: impl AsRef<str>, port: u16) {
        self.spn = Some(format!("MSSQLSvc/{}:{}", host.as_ref(), port));
    }

    #[cfg(any(windows, all(unix, feature = "integrated-auth-gssapi")))]
    pub fn spn(&self) -> &str {
        self.spn.as_deref().unwrap_or("")
    }
}
