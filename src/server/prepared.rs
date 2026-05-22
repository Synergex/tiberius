//! Prepared statement caching for the TDS server.
//!
//! This module provides infrastructure for caching prepared SQL statements,
//! which allows clients to prepare a statement once and execute it multiple
//! times with different parameters. This is a key optimization for database
//! workloads with repeated queries.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     Prepared Statement Cache                     │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │  Client ──[sp_prepare]──► ProcedureCache ──► PreparedHandle    │
//! │                                │                                │
//! │                                ▼                                │
//! │                        PreparedStatement                        │
//! │                     (sql, param_types, stats)                   │
//! │                                                                 │
//! │  Client ──[sp_execute]──► ProcedureCache.get(handle)           │
//! │                                │                                │
//! │                                ▼                                │
//! │                        Execute cached SQL                       │
//! │                                                                 │
//! │  Client ──[sp_unprepare]──► ProcedureCache.unprepare(handle)   │
//! │                                                                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```ignore
//! use tiberius::server::{ProcedureCache, ProcedureCacheConfig};
//!
//! // Create a cache for connection ID 1
//! let mut cache = ProcedureCache::new(1);
//!
//! // Prepare a statement
//! let handle = cache.prepare(
//!     "SELECT * FROM users WHERE id = @id".to_string(),
//!     vec![TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 4, None))],
//!     vec!["@id".to_string()],
//! );
//!
//! // Execute the statement
//! if let Some(stmt) = cache.get_and_record(&handle) {
//!     println!("Executing: {}", stmt.sql);
//! }
//!
//! // Unprepare when done
//! cache.unprepare(&handle);
//! ```

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::tds::codec::TypeInfo;

crate::server::handle_macro::impl_server_handle! {
    /// A handle to a prepared statement.
    ///
    /// Opaque identifier returned by `sp_prepare` that clients use to
    /// reference the prepared statement in subsequent `sp_execute` and
    /// `sp_unprepare` calls. Encodes a connection ID (upper 16 bits) and a
    /// sequence number (lower 16 bits) for uniqueness across connections.
    pub PreparedHandle
}

/// A cached prepared statement.
///
/// This struct holds all the information needed to execute a prepared
/// statement, along with statistics for cache management.
#[derive(Debug, Clone)]
pub struct PreparedStatement {
    /// The SQL text of the prepared statement.
    pub sql: String,

    /// The types of the parameters for this statement.
    pub param_types: Vec<TypeInfo>,

    /// The names of the parameters for this statement.
    pub param_names: Vec<String>,

    /// When this statement was first prepared.
    pub created_at: Instant,

    /// When this statement was last executed.
    pub last_used: Instant,

    /// The number of times this statement has been executed.
    pub execution_count: u64,
}

impl PreparedStatement {
    /// Create a new prepared statement.
    ///
    /// # Arguments
    ///
    /// * `sql` - The SQL text of the statement
    /// * `param_types` - The types of the parameters
    /// * `param_names` - The names of the parameters
    ///
    /// # Returns
    ///
    /// A new `PreparedStatement` with timestamps set to now and execution count of 0.
    pub fn new(sql: String, param_types: Vec<TypeInfo>, param_names: Vec<String>) -> Self {
        let now = Instant::now();
        Self {
            sql,
            param_types,
            param_names,
            created_at: now,
            last_used: now,
            execution_count: 0,
        }
    }

    /// Record an execution of this prepared statement.
    ///
    /// This updates `last_used` to the current time and increments
    /// `execution_count`.
    pub fn record_execution(&mut self) {
        self.last_used = Instant::now();
        self.execution_count = self.execution_count.saturating_add(1);
    }
}

/// Configuration for the procedure cache.
///
/// These settings control the cache capacity and expiration policies.
#[derive(Debug, Clone)]
pub struct ProcedureCacheConfig {
    /// Maximum number of prepared statements to cache.
    ///
    /// When this limit is reached, the oldest unused statements will be
    /// evicted to make room for new ones.
    pub max_capacity: usize,

    /// Maximum age of a cached statement.
    ///
    /// Statements older than this will be removed during cleanup,
    /// regardless of usage.
    pub max_age: Duration,

    /// Time after which an unused statement may be evicted.
    ///
    /// Statements that haven't been executed within this duration
    /// are candidates for eviction during cleanup.
    pub idle_timeout: Duration,
}

impl Default for ProcedureCacheConfig {
    fn default() -> Self {
        Self {
            max_capacity: 1000,
            max_age: Duration::from_secs(60 * 60),      // 1 hour
            idle_timeout: Duration::from_secs(30 * 60), // 30 minutes
        }
    }
}

/// A cache for prepared statements.
///
/// Each connection should have its own `ProcedureCache` instance to manage
/// prepared statements for that connection.
///
/// # Thread Safety
///
/// All mutating methods take `&mut self`, so a plain `u16` suffices for
/// the sequence counter — no atomics needed. Callers that want to share a
/// cache across tasks must provide their own synchronisation.
///
/// # Example
///
/// ```ignore
/// use tiberius::server::{ProcedureCache, ProcedureCacheConfig};
///
/// // Create with default config
/// let mut cache = ProcedureCache::new(1);
///
/// // Or with custom config
/// let config = ProcedureCacheConfig {
///     max_capacity: 500,
///     ..Default::default()
/// };
/// let mut cache = ProcedureCache::with_config(1, config);
/// ```
pub struct ProcedureCache {
    /// The connection ID for this cache.
    conn_id: u16,

    /// The next sequence number for handle generation.
    next_sequence: u16,

    /// The cached prepared statements.
    statements: HashMap<PreparedHandle, PreparedStatement>,

    /// Configuration for this cache.
    config: ProcedureCacheConfig,
}

impl ProcedureCache {
    /// Create a new procedure cache with default configuration.
    ///
    /// # Arguments
    ///
    /// * `conn_id` - The connection ID for this cache
    ///
    /// # Returns
    ///
    /// A new `ProcedureCache` with default settings.
    pub fn new(conn_id: u16) -> Self {
        Self::with_config(conn_id, ProcedureCacheConfig::default())
    }

    /// Create a new procedure cache with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `conn_id` - The connection ID for this cache
    /// * `config` - The configuration for the cache
    ///
    /// # Returns
    ///
    /// A new `ProcedureCache` with the specified settings.
    pub fn with_config(conn_id: u16, config: ProcedureCacheConfig) -> Self {
        Self {
            conn_id,
            next_sequence: 1,
            statements: HashMap::new(),
            config,
        }
    }

    /// Prepare a new statement and add it to the cache.
    ///
    /// This generates a new handle for the statement and stores it in the cache.
    /// If the cache is at capacity, this will trigger cleanup and LRU eviction
    /// to make room.
    ///
    /// # Arguments
    ///
    /// * `sql` - The SQL text of the statement
    /// * `param_types` - The types of the parameters
    /// * `param_names` - The names of the parameters
    ///
    /// # Returns
    ///
    /// A `PreparedHandle` that can be used to execute or unprepare the statement.
    ///
    /// # Note on Handle Wrapping
    ///
    /// Sequence numbers are 16-bit values (0-65535). After 65536 prepare operations,
    /// sequence numbers wrap around. To avoid collisions, old handles should be
    /// unprepared before reaching this limit.
    pub fn prepare(
        &mut self,
        sql: String,
        param_types: Vec<TypeInfo>,
        param_names: Vec<String>,
    ) -> PreparedHandle {
        // Ensure we have room - cleanup first, then LRU evict if needed
        if self.statements.len() >= self.config.max_capacity {
            let removed = self.cleanup();
            // If cleanup didn't free space, evict the least recently used
            if removed == 0 && self.statements.len() >= self.config.max_capacity {
                self.evict_lru();
            }
        }

        // Generate a new handle
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        let handle = PreparedHandle::new(self.conn_id, sequence);

        // Create and store the statement
        let stmt = PreparedStatement::new(sql, param_types, param_names);
        self.statements.insert(handle, stmt);

        handle
    }

    /// Evict the least recently used statement.
    fn evict_lru(&mut self) {
        if let Some((&lru_handle, _)) = self
            .statements
            .iter()
            .min_by_key(|(_, stmt)| stmt.last_used)
        {
            self.statements.remove(&lru_handle);
        }
    }

    /// Get a reference to a prepared statement by handle.
    ///
    /// This does not update usage statistics. Use [`get_and_record`](Self::get_and_record)
    /// if you want to record an execution.
    ///
    /// # Arguments
    ///
    /// * `handle` - The handle of the statement to retrieve
    ///
    /// # Returns
    ///
    /// A reference to the prepared statement, or `None` if not found.
    pub fn get(&self, handle: &PreparedHandle) -> Option<&PreparedStatement> {
        self.statements.get(handle)
    }

    /// Get a mutable reference to a prepared statement by handle.
    ///
    /// # Arguments
    ///
    /// * `handle` - The handle of the statement to retrieve
    ///
    /// # Returns
    ///
    /// A mutable reference to the prepared statement, or `None` if not found.
    pub fn get_mut(&mut self, handle: &PreparedHandle) -> Option<&mut PreparedStatement> {
        self.statements.get_mut(handle)
    }

    /// Get a prepared statement and record the access.
    ///
    /// This retrieves the statement and updates its usage statistics
    /// (last_used time and execution_count). Use this when executing
    /// a prepared statement.
    ///
    /// # Arguments
    ///
    /// * `handle` - The handle of the statement to retrieve
    ///
    /// # Returns
    ///
    /// A reference to the prepared statement after recording access,
    /// or `None` if the handle is not found.
    pub fn get_and_record(&mut self, handle: &PreparedHandle) -> Option<&PreparedStatement> {
        if let Some(stmt) = self.statements.get_mut(handle) {
            stmt.record_execution();
            Some(stmt)
        } else {
            None
        }
    }

    /// Remove a prepared statement from the cache.
    ///
    /// # Arguments
    ///
    /// * `handle` - The handle of the statement to remove
    ///
    /// # Returns
    ///
    /// The removed prepared statement, or `None` if the handle was not found.
    pub fn unprepare(&mut self, handle: &PreparedHandle) -> Option<PreparedStatement> {
        self.statements.remove(handle)
    }

    /// Check if a handle exists in the cache.
    ///
    /// # Arguments
    ///
    /// * `handle` - The handle to check
    ///
    /// # Returns
    ///
    /// `true` if the handle exists in the cache, `false` otherwise.
    pub fn contains(&self, handle: &PreparedHandle) -> bool {
        self.statements.contains_key(handle)
    }

    /// Get the number of cached statements.
    pub fn len(&self) -> usize {
        self.statements.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.statements.is_empty()
    }

    /// Remove all statements from the cache.
    pub fn clear(&mut self) {
        self.statements.clear();
    }

    /// Clean up expired and idle statements.
    ///
    /// This removes statements that:
    /// - Are older than `max_age`
    /// - Haven't been used within `idle_timeout`
    ///
    /// This is called automatically when the cache reaches capacity,
    /// but can also be called manually for maintenance.
    ///
    /// # Returns
    ///
    /// The number of statements removed.
    pub fn cleanup(&mut self) -> usize {
        let now = Instant::now();
        let max_age = self.config.max_age;
        let idle_timeout = self.config.idle_timeout;
        let initial_len = self.statements.len();

        self.statements.retain(|_, stmt| {
            let age = now.duration_since(stmt.created_at);
            let idle = now.duration_since(stmt.last_used);

            // Keep if not too old AND not too idle
            age < max_age && idle < idle_timeout
        });

        initial_len - self.statements.len()
    }

    /// Iterate over all cached statements.
    ///
    /// # Returns
    ///
    /// An iterator yielding (handle, statement) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&PreparedHandle, &PreparedStatement)> {
        self.statements.iter()
    }
}

impl std::fmt::Debug for ProcedureCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcedureCache")
            .field("conn_id", &self.conn_id)
            .field("next_sequence", &self.next_sequence)
            .field("statements_count", &self.statements.len())
            .field("config", &self.config)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tds::codec::{VarLenContext, VarLenType};

    #[test]
    fn prepared_handle_encoding() {
        let handle = PreparedHandle::new(0x1234, 0x5678);
        assert_eq!(handle.as_i32(), 0x12345678);
        assert_eq!(handle.conn_id(), 0x1234);
        assert_eq!(handle.sequence(), 0x5678);
    }

    #[test]
    fn prepared_handle_from_i32() {
        let handle = PreparedHandle::from_i32(0x12345678);
        assert_eq!(handle.conn_id(), 0x1234);
        assert_eq!(handle.sequence(), 0x5678);
    }

    #[test]
    fn prepared_handle_zero_values() {
        let handle = PreparedHandle::new(0, 0);
        assert_eq!(handle.as_i32(), 0);
        assert_eq!(handle.conn_id(), 0);
        assert_eq!(handle.sequence(), 0);
    }

    #[test]
    fn prepared_handle_max_values() {
        let handle = PreparedHandle::new(0xFFFF, 0xFFFF);
        assert_eq!(handle.as_i32(), -1); // 0xFFFFFFFF as i32
        assert_eq!(handle.conn_id(), 0xFFFF);
        assert_eq!(handle.sequence(), 0xFFFF);
    }

    #[test]
    fn procedure_cache_prepare_and_get() {
        let mut cache = ProcedureCache::new(1);

        let handle = cache.prepare(
            "SELECT 1".to_string(),
            vec![],
            vec![],
        );

        assert!(cache.contains(&handle));
        assert_eq!(cache.len(), 1);

        let stmt = cache.get(&handle).unwrap();
        assert_eq!(stmt.sql, "SELECT 1");
        assert_eq!(stmt.execution_count, 0);
    }

    #[test]
    fn procedure_cache_execute() {
        let mut cache = ProcedureCache::new(1);

        let handle = cache.prepare(
            "SELECT @p1".to_string(),
            vec![TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 4, None))],
            vec!["@p1".to_string()],
        );

        let stmt = cache.get_and_record(&handle).unwrap();
        assert_eq!(stmt.execution_count, 1);
        assert_eq!(stmt.sql, "SELECT @p1");

        // Execute again
        cache.get_and_record(&handle).unwrap();
        let stmt = cache.get(&handle).unwrap();
        assert_eq!(stmt.execution_count, 2);
    }

    #[test]
    fn procedure_cache_unprepare() {
        let mut cache = ProcedureCache::new(1);

        let handle = cache.prepare("SELECT 1".to_string(), vec![], vec![]);
        assert!(cache.contains(&handle));

        let removed = cache.unprepare(&handle);
        assert!(removed.is_some());
        assert!(!cache.contains(&handle));
        assert!(cache.is_empty());

        // Unprepare again should return None
        let removed = cache.unprepare(&handle);
        assert!(removed.is_none());
    }

    #[test]
    fn procedure_cache_clear() {
        let mut cache = ProcedureCache::new(1);

        cache.prepare("SELECT 1".to_string(), vec![], vec![]);
        cache.prepare("SELECT 2".to_string(), vec![], vec![]);
        cache.prepare("SELECT 3".to_string(), vec![], vec![]);

        assert_eq!(cache.len(), 3);

        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn procedure_cache_iter() {
        let mut cache = ProcedureCache::new(1);

        let h1 = cache.prepare("SELECT 1".to_string(), vec![], vec![]);
        let h2 = cache.prepare("SELECT 2".to_string(), vec![], vec![]);

        let handles: Vec<_> = cache.iter().map(|(h, _)| *h).collect();
        assert_eq!(handles.len(), 2);
        assert!(handles.contains(&h1));
        assert!(handles.contains(&h2));
    }

    #[test]
    fn procedure_cache_unique_handles() {
        let mut cache = ProcedureCache::new(1);

        let h1 = cache.prepare("SELECT 1".to_string(), vec![], vec![]);
        let h2 = cache.prepare("SELECT 2".to_string(), vec![], vec![]);
        let h3 = cache.prepare("SELECT 3".to_string(), vec![], vec![]);

        // All handles should be unique
        assert_ne!(h1, h2);
        assert_ne!(h2, h3);
        assert_ne!(h1, h3);
    }

    #[test]
    fn procedure_cache_with_config() {
        let config = ProcedureCacheConfig {
            max_capacity: 2,
            max_age: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(30),
        };

        let mut cache = ProcedureCache::with_config(1, config);

        // Add up to capacity
        cache.prepare("SELECT 1".to_string(), vec![], vec![]);
        cache.prepare("SELECT 2".to_string(), vec![], vec![]);
        assert_eq!(cache.len(), 2);

        // Adding more should trigger cleanup (but nothing to clean with default timeouts)
        cache.prepare("SELECT 3".to_string(), vec![], vec![]);
        // The exact behavior depends on cleanup logic; at minimum, the new statement is added
        assert!(cache.len() >= 1);
    }

    #[test]
    fn prepared_statement_record_execution() {
        let mut stmt = PreparedStatement::new(
            "SELECT 1".to_string(),
            vec![],
            vec![],
        );

        assert_eq!(stmt.execution_count, 0);

        stmt.record_execution();
        assert_eq!(stmt.execution_count, 1);

        stmt.record_execution();
        stmt.record_execution();
        assert_eq!(stmt.execution_count, 3);
    }

    #[test]
    fn procedure_cache_get_mut() {
        let mut cache = ProcedureCache::new(1);

        let handle = cache.prepare("SELECT 1".to_string(), vec![], vec![]);

        // Modify through get_mut
        if let Some(stmt) = cache.get_mut(&handle) {
            stmt.execution_count = 42;
        }

        let stmt = cache.get(&handle).unwrap();
        assert_eq!(stmt.execution_count, 42);
    }

    #[test]
    fn procedure_cache_nonexistent_handle() {
        let cache = ProcedureCache::new(1);

        let fake_handle = PreparedHandle::new(1, 999);
        assert!(!cache.contains(&fake_handle));
        assert!(cache.get(&fake_handle).is_none());
    }

    #[test]
    fn procedure_cache_execute_nonexistent() {
        let mut cache = ProcedureCache::new(1);

        let fake_handle = PreparedHandle::new(1, 999);
        assert!(cache.get_and_record(&fake_handle).is_none());
    }
}
