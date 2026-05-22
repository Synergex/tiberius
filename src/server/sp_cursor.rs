//! Handlers for `sp_cursoropen`, `sp_cursorfetch`, and `sp_cursorclose`.
//!
//! These three RPCs let the client incrementally materialize a result set on
//! the server and page through it.
//!
//! # Wire format (TDS §2.2.6.7)
//!
//! ## `sp_cursoropen`
//! - `params[0]`: `@cursor OUTPUT int` — output parameter for the cursor
//!   handle
//! - `params[1]`: `@stmt nvarchar` — the SQL statement
//! - `params[2]`: `@scrollopt OUTPUT int` — requested scroll option (sent as
//!   input, echoed back as output after negotiation)
//! - `params[3]`: `@ccopt OUTPUT int` — requested concurrency option (same)
//! - `params[4]`: `@rowcount OUTPUT int` — output row count
//! - `params[5]`: `@paramdef nvarchar` — parameter definitions string
//! - `params[6..]`: actual parameter values
//!
//! ## `sp_cursorfetch`
//! - `params[0]`: `@cursor int` — cursor handle
//! - `params[1]`: `@fetchtype int` — fetch direction (`FetchType`)
//! - `params[2]`: `@rownum int` — anchor row (signed for `Relative`)
//! - `params[3]`: `@nrows int` — number of rows to fetch
//!
//! ## `sp_cursorclose`
//! - `params[0]`: `@cursor int` — cursor handle
//!
//! # Expected response patterns
//!
//! | RPC | Response |
//! |-----|----------|
//! | `cursoropen` | `RETURNVALUE`(@cursor,@scrollopt,@ccopt,@rowcount) + `RETURNSTATUS` + `DONEPROC` |
//! | `cursorfetch` | `COLMETADATA` + `ROW`\* + `DONEINPROC` + `RETURNSTATUS` + `DONEPROC` |
//! | `cursorclose` | `RETURNSTATUS` + `DONEPROC` |

use std::borrow::Cow;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::server::codec::{DecodedRpcParam, RpcParamSet};
use crate::server::handler::{BoxFuture, RpcHandler, TdsClient};
use crate::server::messages::RpcMessage;
use crate::server::sp_executesql::ExecuteSqlParam;
use crate::tds::codec::{ColumnData, RpcProcId, TypeInfo};
use crate::{Error, Result};

// =============================================================================
// Cursor handle + cache
// =============================================================================

crate::server::handle_macro::impl_server_handle! {
    /// An opaque server-issued cursor handle.
    ///
    /// Encodes a 16-bit connection ID (upper) and a 16-bit sequence (lower)
    /// the same way [`PreparedHandle`](crate::server::PreparedHandle) does.
    pub CursorHandle
}

/// A cached cursor record on the server side.
///
/// Handlers are free to subclass this via `custom` state; the cache itself
/// stores the SQL and negotiated options. The row set is intentionally not
/// part of this struct — different backends materialize rows differently, so
/// they should store them alongside via their own map keyed by
/// [`CursorHandle`].
#[derive(Debug, Clone)]
pub struct CursorEntry {
    /// The SQL statement the cursor was opened over.
    pub sql: String,
    /// Negotiated scroll options (as returned to the client).
    pub scrollopt: i32,
    /// Negotiated concurrency options.
    pub ccopt: i32,
    /// Server-reported row count, or `-1` if unknown.
    pub row_count: i32,
    /// Current position within the cursor (1-based; 0 = before first row).
    pub position: i32,
    /// When the cursor was opened.
    pub created_at: Instant,
    /// When the cursor was last touched (fetched from).
    pub last_used: Instant,
}

impl CursorEntry {
    /// Build a new entry representing a freshly opened cursor.
    pub fn new(sql: String, scrollopt: i32, ccopt: i32, row_count: i32) -> Self {
        let now = Instant::now();
        Self {
            sql,
            scrollopt,
            ccopt,
            row_count,
            position: 0,
            created_at: now,
            last_used: now,
        }
    }

    /// Update `last_used` and return the new position after applying a
    /// relative move. Handlers that need precise position tracking should
    /// manage this themselves.
    pub fn record_fetch(&mut self) {
        self.last_used = Instant::now();
    }
}

/// Tunables for [`CursorCache`].
#[derive(Debug, Clone)]
pub struct CursorCacheConfig {
    /// Maximum number of simultaneously open cursors.
    pub max_capacity: usize,
    /// Cursors older than this are pruned on insert.
    pub max_age: Duration,
    /// Cursors untouched for this long are pruned on insert.
    pub idle_timeout: Duration,
}

impl Default for CursorCacheConfig {
    fn default() -> Self {
        Self {
            max_capacity: 1000,
            max_age: Duration::from_secs(60 * 60),
            idle_timeout: Duration::from_secs(30 * 60),
        }
    }
}

/// Per-connection cursor cache.
///
/// Handles are allocated sequentially, paired with the connection id the
/// cache was constructed with. `open()` takes `&mut self`, so the sequence
/// counter is a plain `u16` — no atomics needed.
pub struct CursorCache {
    conn_id: u16,
    next_sequence: u16,
    cursors: HashMap<CursorHandle, CursorEntry>,
    config: CursorCacheConfig,
}

impl CursorCache {
    /// Create an empty cache for the given connection id.
    pub fn new(conn_id: u16) -> Self {
        Self::with_config(conn_id, CursorCacheConfig::default())
    }

    /// Create an empty cache with custom configuration.
    pub fn with_config(conn_id: u16, config: CursorCacheConfig) -> Self {
        Self {
            conn_id,
            next_sequence: 1,
            cursors: HashMap::new(),
            config,
        }
    }

    /// Register a new cursor and return its handle.
    pub fn open(&mut self, entry: CursorEntry) -> CursorHandle {
        if self.cursors.len() >= self.config.max_capacity {
            let removed = self.cleanup();
            if removed == 0 && self.cursors.len() >= self.config.max_capacity {
                self.evict_lru();
            }
        }
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        let handle = CursorHandle::new(self.conn_id, sequence);
        self.cursors.insert(handle, entry);
        handle
    }

    /// Borrow the entry for the given handle.
    pub fn get(&self, handle: &CursorHandle) -> Option<&CursorEntry> {
        self.cursors.get(handle)
    }

    /// Mutably borrow the entry for the given handle.
    pub fn get_mut(&mut self, handle: &CursorHandle) -> Option<&mut CursorEntry> {
        self.cursors.get_mut(handle)
    }

    /// Remove and return the entry for the given handle.
    pub fn close(&mut self, handle: &CursorHandle) -> Option<CursorEntry> {
        self.cursors.remove(handle)
    }

    /// Returns `true` if the handle is currently open in this cache.
    pub fn contains(&self, handle: &CursorHandle) -> bool {
        self.cursors.contains_key(handle)
    }

    /// Number of open cursors.
    pub fn len(&self) -> usize {
        self.cursors.len()
    }

    /// Are there no open cursors?
    pub fn is_empty(&self) -> bool {
        self.cursors.is_empty()
    }

    /// Close every cursor in the cache.
    pub fn clear(&mut self) {
        self.cursors.clear();
    }

    /// Prune cursors that are over `max_age` or haven't been touched in at
    /// least `idle_timeout`. Returns the number of cursors pruned.
    pub fn cleanup(&mut self) -> usize {
        let now = Instant::now();
        let max_age = self.config.max_age;
        let idle_timeout = self.config.idle_timeout;
        let before = self.cursors.len();
        self.cursors.retain(|_, e| {
            let age = now.duration_since(e.created_at);
            let idle = now.duration_since(e.last_used);
            age < max_age && idle < idle_timeout
        });
        before - self.cursors.len()
    }

    fn evict_lru(&mut self) {
        if let Some((&h, _)) = self.cursors.iter().min_by_key(|(_, e)| e.last_used) {
            self.cursors.remove(&h);
        }
    }
}

impl std::fmt::Debug for CursorCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CursorCache")
            .field("conn_id", &self.conn_id)
            .field("next_sequence", &self.next_sequence)
            .field("cursors", &self.cursors.len())
            .field("config", &self.config)
            .finish()
    }
}

// =============================================================================
// Parsed request types
// =============================================================================

/// Parsed `sp_cursoropen` request.
#[derive(Debug)]
pub struct ParsedCursorOpen<'a> {
    /// The SQL statement to open the cursor over.
    pub sql: Cow<'a, str>,
    /// Parameter definitions string (empty when absent).
    pub param_defs: Option<Cow<'a, str>>,
    /// Requested scroll option as sent by the client.
    pub scrollopt: i32,
    /// Requested concurrency option as sent by the client.
    pub ccopt: i32,
    /// Type info for the `@cursor` output parameter — echo back on response.
    pub cursor_type_info: TypeInfo,
    /// Type info for `@scrollopt` output parameter.
    pub scrollopt_type_info: TypeInfo,
    /// Type info for `@ccopt` output parameter.
    pub ccopt_type_info: TypeInfo,
    /// Type info for `@rowcount` output parameter.
    pub rowcount_type_info: TypeInfo,
    /// Statement parameter values (ordinals start at 0).
    pub params: Vec<ExecuteSqlParam<'a>>,
}

/// Parsed `sp_cursorfetch` request.
#[derive(Debug)]
pub struct ParsedCursorFetch {
    /// Cursor handle supplied by the client.
    pub handle: CursorHandle,
    /// Fetch direction (raw i32; compare against `FetchType` on the client).
    pub fetch_type: i32,
    /// Anchor row number.
    pub row_num: i32,
    /// Number of rows the client asked to fetch.
    pub n_rows: i32,
}

/// Parsed `sp_cursorclose` request.
#[derive(Debug)]
pub struct ParsedCursorClose {
    /// Cursor handle supplied by the client.
    pub handle: CursorHandle,
}

// =============================================================================
// Parsers
// =============================================================================

fn extract_i32(param: &DecodedRpcParam, field: &str) -> Result<i32> {
    match &param.value {
        ColumnData::I32(Some(v)) => Ok(*v),
        ColumnData::I32(None) => Err(Error::Protocol(
            format!("{}: parameter is NULL", field).into(),
        )),
        other => Err(Error::Protocol(
            format!(
                "{}: expected int, got {:?}",
                field,
                std::mem::discriminant(other)
            )
            .into(),
        )),
    }
}

fn extract_string(param: DecodedRpcParam, field: &str) -> Result<Cow<'static, str>> {
    match param.value {
        ColumnData::String(Some(s)) => Ok(Cow::Owned(s.into_owned())),
        ColumnData::String(None) => Err(Error::Protocol(
            format!("{}: parameter is NULL", field).into(),
        )),
        other => Err(Error::Protocol(
            format!(
                "{}: expected string, got {:?}",
                field,
                std::mem::discriminant(&other)
            )
            .into(),
        )),
    }
}

fn extract_optional_string(param: DecodedRpcParam) -> Option<Cow<'static, str>> {
    match param.value {
        ColumnData::String(Some(s)) if !s.is_empty() => Some(Cow::Owned(s.into_owned())),
        _ => None,
    }
}

/// Parse an `sp_cursoropen` RPC parameter set.
pub fn parse_cursor_open(params: RpcParamSet) -> Result<ParsedCursorOpen<'static>> {
    let mut params_vec = params.into_inner();

    if params_vec.len() < 5 {
        return Err(Error::Protocol(
            format!(
                "sp_cursoropen: expected at least 5 parameters, got {}",
                params_vec.len()
            )
            .into(),
        ));
    }

    // [0] @cursor OUT int
    let cursor_param = params_vec.remove(0);
    let cursor_type_info = cursor_param.ty.clone();

    // [1] @stmt nvarchar
    let stmt_param = params_vec.remove(0);
    let sql = extract_string(stmt_param, "sp_cursoropen @stmt")?;

    // [2] @scrollopt OUT int (also input)
    let scrollopt_param = params_vec.remove(0);
    let scrollopt_type_info = scrollopt_param.ty.clone();
    let scrollopt = match &scrollopt_param.value {
        ColumnData::I32(Some(v)) => *v,
        _ => 0,
    };

    // [3] @ccopt OUT int (also input)
    let ccopt_param = params_vec.remove(0);
    let ccopt_type_info = ccopt_param.ty.clone();
    let ccopt = match &ccopt_param.value {
        ColumnData::I32(Some(v)) => *v,
        _ => 0,
    };

    // [4] @rowcount OUT int
    let rowcount_param = params_vec.remove(0);
    let rowcount_type_info = rowcount_param.ty.clone();

    // [5] @paramdef nvarchar (optional)
    let param_defs = if !params_vec.is_empty() {
        let p = params_vec.remove(0);
        extract_optional_string(p)
    } else {
        None
    };

    let params: Vec<ExecuteSqlParam<'static>> = params_vec
        .into_iter()
        .enumerate()
        .map(|(i, p)| ExecuteSqlParam::new(p, i))
        .collect();

    Ok(ParsedCursorOpen {
        sql,
        param_defs,
        scrollopt,
        ccopt,
        cursor_type_info,
        scrollopt_type_info,
        ccopt_type_info,
        rowcount_type_info,
        params,
    })
}

/// Parse an `sp_cursorfetch` RPC parameter set.
pub fn parse_cursor_fetch(params: RpcParamSet) -> Result<ParsedCursorFetch> {
    let params_vec = params.into_inner();

    if params_vec.len() < 4 {
        return Err(Error::Protocol(
            format!(
                "sp_cursorfetch: expected 4 parameters, got {}",
                params_vec.len()
            )
            .into(),
        ));
    }

    let handle = CursorHandle::from_i32(extract_i32(&params_vec[0], "sp_cursorfetch @cursor")?);
    let fetch_type = extract_i32(&params_vec[1], "sp_cursorfetch @fetchtype")?;
    let row_num = extract_i32(&params_vec[2], "sp_cursorfetch @rownum")?;
    let n_rows = extract_i32(&params_vec[3], "sp_cursorfetch @nrows")?;

    Ok(ParsedCursorFetch {
        handle,
        fetch_type,
        row_num,
        n_rows,
    })
}

/// Parse an `sp_cursorclose` RPC parameter set.
pub fn parse_cursor_close(params: RpcParamSet) -> Result<ParsedCursorClose> {
    let params_vec = params.into_inner();
    if params_vec.is_empty() {
        return Err(Error::Protocol(
            "sp_cursorclose: missing @cursor parameter".into(),
        ));
    }
    let handle = CursorHandle::from_i32(extract_i32(&params_vec[0], "sp_cursorclose @cursor")?);
    Ok(ParsedCursorClose { handle })
}

// =============================================================================
// Handler traits
// =============================================================================

/// Handler for `sp_cursoropen`.
///
/// Must send the negotiated `@cursor`, `@scrollopt`, `@ccopt`, `@rowcount`
/// output parameters and a closing `DONEPROC` before returning.
pub trait SpCursorOpenHandler: Send + Sync {
    /// Open a cursor and return the new handle.
    fn cursor_open<'a, C>(
        &'a self,
        client: &'a mut C,
        request: ParsedCursorOpen<'a>,
    ) -> BoxFuture<'a, Result<CursorHandle>>
    where
        C: TdsClient + 'a;
}

/// Handler for `sp_cursorfetch`.
///
/// Must stream any fetched rows (via `ResultSetWriter`) and a closing
/// `DONEPROC`.
pub trait SpCursorFetchHandler: Send + Sync {
    /// Fetch rows for the given cursor.
    fn cursor_fetch<'a, C>(
        &'a self,
        client: &'a mut C,
        request: ParsedCursorFetch,
    ) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClient + 'a;
}

/// Handler for `sp_cursorclose`.
///
/// Must send a `RETURNSTATUS` + `DONEPROC` before returning.
pub trait SpCursorCloseHandler: Send + Sync {
    /// Release resources for the given cursor handle.
    fn cursor_close<'a, C>(
        &'a self,
        client: &'a mut C,
        request: ParsedCursorClose,
    ) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClient + 'a;
}

// =============================================================================
// RPC handler adapters
// =============================================================================

macro_rules! impl_adapter {
    ($Adapter:ident, $Trait:ident, $parse:ident, $method:ident, $proc:path) => {
        /// Adapter wrapping a specialized handler so it can be used wherever
        /// an [`RpcHandler`] is expected.
        pub struct $Adapter<H> {
            inner: H,
        }

        impl<H> $Adapter<H> {
            /// Wrap the given handler.
            pub fn new(inner: H) -> Self {
                Self { inner }
            }

            /// Borrow the inner handler.
            pub fn inner(&self) -> &H {
                &self.inner
            }

            /// Mutably borrow the inner handler.
            pub fn inner_mut(&mut self) -> &mut H {
                &mut self.inner
            }

            /// Consume the adapter and return the inner handler.
            pub fn into_inner(self) -> H {
                self.inner
            }
        }

        impl<H> RpcHandler for $Adapter<H>
        where
            H: $Trait,
        {
            fn on_rpc<'a, C>(
                &'a self,
                client: &'a mut C,
                message: RpcMessage,
            ) -> BoxFuture<'a, Result<()>>
            where
                C: TdsClient + 'a,
            {
                Box::pin(async move {
                    match message.proc_id {
                        Some($proc) => {
                            let param_set = message.into_param_set().await?;
                            let request = $parse(param_set)?;
                            let _ = self.inner.$method(client, request).await?;
                            Ok(())
                        }
                        Some(other) => Err(Error::Protocol(
                            format!(
                                "{}: unsupported RPC proc ID {:?}",
                                stringify!($Adapter),
                                other
                            )
                            .into(),
                        )),
                        None => {
                            let name = message.proc_name.as_deref().unwrap_or("<unknown>");
                            Err(Error::Protocol(
                                format!(
                                    "{}: unsupported RPC procedure '{}'",
                                    stringify!($Adapter),
                                    name
                                )
                                .into(),
                            ))
                        }
                    }
                })
            }
        }
    };
}

impl_adapter!(
    SpCursorOpenRpcHandler,
    SpCursorOpenHandler,
    parse_cursor_open,
    cursor_open,
    RpcProcId::CursorOpen
);
impl_adapter!(
    SpCursorFetchRpcHandler,
    SpCursorFetchHandler,
    parse_cursor_fetch,
    cursor_fetch,
    RpcProcId::CursorFetch
);
impl_adapter!(
    SpCursorCloseRpcHandler,
    SpCursorCloseHandler,
    parse_cursor_close,
    cursor_close,
    RpcProcId::CursorClose
);

// NOTE: the public [`SystemProcRouter`](super::router::SystemProcRouter) is
// the canonical way to dispatch a whole RPC surface; we no longer ship a
// bespoke `CursorRpcHandler` bundler because it would duplicate the router's
// own dispatch logic. Users who want just the cursor procs can either
// register handlers on the router and leave the non-cursor slots defaulted,
// or compose the three single-proc adapters themselves.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tds::codec::{FixedLenType, VarLenContext, VarLenType};
    use enumflags2::BitFlags;

    fn make_i32(name: &str, value: Option<i32>, output: bool) -> DecodedRpcParam {
        use crate::tds::codec::RpcStatus;
        DecodedRpcParam {
            name: name.to_string(),
            flags: if output { RpcStatus::ByRefValue.into() } else { BitFlags::empty() },
            ty: TypeInfo::FixedLen(FixedLenType::Int4),
            value: ColumnData::I32(value),
        }
    }

    fn make_string(name: &str, value: &str) -> DecodedRpcParam {
        DecodedRpcParam {
            name: name.to_string(),
            flags: BitFlags::empty(),
            ty: TypeInfo::VarLenSized(VarLenContext::new(VarLenType::NVarchar, 4000, None)),
            value: ColumnData::String(Some(Cow::Owned(value.to_string()))),
        }
    }

    #[test]
    fn cursor_handle_round_trip() {
        let h = CursorHandle::new(0x1234, 0xABCD);
        assert_eq!(h.as_i32(), 0x1234_ABCDu32 as i32);
        assert_eq!(h.conn_id(), 0x1234);
        assert_eq!(h.sequence(), 0xABCD);
        assert_eq!(CursorHandle::from_i32(h.as_i32()), h);
    }

    #[test]
    fn parse_cursor_open_happy_path() {
        let params = vec![
            make_i32("@cursor", None, true),
            make_string("@stmt", "SELECT * FROM t"),
            make_i32("@scrollopt", Some(0x10), true),
            make_i32("@ccopt", Some(0x01), true),
            make_i32("@rowcount", Some(0), true),
            make_string("@paramdef", ""),
        ];
        let parsed = parse_cursor_open(RpcParamSet::new(params)).unwrap();
        assert_eq!(parsed.sql, "SELECT * FROM t");
        assert_eq!(parsed.scrollopt, 0x10);
        assert_eq!(parsed.ccopt, 0x01);
        assert_eq!(parsed.param_defs, None);
        assert_eq!(parsed.params.len(), 0);
    }

    #[test]
    fn parse_cursor_open_rejects_too_few_params() {
        let params = vec![
            make_i32("@cursor", None, true),
            make_string("@stmt", "SELECT 1"),
        ];
        let err = parse_cursor_open(RpcParamSet::new(params)).unwrap_err();
        assert!(err.to_string().contains("at least 5"));
    }

    #[test]
    fn parse_cursor_fetch_happy_path() {
        let params = vec![
            make_i32("@cursor", Some(7), false),
            make_i32("@fetchtype", Some(2), false),
            make_i32("@rownum", Some(1), false),
            make_i32("@nrows", Some(10), false),
        ];
        let parsed = parse_cursor_fetch(RpcParamSet::new(params)).unwrap();
        assert_eq!(parsed.handle.as_i32(), 7);
        assert_eq!(parsed.fetch_type, 2);
        assert_eq!(parsed.row_num, 1);
        assert_eq!(parsed.n_rows, 10);
    }

    #[test]
    fn parse_cursor_close_happy_path() {
        let params = vec![make_i32("@cursor", Some(42), false)];
        let parsed = parse_cursor_close(RpcParamSet::new(params)).unwrap();
        assert_eq!(parsed.handle.as_i32(), 42);
    }

    #[test]
    fn cursor_cache_open_and_close() {
        let mut cache = CursorCache::new(1);
        let entry = CursorEntry::new("SELECT 1".into(), 4, 1, 0);
        let h = cache.open(entry);
        assert!(cache.contains(&h));
        assert_eq!(cache.len(), 1);
        assert!(cache.close(&h).is_some());
        assert!(cache.is_empty());
    }

    #[test]
    fn cursor_cache_distinct_handles() {
        let mut cache = CursorCache::new(1);
        let h1 = cache.open(CursorEntry::new("q1".into(), 4, 1, 0));
        let h2 = cache.open(CursorEntry::new("q2".into(), 4, 1, 0));
        assert_ne!(h1, h2);
    }
}
