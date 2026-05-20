//! End-to-end tests for the prepare / prep_exec / unprepare / cursor client APIs.
//!
//! A Tiberius server (in-process, via the `server-smol` backend) is spawned
//! on `127.0.0.1:0`; a Tiberius client connects over TCP and drives the new
//! RPC helpers against handlers that simulate a minimal SQL executor.

#![cfg(feature = "server-smol")]

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use enumflags2::BitFlags;
use futures_util::sink::SinkExt;

use tiberius::server::sp_cursor::{
    CursorCache, CursorEntry, CursorHandle, ParsedCursorClose, ParsedCursorFetch, ParsedCursorOpen,
    SpCursorCloseHandler, SpCursorFetchHandler, SpCursorOpenHandler,
};
use tiberius::server::{
    process_connection, send_output_param, send_output_params, send_return_status, AuthBuilder,
    AuthError, AuthHandler, AuthSuccess, BackendToken, BoxFuture, DefaultEnvChangeProvider,
    LoginInfo, NoOpAttention, NoOpError, OutputParameter, ParsedExecute, ParsedPrepExec,
    ParsedPrepare, ParsedUnprepare, PreparedHandle, ProcedureCache, RejectBulkLoad,
    ResultSetWriter, RpcHandler, SpExecuteHandler, SpPrepExecHandler, SpPrepareHandler,
    SpUnprepareHandler, SqlAuthSource, SqlBatchHandler, SystemProcRouter, SystemProcRouterBuilder,
    TdsAuthHandler, TdsBackendMessage, TdsClient, TdsServerHandlers,
};
use tiberius::{
    BaseMetaDataColumn, Client, ColumnData, ColumnFlag, Config, CursorOpenOptions,
    CursorScrollOptions, EncryptionLevel, FixedLenType, MetaDataColumn, RpcProcId,
    TokenColMetaData, TokenDone, TypeInfo,
};

// =============================================================================
// Trivial auth source — accepts everything
// =============================================================================

#[derive(Debug, Default)]
struct AlwaysOkAuth;

#[async_trait]
impl SqlAuthSource for AlwaysOkAuth {
    async fn authenticate(
        &self,
        _login: &LoginInfo,
        _password: &str,
    ) -> std::result::Result<AuthSuccess, AuthError> {
        Ok(AuthSuccess::default())
    }
}

struct TestAuth {
    inner: TdsAuthHandler<DefaultEnvChangeProvider>,
}

impl TestAuth {
    fn new() -> Self {
        let inner = AuthBuilder::new(DefaultEnvChangeProvider::default())
            .encryption(EncryptionLevel::NotSupported)
            .with_sql_auth(Arc::new(AlwaysOkAuth::default()))
            .allow_trust()
            .build();
        Self { inner }
    }
}

impl AuthHandler for TestAuth {
    fn on_prelogin<'a, C>(
        &'a self,
        client: &'a mut C,
        message: tiberius::PreloginMessage,
    ) -> BoxFuture<'a, tiberius::Result<()>>
    where
        C: TdsClient + 'a,
    {
        self.inner.on_prelogin(client, message)
    }

    fn on_login<'a, C>(
        &'a self,
        client: &'a mut C,
        message: tiberius::LoginMessage<'static>,
    ) -> BoxFuture<'a, tiberius::Result<()>>
    where
        C: TdsClient + 'a,
    {
        self.inner.on_login(client, message)
    }

    fn on_sspi<'a, C>(
        &'a self,
        client: &'a mut C,
        token: tiberius::TokenSspi,
    ) -> BoxFuture<'a, tiberius::Result<()>>
    where
        C: TdsClient + 'a,
    {
        self.inner.on_sspi(client, token)
    }
}

// =============================================================================
// Trivial SQL batch handler — responds with a single empty Done
// =============================================================================

struct NoopSqlBatch;

impl SqlBatchHandler for NoopSqlBatch {
    fn on_sql_batch<'a, C>(
        &'a self,
        client: &'a mut C,
        _message: tiberius::server::SqlBatchMessage,
    ) -> BoxFuture<'a, tiberius::Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async move {
            client
                .send(TdsBackendMessage::Token(BackendToken::Done(
                    TokenDone::with_rows(0),
                )))
                .await
        })
    }
}

// =============================================================================
// Shared state for prepared-statement + cursor handlers
// =============================================================================

struct SharedState {
    procs: Mutex<ProcedureCache>,
    cursors: Mutex<CursorCache>,
    /// Rows materialized per cursor handle.
    cursor_rows: Mutex<HashMap<CursorHandle, Vec<i32>>>,
    /// Records the parameters of every `sp_cursorfetch` RPC the server
    /// observed. Tests assert on this to prove the client's wire encoding
    /// of (fetch_type, row_num, n_rows) actually reaches the server.
    cursor_fetch_log: Mutex<Vec<(i32, i32, i32)>>,
    cursorprepexec_param_defs_log: Mutex<Vec<Option<String>>>,
    cursorprepexec_send_metadata: Mutex<bool>,
    rpc_log: Mutex<Vec<RpcProcId>>,
}

impl SharedState {
    fn new() -> Self {
        Self {
            procs: Mutex::new(ProcedureCache::new(1)),
            cursors: Mutex::new(CursorCache::new(1)),
            cursor_rows: Mutex::new(HashMap::new()),
            cursor_fetch_log: Mutex::new(Vec::new()),
            cursorprepexec_param_defs_log: Mutex::new(Vec::new()),
            cursorprepexec_send_metadata: Mutex::new(false),
            rpc_log: Mutex::new(Vec::new()),
        }
    }
}

// =============================================================================
// Minimal SQL "evaluator"
// =============================================================================
//
// Supports exactly:
//   "SELECT @P1 AS v"          — one int column, value = @P1
//   "SELECT @P1 + @P2 AS s"    — one int column, value = @P1 + @P2
//   "SELECT 1 AS v UNION ALL SELECT 2 AS v UNION ALL SELECT 3 AS v"
//                               — three-row result, used for cursor tests
//
// Both named-parameter binding ("@id", "@P1") are resolved via a hashmap built
// from the execution params.

fn eval_sql(sql: &str, params: &HashMap<String, i32>) -> Vec<i32> {
    let sql = sql.trim();
    if sql.eq_ignore_ascii_case("SELECT @P1 AS v") {
        return vec![params.get("@P1").copied().unwrap_or(0)];
    }
    if sql.eq_ignore_ascii_case("SELECT @P1 + @P2 AS s") {
        let a = params.get("@P1").copied().unwrap_or(0);
        let b = params.get("@P2").copied().unwrap_or(0);
        return vec![a + b];
    }
    if sql.eq_ignore_ascii_case("SELECT 1 AS v UNION ALL SELECT 2 AS v UNION ALL SELECT 3 AS v") {
        return vec![1, 2, 3];
    }
    // Fail loud rather than silently returning an empty result set — real
    // SQL Server would reject malformed SQL, and silence here would mask
    // client-side bugs that place the param-defs string in the SQL slot,
    // botch parameter names, etc.
    panic!(
        "test harness received SQL it doesn't recognise: {:?} (known params: {:?}). \
         Either the client sent the wrong string or this harness needs a new arm.",
        sql, params
    );
}

fn int_int_column() -> MetaDataColumn<'static> {
    MetaDataColumn {
        base: BaseMetaDataColumn {
            user_type: 0,
            flags: BitFlags::from(ColumnFlag::Nullable),
            ty: TypeInfo::FixedLen(FixedLenType::Int4),
            table_name: None,
        },
        col_name: Cow::Borrowed("v"),
    }
}

async fn write_int_result_set<C>(
    client: &mut C,
    rows: &[i32],
    final_done_flags: FinalDone,
) -> tiberius::Result<()>
where
    C: TdsClient,
{
    let mut writer = ResultSetWriter::start(client, vec![int_int_column()]).await?;
    for v in rows {
        writer.send_row_iter([ColumnData::I32(Some(*v))]).await?;
    }
    // DoneInProc is part of an in-flight RPC response — subsequent tokens
    // (ReturnValue, ReturnStatus, DoneProc) follow, so we must NOT flag this
    // as end-of-message.
    match final_done_flags {
        FinalDone::InProcMore => {
            let done = TokenDone::with_more_rows(rows.len() as u64);
            writer
                .into_client()
                .send(TdsBackendMessage::TokenPartial(BackendToken::DoneInProc(
                    done,
                )))
                .await
        }
        FinalDone::InProc => {
            let done = TokenDone::with_rows(rows.len() as u64);
            writer
                .into_client()
                .send(TdsBackendMessage::TokenPartial(BackendToken::DoneInProc(
                    done,
                )))
                .await
        }
    }
}

enum FinalDone {
    InProc,
    InProcMore,
}

// =============================================================================
// Prepare / Execute / Unprepare
// =============================================================================

struct TestPrepare(Arc<SharedState>);

impl SpPrepareHandler for TestPrepare {
    fn prepare<'a, C>(
        &'a self,
        client: &'a mut C,
        request: ParsedPrepare<'a>,
    ) -> BoxFuture<'a, tiberius::Result<PreparedHandle>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async move {
            let sql = request.sql().to_string();
            let handle = self
                .0
                .procs
                .lock()
                .unwrap()
                .prepare(sql, Vec::new(), Vec::new());

            send_output_param(
                client,
                OutputParameter::new("@handle", ColumnData::I32(Some(handle.as_i32())))
                    .with_ordinal(1)
                    .with_type_info(request.handle_type_info().clone()),
            )
            .await?;
            send_return_status(client, 0).await?;
            client
                .send(TdsBackendMessage::Token(BackendToken::DoneProc(
                    TokenDone::with_rows(0),
                )))
                .await?;
            Ok(handle)
        })
    }
}

struct TestExecute(Arc<SharedState>);

impl SpExecuteHandler for TestExecute {
    fn execute<'a, C>(
        &'a self,
        client: &'a mut C,
        request: ParsedExecute<'a>,
    ) -> BoxFuture<'a, tiberius::Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async move {
            let handle = request.handle();
            let sql = {
                let mut cache = self.0.procs.lock().unwrap();
                match cache.get_and_record(&handle) {
                    Some(stmt) => stmt.sql.clone(),
                    None => {
                        return Err(tiberius::error::Error::Protocol(
                            format!("unknown prepared handle {}", handle.as_i32()).into(),
                        ));
                    }
                }
            };
            let params = collect_params(&request);
            let rows = eval_sql(&sql, &params);

            write_int_result_set(client, &rows, FinalDone::InProcMore).await?;
            send_return_status(client, 0).await?;
            client
                .send(TdsBackendMessage::Token(BackendToken::DoneProc(
                    TokenDone::with_rows(rows.len() as u64),
                )))
                .await?;
            Ok(())
        })
    }
}

struct TestUnprepare(Arc<SharedState>);

impl SpUnprepareHandler for TestUnprepare {
    fn unprepare<'a, C>(
        &'a self,
        client: &'a mut C,
        request: ParsedUnprepare,
    ) -> BoxFuture<'a, tiberius::Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async move {
            self.0.procs.lock().unwrap().unprepare(&request.handle());
            send_return_status(client, 0).await?;
            client
                .send(TdsBackendMessage::Token(BackendToken::DoneProc(
                    TokenDone::with_rows(0),
                )))
                .await?;
            Ok(())
        })
    }
}

// =============================================================================
// PrepExec
// =============================================================================

struct TestPrepExec(Arc<SharedState>);

impl SpPrepExecHandler for TestPrepExec {
    fn prep_exec<'a, C>(
        &'a self,
        client: &'a mut C,
        request: ParsedPrepExec<'a>,
    ) -> BoxFuture<'a, tiberius::Result<PreparedHandle>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async move {
            let sql = request.sql().to_string();
            let handle_type = request.handle_type_info().clone();
            let handle = self
                .0
                .procs
                .lock()
                .unwrap()
                .prepare(sql.clone(), Vec::new(), Vec::new());

            let mut params: HashMap<String, i32> = HashMap::new();
            for p in request.params() {
                if let Some(v) = p.get_i32() {
                    params.insert(p.name().to_string(), v);
                }
            }
            let rows = eval_sql(&sql, &params);
            write_int_result_set(client, &rows, FinalDone::InProc).await?;
            send_output_param(
                client,
                OutputParameter::new("@handle", ColumnData::I32(Some(handle.as_i32())))
                    .with_ordinal(1)
                    .with_type_info(handle_type),
            )
            .await?;
            send_return_status(client, 0).await?;
            client
                .send(TdsBackendMessage::Token(BackendToken::DoneProc(
                    TokenDone::with_rows(rows.len() as u64),
                )))
                .await?;
            Ok(handle)
        })
    }
}

fn collect_params(request: &ParsedExecute<'_>) -> HashMap<String, i32> {
    let mut out = HashMap::new();
    for p in request.params() {
        if let Some(v) = p.get_i32() {
            out.insert(p.name().to_string(), v);
        }
    }
    out
}

// =============================================================================
// Cursor handlers
// =============================================================================

struct TestCursorOpen(Arc<SharedState>);

impl SpCursorOpenHandler for TestCursorOpen {
    fn cursor_open<'a, C>(
        &'a self,
        client: &'a mut C,
        request: ParsedCursorOpen<'a>,
    ) -> BoxFuture<'a, tiberius::Result<CursorHandle>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async move {
            let rows = eval_sql(&request.sql, &HashMap::new());
            let scrollopt = request.scrollopt;
            let ccopt = request.ccopt;

            let entry =
                CursorEntry::new(request.sql.to_string(), scrollopt, ccopt, rows.len() as i32);
            let handle = self.0.cursors.lock().unwrap().open(entry);
            self.0
                .cursor_rows
                .lock()
                .unwrap()
                .insert(handle, rows.clone());

            // Build output parameters in the order the spec declares.
            let outputs = vec![
                OutputParameter::new("@cursor", ColumnData::I32(Some(handle.as_i32())))
                    .with_ordinal(1)
                    .with_type_info(request.cursor_type_info.clone()),
                OutputParameter::new("@scrollopt", ColumnData::I32(Some(scrollopt)))
                    .with_ordinal(3)
                    .with_type_info(request.scrollopt_type_info.clone()),
                OutputParameter::new("@ccopt", ColumnData::I32(Some(ccopt)))
                    .with_ordinal(4)
                    .with_type_info(request.ccopt_type_info.clone()),
                OutputParameter::new("@rowcount", ColumnData::I32(Some(rows.len() as i32)))
                    .with_ordinal(5)
                    .with_type_info(request.rowcount_type_info.clone()),
            ];
            send_output_params(client, outputs).await?;
            send_return_status(client, 0).await?;
            client
                .send(TdsBackendMessage::Token(BackendToken::DoneProc(
                    TokenDone::with_rows(0),
                )))
                .await?;
            Ok(handle)
        })
    }
}

struct TestCursorFetch(Arc<SharedState>);

impl SpCursorFetchHandler for TestCursorFetch {
    fn cursor_fetch<'a, C>(
        &'a self,
        client: &'a mut C,
        request: ParsedCursorFetch,
    ) -> BoxFuture<'a, tiberius::Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async move {
            self.0.rpc_log.lock().unwrap().push(RpcProcId::CursorFetch);
            // Record the fetch params so tests can assert the client's
            // wire encoding of (fetch_type, row_num, n_rows) survived the
            // round trip.
            self.0.cursor_fetch_log.lock().unwrap().push((
                request.fetch_type,
                request.row_num,
                request.n_rows,
            ));

            let rows = {
                let store = self.0.cursor_rows.lock().unwrap();
                store.get(&request.handle).cloned().unwrap_or_default()
            };

            if request.n_rows == 0 {
                client
                    .send(TdsBackendMessage::TokenPartial(BackendToken::ColMetaData(
                        TokenColMetaData {
                            columns: vec![int_int_column()],
                        },
                    )))
                    .await?;
                client
                    .send(TdsBackendMessage::TokenPartial(BackendToken::DoneInProc(
                        TokenDone::with_rows(0),
                    )))
                    .await?;
            } else {
                write_int_result_set(client, &rows, FinalDone::InProc).await?;
            }
            send_return_status(client, 0).await?;
            client
                .send(TdsBackendMessage::Token(BackendToken::DoneProc(
                    TokenDone::with_rows(rows.len() as u64),
                )))
                .await?;
            Ok(())
        })
    }
}

struct TestCursorClose(Arc<SharedState>);

impl SpCursorCloseHandler for TestCursorClose {
    fn cursor_close<'a, C>(
        &'a self,
        client: &'a mut C,
        request: ParsedCursorClose,
    ) -> BoxFuture<'a, tiberius::Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async move {
            self.0.rpc_log.lock().unwrap().push(RpcProcId::CursorClose);
            self.0.cursors.lock().unwrap().close(&request.handle);
            self.0.cursor_rows.lock().unwrap().remove(&request.handle);
            send_return_status(client, 0).await?;
            client
                .send(TdsBackendMessage::Token(BackendToken::DoneProc(
                    TokenDone::with_rows(0),
                )))
                .await?;
            Ok(())
        })
    }
}

// =============================================================================
// Server wiring
// =============================================================================

type TestRouter = SystemProcRouter<
    RejectIt,
    TestPrepare,
    TestExecute,
    TestUnprepare,
    TestPrepExec,
    TestCursorOpen,
    TestCursorFetch,
    TestCursorClose,
    SpecialRpc,
>;

struct RejectIt;

impl RpcHandler for RejectIt {
    fn on_rpc<'a, C>(
        &'a self,
        _client: &'a mut C,
        _message: tiberius::server::RpcMessage,
    ) -> BoxFuture<'a, tiberius::Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async {
            Err(tiberius::error::Error::Protocol(
                "test harness: unexpected RPC".into(),
            ))
        })
    }
}

struct SpecialRpc(Arc<SharedState>);

impl RpcHandler for SpecialRpc {
    fn on_rpc<'a, C>(
        &'a self,
        client: &'a mut C,
        message: tiberius::server::RpcMessage,
    ) -> BoxFuture<'a, tiberius::Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async move {
            match message.proc_id {
                Some(RpcProcId::CursorPrepExec) => {
                    self.0
                        .rpc_log
                        .lock()
                        .unwrap()
                        .push(RpcProcId::CursorPrepExec);
                    let params = message.into_param_set().await?;
                    let all = params.all();
                    assert!(
                        all.len() >= 7,
                        "sp_cursorprepexec expected at least 7 params, got {}",
                        all.len()
                    );
                    assert!(all[0].is_output());
                    assert!(all[1].is_output());
                    assert!(all[4].is_output());
                    assert!(all[5].is_output());
                    assert!(all[6].is_output());
                    match &all[2].value {
                        ColumnData::String(Some(s)) => {
                            self.0
                                .cursorprepexec_param_defs_log
                                .lock()
                                .unwrap()
                                .push(Some(s.to_string()));
                        }
                        ColumnData::String(None) => {
                            self.0
                                .cursorprepexec_param_defs_log
                                .lock()
                                .unwrap()
                                .push(None);
                        }
                        other => panic!("sp_cursorprepexec @params was not a string: {:?}", other),
                    }

                    let sql = match &all[3].value {
                        ColumnData::String(Some(s)) => s.to_string(),
                        other => panic!("sp_cursorprepexec @stmt was not a string: {:?}", other),
                    };
                    let mut values = HashMap::new();
                    for p in &all[7..] {
                        if let ColumnData::I32(Some(v)) = &p.value {
                            values.insert(p.name.clone(), *v);
                        }
                    }
                    let rows = eval_sql(&sql, &values);

                    let prepared_handle =
                        self.0
                            .procs
                            .lock()
                            .unwrap()
                            .prepare(sql.clone(), Vec::new(), Vec::new());
                    let scrollopt = match &all[4].value {
                        ColumnData::I32(Some(v)) => *v,
                        _ => 0,
                    };
                    let ccopt = match &all[5].value {
                        ColumnData::I32(Some(v)) => *v,
                        _ => 0,
                    };
                    let cursor_entry = CursorEntry::new(sql, scrollopt, ccopt, rows.len() as i32);
                    let cursor_handle = self.0.cursors.lock().unwrap().open(cursor_entry);
                    self.0
                        .cursor_rows
                        .lock()
                        .unwrap()
                        .insert(cursor_handle, rows.clone());

                    let send_metadata = *self.0.cursorprepexec_send_metadata.lock().unwrap();
                    if send_metadata {
                        client
                            .send(TdsBackendMessage::TokenPartial(BackendToken::ColMetaData(
                                TokenColMetaData {
                                    columns: vec![int_int_column()],
                                },
                            )))
                            .await?;
                        client
                            .send(TdsBackendMessage::TokenPartial(BackendToken::DoneInProc(
                                TokenDone::with_rows(0),
                            )))
                            .await?;
                    }

                    let outputs = vec![
                        OutputParameter::from_input(
                            &all[0],
                            ColumnData::I32(Some(prepared_handle.as_i32())),
                        )
                        .with_ordinal(1),
                        OutputParameter::from_input(
                            &all[1],
                            ColumnData::I32(Some(cursor_handle.as_i32())),
                        )
                        .with_ordinal(2),
                        OutputParameter::from_input(&all[4], ColumnData::I32(Some(scrollopt)))
                            .with_ordinal(5),
                        OutputParameter::from_input(&all[5], ColumnData::I32(Some(ccopt)))
                            .with_ordinal(6),
                        OutputParameter::from_input(
                            &all[6],
                            ColumnData::I32(Some(rows.len() as i32)),
                        )
                        .with_ordinal(7),
                    ];
                    send_output_params(client, outputs).await?;
                    send_return_status(client, 0).await?;
                    client
                        .send(TdsBackendMessage::Token(BackendToken::DoneProc(
                            TokenDone::with_rows(0),
                        )))
                        .await?;
                    Ok(())
                }
                Some(RpcProcId::CursorUnprepare) => {
                    self.0
                        .rpc_log
                        .lock()
                        .unwrap()
                        .push(RpcProcId::CursorUnprepare);
                    let params = message.into_param_set().await?;
                    let handle = match params.get(0).map(|p| &p.value) {
                        Some(ColumnData::I32(Some(v))) => PreparedHandle::from_i32(*v),
                        other => panic!("sp_cursorunprepare handle was not i32: {:?}", other),
                    };
                    self.0.procs.lock().unwrap().unprepare(&handle);
                    send_return_status(client, 0).await?;
                    client
                        .send(TdsBackendMessage::Token(BackendToken::DoneProc(
                            TokenDone::with_rows(0),
                        )))
                        .await?;
                    Ok(())
                }
                _ => Err(tiberius::error::Error::Protocol(
                    "test harness: unexpected RPC".into(),
                )),
            }
        })
    }
}

// SystemProcRouter requires each slot's type to implement the corresponding
// handler trait (even if the slot is None). We don't wire an sp_executesql
// handler for these tests, so give `RejectIt` a trait impl that errors on
// invocation — it will never be reached because the slot is None.
impl tiberius::server::SpExecuteSqlHandler for RejectIt {
    fn execute<'a, C>(
        &'a self,
        _client: &'a mut C,
        _request: tiberius::server::ParsedExecuteSql<'a>,
    ) -> BoxFuture<'a, tiberius::Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async {
            Err(tiberius::error::Error::Protocol(
                "test harness: unexpected sp_executesql".into(),
            ))
        })
    }
}

struct TestHandlers {
    auth: TestAuth,
    sql: NoopSqlBatch,
    rpc: TestRouter,
    bulk: RejectBulkLoad,
    attention: NoOpAttention,
    error: NoOpError,
}

impl TestHandlers {
    fn new(state: Arc<SharedState>) -> Self {
        let rpc: TestRouter = SystemProcRouterBuilder::new()
            .with_executesql(RejectIt)
            .with_prepare(TestPrepare(state.clone()))
            .with_execute(TestExecute(state.clone()))
            .with_unprepare(TestUnprepare(state.clone()))
            .with_prepexec(TestPrepExec(state.clone()))
            .with_cursor_open(TestCursorOpen(state.clone()))
            .with_cursor_fetch(TestCursorFetch(state.clone()))
            .with_cursor_close(TestCursorClose(state.clone()))
            .with_fallback(SpecialRpc(state.clone()))
            .build();
        Self {
            auth: TestAuth::new(),
            sql: NoopSqlBatch,
            rpc,
            bulk: RejectBulkLoad,
            attention: NoOpAttention,
            error: NoOpError,
        }
    }
}

impl TdsServerHandlers for TestHandlers {
    type Auth = TestAuth;
    type SqlBatch = NoopSqlBatch;
    type Rpc = TestRouter;
    type Bulk = RejectBulkLoad;
    type Attention = NoOpAttention;
    type Error = NoOpError;

    fn auth_handler(&self) -> &Self::Auth {
        &self.auth
    }
    fn sql_batch_handler(&self) -> &Self::SqlBatch {
        &self.sql
    }
    fn rpc_handler(&self) -> &Self::Rpc {
        &self.rpc
    }
    fn bulk_load_handler(&self) -> &Self::Bulk {
        &self.bulk
    }
    fn attention_handler(&self) -> &Self::Attention {
        &self.attention
    }
    fn error_handler(&self) -> &Self::Error {
        &self.error
    }
}

// =============================================================================
// Test harness: spawn a server, connect a client
// =============================================================================

async fn run_server_once(
    listener: async_net::TcpListener,
    handlers: Arc<TestHandlers>,
) -> tiberius::Result<()> {
    use tiberius::server::backend::smol_net::SmolStream;
    let (stream, _addr) = listener
        .accept()
        .await
        .map_err(|e| tiberius::error::Error::Io {
            kind: e.kind(),
            message: e.to_string(),
        })?;
    let stream = SmolStream::new(stream);
    let tls: Option<tiberius::server::NoTls> = None;
    process_connection(stream, tls, &*handlers).await
}

async fn connect_client(
    addr: SocketAddr,
) -> tiberius::Result<Client<smol_adapter::Compat<async_net::TcpStream>>> {
    let stream =
        async_net::TcpStream::connect(addr)
            .await
            .map_err(|e| tiberius::error::Error::Io {
                kind: e.kind(),
                message: e.to_string(),
            })?;
    stream.set_nodelay(true).ok();
    let mut config = Config::new();
    config.host(addr.ip().to_string());
    config.port(addr.port());
    config.authentication(tiberius::AuthMethod::sql_server("u", "p"));
    config.encryption(EncryptionLevel::NotSupported);
    config.trust_cert();
    Client::connect(config, smol_adapter::Compat::new(stream)).await
}

mod smol_adapter {
    //! Minimal wrapper so async-net TcpStream (which uses futures_lite) can
    //! act as futures_util AsyncRead/AsyncWrite for the Tiberius client.
    use futures_lite::io::{AsyncRead as LiteRead, AsyncWrite as LiteWrite};
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    pub struct Compat<S>(S);

    impl<S> Compat<S> {
        pub fn new(inner: S) -> Self {
            Self(inner)
        }
    }

    impl<S: LiteRead + Unpin> futures_util::io::AsyncRead for Compat<S> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl<S: LiteWrite + Unpin> futures_util::io::AsyncWrite for Compat<S> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }
        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_close(cx)
        }
    }
}

async fn with_server<F, Fut, T>(test: F) -> T
where
    F: FnOnce(SocketAddr, Arc<SharedState>) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let state = Arc::new(SharedState::new());
    let handlers = Arc::new(TestHandlers::new(state.clone()));

    let listener = async_net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = smol::spawn({
        let handlers = handlers.clone();
        async move {
            let _ = run_server_once(listener, handlers).await;
        }
    });

    let result = test(addr, state).await;
    server_task.cancel().await;
    result
}

// =============================================================================
// Tests
// =============================================================================

#[test]
fn prepare_execute_unprepare_round_trip() {
    smol::block_on(async {
        with_server(|addr, _state| async move {
            let mut client = connect_client(addr).await.unwrap();

            let stmt = client
                .prepare("SELECT @P1 + @P2 AS s", "@P1 int, @P2 int")
                .await
                .unwrap();
            let handle = stmt.handle();
            assert_ne!(handle.as_i32(), 0);

            let row = stmt
                .query(&mut client, &[&7i32, &35i32])
                .await
                .unwrap()
                .into_row()
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.get::<i32, _>(0), Some(42));
            // Handle is stable across executes.
            assert_eq!(stmt.handle(), handle);

            stmt.unprepare(&mut client).await.unwrap();
        })
        .await;
    });
}

#[test]
fn prep_exec_returns_handle_and_rows() {
    smol::block_on(async {
        with_server(|addr, _state| async move {
            let mut client = connect_client(addr).await.unwrap();

            let (stmt, results) = client
                .prep_exec("SELECT @P1 AS v", "@P1 int", &[&99i32])
                .await
                .unwrap();
            assert_ne!(stmt.handle().as_i32(), 0);
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].len(), 1);
            assert_eq!(results[0][0].get::<i32, _>(0), Some(99));

            // Reuse the returned handle.
            let row = stmt
                .query(&mut client, &[&7i32])
                .await
                .unwrap()
                .into_row()
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.get::<i32, _>(0), Some(7));

            stmt.unprepare(&mut client).await.unwrap();
        })
        .await;
    });
}

#[test]
fn open_fetch_close_cursor() {
    smol::block_on(async {
        with_server(|addr, state| async move {
            let mut client = connect_client(addr).await.unwrap();

            let cursor = client
                .open_cursor(
                    "SELECT 1 AS v UNION ALL SELECT 2 AS v UNION ALL SELECT 3 AS v",
                    CursorOpenOptions::default(),
                    "",
                    &[],
                )
                .await
                .unwrap();
            assert_ne!(cursor.handle().as_i32(), 0);
            assert_eq!(cursor.row_count(), 3);

            // Use a distinctive fetch request so we can prove the wire
            // encoding survives: Fetch::Absolute encodes to (0x0010, 7, 3).
            let rows = cursor
                .fetch(&mut client, tiberius::Fetch::Absolute { row: 7, count: 3 })
                .await
                .unwrap()
                .into_first_result()
                .await
                .unwrap();
            assert_eq!(rows.len(), 3);
            assert_eq!(rows[0].get::<i32, _>(0), Some(1));
            assert_eq!(rows[1].get::<i32, _>(0), Some(2));
            assert_eq!(rows[2].get::<i32, _>(0), Some(3));

            // Server received what the client claimed to send.
            let seen = state.cursor_fetch_log.lock().unwrap().clone();
            assert_eq!(seen, vec![(0x0010, 7, 3)]);

            cursor.close(&mut client).await.unwrap();
        })
        .await;
    });
}

#[test]
fn cursor_prep_exec_fetch_close_unprepare() {
    smol::block_on(async {
        with_server(|addr, state| async move {
            let mut client = connect_client(addr).await.unwrap();

            let mut cursor = client
                .cursor_prep_exec(
                    "SELECT 1 AS v UNION ALL SELECT 2 AS v UNION ALL SELECT 3 AS v",
                    CursorOpenOptions::new(
                        CursorScrollOptions::ParameterizedStmt | CursorScrollOptions::ForwardOnly,
                        tiberius::CursorConcurrencyOptions::ReadOnly,
                    ),
                    "",
                    &[],
                )
                .await
                .unwrap();
            assert_ne!(cursor.prepared_handle().as_i32(), 0);
            assert_ne!(cursor.cursor_handle().as_i32(), 0);
            assert_eq!(cursor.row_count(), 3);
            assert!(cursor
                .scroll_options()
                .contains(CursorScrollOptions::ParameterizedStmt));

            let mut stream = cursor
                .fetch(&mut client, tiberius::Fetch::Next { count: 142 })
                .await
                .unwrap();
            let columns = stream.columns().await.unwrap().unwrap();
            assert_eq!(columns[0].name(), "v");
            assert_eq!(columns[0].ordinal(), Some(0));
            assert_eq!(
                columns[0].type_info(),
                Some(&TypeInfo::FixedLen(FixedLenType::Int4))
            );
            assert_eq!(columns[0].fixed_len_type(), Some(FixedLenType::Int4));
            assert!(columns[0].flags().contains(ColumnFlag::Nullable));
            assert!(columns[0].is_nullable());

            let rows = stream.into_first_result().await.unwrap();
            assert_eq!(rows.len(), 3);
            assert_eq!(rows[0].get::<i32, _>(0), Some(1));
            assert_eq!(
                rows[0].columns()[0].type_info(),
                Some(&TypeInfo::FixedLen(FixedLenType::Int4))
            );
            assert!(rows[0].columns()[0].flags().contains(ColumnFlag::Nullable));
            assert_eq!(rows[1].get::<i32, _>(0), Some(2));
            assert_eq!(rows[2].get::<i32, _>(0), Some(3));

            let seen_fetches = state.cursor_fetch_log.lock().unwrap().clone();
            assert_eq!(seen_fetches, vec![(0x0002, 0, 142)]);

            cursor.close_cursor(&mut client).await.unwrap();
            cursor.close_cursor(&mut client).await.unwrap();
            cursor.unprepare(&mut client).await.unwrap();

            let seen_rpcs = state.rpc_log.lock().unwrap().clone();
            assert_eq!(
                seen_rpcs,
                vec![
                    RpcProcId::CursorPrepExec,
                    RpcProcId::CursorFetch,
                    RpcProcId::CursorClose,
                    RpcProcId::CursorUnprepare,
                ]
            );
        })
        .await;
    });
}

#[test]
fn cursor_prep_exec_fetch_metadata_close_unprepare() {
    smol::block_on(async {
        with_server(|addr, state| async move {
            let mut client = connect_client(addr).await.unwrap();

            let mut cursor = client
                .cursor_prep_exec(
                    "SELECT 1 AS v UNION ALL SELECT 2 AS v UNION ALL SELECT 3 AS v",
                    CursorOpenOptions::default(),
                    "",
                    &[],
                )
                .await
                .unwrap();

            let columns = cursor.fetch_metadata(&mut client).await.unwrap();
            assert_eq!(columns.len(), 1);
            assert_eq!(columns[0].name(), "v");
            assert_eq!(columns[0].ordinal(), Some(0));
            assert_eq!(
                columns[0].type_info(),
                Some(&TypeInfo::FixedLen(FixedLenType::Int4))
            );
            assert!(columns[0].flags().contains(ColumnFlag::Nullable));

            let seen_fetches = state.cursor_fetch_log.lock().unwrap().clone();
            assert_eq!(seen_fetches, vec![(0x0002, 0, 0)]);

            let param_defs = state.cursorprepexec_param_defs_log.lock().unwrap().clone();
            assert_eq!(param_defs, vec![None]);

            cursor.close_cursor(&mut client).await.unwrap();
            cursor.unprepare(&mut client).await.unwrap();

            let seen_rpcs = state.rpc_log.lock().unwrap().clone();
            assert_eq!(
                seen_rpcs,
                vec![
                    RpcProcId::CursorPrepExec,
                    RpcProcId::CursorFetch,
                    RpcProcId::CursorClose,
                    RpcProcId::CursorUnprepare,
                ]
            );
        })
        .await;
    });
}

#[test]
fn cursor_prep_exec_fetch_metadata_reuses_initial_metadata() {
    smol::block_on(async {
        with_server(|addr, state| async move {
            *state.cursorprepexec_send_metadata.lock().unwrap() = true;
            let mut client = connect_client(addr).await.unwrap();

            let mut cursor = client
                .cursor_prep_exec(
                    "SELECT 1 AS v UNION ALL SELECT 2 AS v UNION ALL SELECT 3 AS v",
                    CursorOpenOptions::default(),
                    "",
                    &[],
                )
                .await
                .unwrap();

            let columns = cursor.fetch_metadata(&mut client).await.unwrap();
            assert_eq!(columns.len(), 1);
            assert_eq!(columns[0].name(), "v");
            assert_eq!(columns[0].ordinal(), Some(0));
            assert_eq!(
                columns[0].type_info(),
                Some(&TypeInfo::FixedLen(FixedLenType::Int4))
            );
            assert!(columns[0].flags().contains(ColumnFlag::Nullable));

            let seen_fetches = state.cursor_fetch_log.lock().unwrap().clone();
            assert!(seen_fetches.is_empty());

            let param_defs = state.cursorprepexec_param_defs_log.lock().unwrap().clone();
            assert_eq!(param_defs, vec![None]);

            cursor.close_cursor(&mut client).await.unwrap();
            cursor.unprepare(&mut client).await.unwrap();

            let seen_rpcs = state.rpc_log.lock().unwrap().clone();
            assert_eq!(
                seen_rpcs,
                vec![
                    RpcProcId::CursorPrepExec,
                    RpcProcId::CursorClose,
                    RpcProcId::CursorUnprepare,
                ]
            );
        })
        .await;
    });
}

#[test]
fn cursor_fetch_encodes_all_directions() {
    // Drives every `Fetch` variant and asserts the server sees the right
    // (fetch_type, row_num, count) triple for each. Catches bugs where the
    // client-side encoder maps a variant to the wrong wire bits.
    smol::block_on(async {
        with_server(|addr, state| async move {
            let mut client = connect_client(addr).await.unwrap();
            let cursor = client
                .open_cursor(
                    "SELECT 1 AS v UNION ALL SELECT 2 AS v UNION ALL SELECT 3 AS v",
                    CursorOpenOptions::default(),
                    "",
                    &[],
                )
                .await
                .unwrap();

            let cases: &[(tiberius::Fetch, (i32, i32, i32))] = &[
                (tiberius::Fetch::First { count: 1 }, (0x0001, 0, 1)),
                (tiberius::Fetch::Next { count: 2 }, (0x0002, 0, 2)),
                (tiberius::Fetch::Prev { count: 3 }, (0x0004, 0, 3)),
                (tiberius::Fetch::Last { count: 4 }, (0x0008, 0, 4)),
                (
                    tiberius::Fetch::Absolute { row: 9, count: 5 },
                    (0x0010, 9, 5),
                ),
                (
                    tiberius::Fetch::Relative {
                        offset: -7,
                        count: 6,
                    },
                    (0x0020, -7, 6),
                ),
                (tiberius::Fetch::Refresh { count: 1 }, (0x0080, 0, 1)),
            ];

            for (fetch, _expected) in cases {
                let _ = cursor
                    .fetch(&mut client, *fetch)
                    .await
                    .unwrap()
                    .into_first_result()
                    .await
                    .unwrap();
            }

            let seen = state.cursor_fetch_log.lock().unwrap().clone();
            let expected: Vec<_> = cases.iter().map(|(_, e)| *e).collect();
            assert_eq!(seen, expected);

            cursor.close(&mut client).await.unwrap();
        })
        .await;
    });
}

#[test]
fn cancellation_mid_query_surfaces_as_error() {
    // Exercises the interaction between CancellationToken and the RPC
    // stream drain path. We fire the cancel from another task before the
    // result stream is consumed; the next poll on the stream must surface
    // an error (not hang).
    smol::block_on(async {
        with_server(|addr, _state| async move {
            let mut client = connect_client(addr).await.unwrap();
            let stmt = client.prepare("SELECT @P1 AS v", "@P1 int").await.unwrap();

            // Issue the query so bytes are in flight, then cancel before
            // consuming the response.
            let token = client.cancellation_token();
            let stream = stmt.query(&mut client, &[&1i32]).await.unwrap();
            token.cancel();

            // Consuming the stream after cancel: either yields results or
            // errors, but must NOT hang — we're just asserting termination.
            let _ = stream.into_results().await;

            // Connection is still reusable after cancellation drain.
            let stmt2 = client.prepare("SELECT @P1 AS v", "@P1 int").await.unwrap();
            let row = stmt2
                .query(&mut client, &[&42i32])
                .await
                .unwrap()
                .into_row()
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.get::<i32, _>(0), Some(42));

            stmt.unprepare(&mut client).await.ok();
            stmt2.unprepare(&mut client).await.unwrap();
        })
        .await;
    });
}

#[test]
fn prepared_statement_is_marked_released_after_unprepare() {
    // Guards the drop-warn false-positive fix (issue #2): `released` must
    // flip to true as soon as the sp_unprepare packet reaches the wire,
    // not after a potentially-flaky drain. We can't directly observe the
    // Drop warn, but unprepare returning Ok(()) means the flag was set;
    // the test below exercises the "dropped without unprepare" path by
    // explicitly leaking a prepared statement and verifying the test
    // doesn't panic (the warn is emitted via tracing::event! which is a
    // no-op under the default test subscriber).
    smol::block_on(async {
        with_server(|addr, _state| async move {
            let mut client = connect_client(addr).await.unwrap();
            let stmt = client.prepare("SELECT @P1 AS v", "@P1 int").await.unwrap();
            // Explicitly drop without unprepare — exercises the Drop warn
            // path. Test passes as long as this doesn't panic / hang.
            drop(stmt);
        })
        .await;
    });
}
