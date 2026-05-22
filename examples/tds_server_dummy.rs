//! Dummy TDS server for protocol testing.
//!
//! Run with:
//!   cargo run --example tds_server_dummy --features server-smol

#[cfg(not(feature = "server-smol"))]
fn main() {
    eprintln!("Enable the server-smol feature to run this example.");
}

#[cfg(feature = "server-smol")]
mod server {
    use async_io::Timer;
    use async_trait::async_trait;
    use bytes::{BufMut, BytesMut};
    use futures_lite::future;
    use futures_util::sink::SinkExt;
    use std::borrow::Cow;
    use std::io;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use tiberius::server::backend::smol_net::SmolNetBackend;
    use tiberius::server::backend::{NetBackend, NetListener, NetStream};
    use tiberius::server::codec::{decode_rpc_params, DecodedRpcParam};
    use tiberius::server::{
        process_connection, AttentionHandler, AuthBuilder, AuthError, AuthHandler, AuthSuccess,
        BulkLoadHandler, DefaultEnvChangeProvider, EnvChangeProvider, ErrorHandler, FedAuthValidator,
        LoginInfo, ResultSetWriter, RpcHandler, SqlAuthSource, SqlBatchHandler, SspiAcceptor,
        SspiStart, SspiStep, TdsAuthHandler, TdsBackendMessage, TdsConnectionContext, TdsConnectionState,
        TdsServerHandlers,
    };
    use tiberius::{
        numeric::Numeric,
        time::{Date, DateTime, DateTime2, DateTimeOffset, SmallDateTime, Time},
        xml::XmlData,
        AltMetaDataColumn, BaseMetaDataColumn, Collation, ColumnData, ColumnFlag, DoneStatus,
        FedAuthInfoOption, FixedLenType, LoginMessage, MetaDataColumn, PreloginMessage, RpcStatus,
        SessionStateEntry, SsVariantInfo, TokenAltMetaData, TokenAltRow, TokenColInfo,
        TokenColMetaData, TokenColName, TokenDone, TokenEnvChange, TokenError, TokenFedAuthInfo,
        TokenFeatureExtAck, TokenInfo, TokenLoginAck, TokenOrder, TokenReturnValue, TokenRow,
        TokenSessionState, TokenTabName, TvpColumn, TvpData, TvpInfo, TypeInfo, UdtInfo,
        VariantData, Uuid, VarLenContext, VarLenType,
    };
    use tiberius::{EncryptionLevel, Result};

    #[cfg(feature = "server-rustls")]
    use async_rustls::rustls::{version, Certificate, PrivateKey, ServerConfig};
    #[cfg(feature = "server-rustls")]
    use std::fs::File;
    #[cfg(feature = "server-rustls")]
    use std::io::BufReader;
    #[cfg(feature = "server-rustls")]
    use tiberius::server::RustlsAcceptor;

    fn log_event(event: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        eprintln!(
            "[tds-dummy {:>10}.{:03}] {event}",
            now.as_secs(),
            now.subsec_millis()
        );
    }

    static TRACE_CONN_ID: AtomicU64 = AtomicU64::new(1);

    struct TraceStream<S> {
        inner: S,
        id: u64,
        remaining: usize,
        enabled: bool,
    }

    impl<S> TraceStream<S> {
        fn new(inner: S) -> Self {
            let enabled = std::env::var("TDS_DUMMY_TRACE_IO").ok().as_deref() == Some("1");
            let remaining = std::env::var("TDS_DUMMY_TRACE_LIMIT")
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(40);

            Self {
                inner,
                id: TRACE_CONN_ID.fetch_add(1, Ordering::Relaxed),
                remaining,
                enabled,
            }
        }

        fn trace_write(&mut self, buf: &[u8]) {
            if !self.enabled || self.remaining == 0 || buf.is_empty() {
                return;
            }
            self.remaining -= 1;

            let kind = if buf.len() >= 2
                && matches!(buf[0], 0x14 | 0x15 | 0x16 | 0x17)
                && buf[1] == 0x03
            {
                "tls"
            } else {
                "plain"
            };

            let mut head = String::new();
            for (idx, byte) in buf.iter().take(12).enumerate() {
                if idx > 0 {
                    head.push(' ');
                }
                head.push_str(&format!("{:02x}", byte));
            }

            log_event(&format!(
                "trace-io id={} write len={} kind={} head={}",
                self.id,
                buf.len(),
                kind,
                head
            ));
        }
    }

    impl<S: NetStream> NetStream for TraceStream<S> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }

        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            this.trace_write(buf);
            Pin::new(&mut this.inner).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_close(cx)
        }

        fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
            self.inner.peer_addr()
        }

        fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
            self.inner.local_addr()
        }
    }

    const TDS_VER_70: u32 = 0x70000000;
    const TDS_VER_74: u32 = 0x74000004;

    fn meta_type(name: &str, ty: TypeInfo) -> MetaDataColumn<'static> {
        meta_type_flags(name, ty, ColumnFlag::Nullable.into())
    }

    fn meta_type_flags(
        name: &str,
        ty: TypeInfo,
        flags: enumflags2::BitFlags<ColumnFlag>,
    ) -> MetaDataColumn<'static> {
        MetaDataColumn {
            base: BaseMetaDataColumn {
                user_type: 0,
                flags,
                ty,
                table_name: None,
            },
            col_name: name.to_string().into(),
        }
    }

    fn meta_type_flags_table(
        name: &str,
        ty: TypeInfo,
        flags: enumflags2::BitFlags<ColumnFlag>,
        table_name: Option<Vec<String>>,
    ) -> MetaDataColumn<'static> {
        MetaDataColumn {
            base: BaseMetaDataColumn {
                user_type: 0,
                flags,
                ty,
                table_name,
            },
            col_name: name.to_string().into(),
        }
    }

    fn meta_fixed(name: &str, ty: FixedLenType) -> MetaDataColumn<'static> {
        meta_type_flags(name, TypeInfo::FixedLen(ty), enumflags2::BitFlags::empty())
    }

    fn meta_var(
        name: &str,
        ty: VarLenType,
        len: usize,
        collation: Option<Collation>,
    ) -> MetaDataColumn<'static> {
        meta_var_flags(name, ty, len, collation, ColumnFlag::Nullable.into())
    }

    fn meta_var_flags(
        name: &str,
        ty: VarLenType,
        len: usize,
        collation: Option<Collation>,
        flags: enumflags2::BitFlags<ColumnFlag>,
    ) -> MetaDataColumn<'static> {
        let table_name = if matches!(ty, VarLenType::Text | VarLenType::NText | VarLenType::Image)
        {
            Some(vec!["dummy_table".into()])
        } else {
            None
        };
        MetaDataColumn {
            base: BaseMetaDataColumn {
                user_type: 0,
                flags,
                ty: TypeInfo::VarLenSized(VarLenContext::new(ty, len, collation)),
                table_name,
            },
            col_name: name.to_string().into(),
        }
    }

    fn numeric_len(precision: u8) -> usize {
        match precision {
            1..=9 => 5,
            10..=19 => 9,
            20..=28 => 13,
            _ => 17,
        }
    }

    fn meta_numeric(name: &str, precision: u8, scale: u8) -> MetaDataColumn<'static> {
        meta_type(
            name,
            TypeInfo::VarLenSizedPrecision {
                ty: VarLenType::Numericn,
                size: numeric_len(precision),
                precision,
                scale,
            },
        )
    }

    fn meta_decimal(name: &str, precision: u8, scale: u8) -> MetaDataColumn<'static> {
        meta_type(
            name,
            TypeInfo::VarLenSizedPrecision {
                ty: VarLenType::Decimaln,
                size: numeric_len(precision),
                precision,
                scale,
            },
        )
    }

    fn meta_numeric_legacy(name: &str, precision: u8, scale: u8) -> MetaDataColumn<'static> {
        meta_type(
            name,
            TypeInfo::VarLenSizedPrecision {
                ty: VarLenType::Numeric,
                size: numeric_len(precision),
                precision,
                scale,
            },
        )
    }

    fn meta_decimal_legacy(name: &str, precision: u8, scale: u8) -> MetaDataColumn<'static> {
        meta_type(
            name,
            TypeInfo::VarLenSizedPrecision {
                ty: VarLenType::Decimal,
                size: numeric_len(precision),
                precision,
                scale,
            },
        )
    }

    fn meta_udt(name: &str, max_len: u16) -> MetaDataColumn<'static> {
        meta_udt_named(name, max_len, "demo_udt", "demo_udt_assembly")
    }

    fn meta_udt_named(
        name: &str,
        max_len: u16,
        type_name: &str,
        assembly_name: &str,
    ) -> MetaDataColumn<'static> {
        meta_type(
            name,
            TypeInfo::Udt(UdtInfo {
                max_len,
                db_name: "dummy".into(),
                schema: "dbo".into(),
                type_name: type_name.into(),
                assembly_name: assembly_name.into(),
            }),
        )
    }

    fn meta_clr_udt(name: &str, max_len: u16, clr_type: &str) -> MetaDataColumn<'static> {
        let (sql_type, clr_type) = match clr_type {
            "geometry" => ("geometry", "Microsoft.SqlServer.Types.SqlGeometry"),
            "geography" => ("geography", "Microsoft.SqlServer.Types.SqlGeography"),
            "hierarchyid" => ("hierarchyid", "Microsoft.SqlServer.Types.SqlHierarchyId"),
            _ => (clr_type, clr_type),
        };
        let assembly_name = format!("{clr_type}, Microsoft.SqlServer.Types");
        meta_udt_named(name, max_len, sql_type, &assembly_name)
    }

    fn meta_variant(name: &str, max_len: u32) -> MetaDataColumn<'static> {
        meta_type(name, TypeInfo::SsVariant(SsVariantInfo { max_len }))
    }

    fn meta_xml(name: &str) -> MetaDataColumn<'static> {
        meta_type(
            name,
            TypeInfo::Xml {
                schema: None,
                size: 0xfffffffffffffffe,
            },
        )
    }

    fn param_value_to_string(value: &ColumnData<'_>) -> String {
        match value {
            ColumnData::U8(Some(v)) => v.to_string(),
            ColumnData::I16(Some(v)) => v.to_string(),
            ColumnData::I32(Some(v)) => v.to_string(),
            ColumnData::I64(Some(v)) => v.to_string(),
            ColumnData::F32(Some(v)) => v.to_string(),
            ColumnData::F64(Some(v)) => v.to_string(),
            ColumnData::Bit(Some(v)) => v.to_string(),
            ColumnData::String(Some(s)) => s.to_string(),
            ColumnData::Guid(Some(g)) => g.to_string(),
            ColumnData::Binary(Some(b)) => format!("{:?}", b),
            ColumnData::Numeric(Some(n)) => format!("{n}"),
            ColumnData::DateTime(Some(dt)) => format!("{dt:?}"),
            ColumnData::SmallDateTime(Some(dt)) => format!("{dt:?}"),
            ColumnData::Time(Some(time)) => format!("{time:?}"),
            ColumnData::Date(Some(date)) => format!("{date:?}"),
            ColumnData::DateTime2(Some(dt)) => format!("{dt:?}"),
            ColumnData::DateTimeOffset(Some(dt)) => format!("{dt:?}"),
            ColumnData::Xml(Some(xml)) => xml.as_ref().to_string(),
            ColumnData::Udt(Some(bytes)) => format!("{:?}", bytes),
            ColumnData::Variant(Some(variant)) => {
                format!("variant({} bytes)", variant.payload().len())
            }
            ColumnData::Tvp(Some(tvp)) => {
                format!("tvp(cols={}, rows={})", tvp.columns.len(), tvp.rows.len())
            }
            ColumnData::U8(None)
            | ColumnData::I16(None)
            | ColumnData::I32(None)
            | ColumnData::I64(None)
            | ColumnData::F32(None)
            | ColumnData::F64(None)
            | ColumnData::Bit(None)
            | ColumnData::String(None)
            | ColumnData::Guid(None)
            | ColumnData::Binary(None)
            | ColumnData::Numeric(None)
            | ColumnData::DateTime(None)
            | ColumnData::SmallDateTime(None)
            | ColumnData::Time(None)
            | ColumnData::Date(None)
            | ColumnData::DateTime2(None)
            | ColumnData::DateTimeOffset(None)
            | ColumnData::Xml(None)
            | ColumnData::Udt(None)
            | ColumnData::Variant(None)
            | ColumnData::Tvp(None) => "<null>".to_string(),
            _ => format!("{value:?}"),
        }
    }

    fn rpc_output_value(param: &DecodedRpcParam) -> ColumnData<'static> {
        match &param.ty {
            TypeInfo::FixedLen(FixedLenType::Int4) => ColumnData::I32(Some(4242)),
            TypeInfo::FixedLen(FixedLenType::Int8) => ColumnData::I64(Some(4242)),
            TypeInfo::VarLenSized(cx) if cx.r#type() == VarLenType::Intn && cx.len() <= 4 => {
                ColumnData::I32(Some(4242))
            }
            TypeInfo::VarLenSized(cx) if cx.r#type() == VarLenType::Intn && cx.len() == 8 => {
                ColumnData::I64(Some(4242))
            }
            TypeInfo::VarLenSized(cx) if cx.r#type() == VarLenType::Bitn => {
                ColumnData::Bit(Some(true))
            }
            TypeInfo::VarLenSized(cx) if cx.r#type() == VarLenType::NVarchar => {
                ColumnData::String(Some("out".into()))
            }
            _ => param.value.clone(),
        }
    }

    struct DummyHandlers {
        auth: DummyAuth,
        sql: DummySqlBatch,
        rpc: DummyRpc,
        bulk: DummyBulk,
        attention: DummyAttention,
        error: DummyErrorHandler,
    }

    impl DummyHandlers {
        fn new(encryption: EncryptionLevel) -> Self {
            Self {
                auth: DummyAuth::new(encryption),
                sql: DummySqlBatch,
                rpc: DummyRpc,
                bulk: DummyBulk,
                attention: DummyAttention,
                error: DummyErrorHandler,
            }
        }
    }

    impl TdsServerHandlers for DummyHandlers {
        type Auth = DummyAuth;
        type SqlBatch = DummySqlBatch;
        type Rpc = DummyRpc;
        type Bulk = DummyBulk;
        type Attention = DummyAttention;
        type Error = DummyErrorHandler;

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

    #[derive(Debug, Clone)]
    struct DummyEnvChangeProvider {
        inner: DefaultEnvChangeProvider,
        force_feature_ack: bool,
    }

    impl DummyEnvChangeProvider {
        fn new() -> Self {
            let force_feature_ack =
                std::env::var("TDS_DUMMY_FORCE_FEATURE_ACK").ok().as_deref() == Some("1");

            Self {
                inner: DefaultEnvChangeProvider::default(),
                force_feature_ack,
            }
        }
    }

    impl EnvChangeProvider for DummyEnvChangeProvider {
        fn login_ack(&self, login: &LoginMessage<'_>) -> TokenLoginAck {
            self.inner.login_ack(login)
        }

        fn env_changes<C>(&self, client: &C, login: &LoginMessage<'_>) -> Vec<TokenEnvChange>
        where
            C: TdsConnectionContext,
        {
            self.inner.env_changes(client, login)
        }

        fn feature_ext_ack(&self, login: &LoginMessage<'_>) -> Option<TokenFeatureExtAck> {
            if self.force_feature_ack && !login.has_feature_ext() {
                log_event("login: sending FeatureExtAck (forced)");
                return Some(TokenFeatureExtAck { features: Vec::new() });
            }

            let ack = self.inner.feature_ext_ack(login);
            if ack.is_some() {
                log_event("login: sending FeatureExtAck");
            }
            ack
        }

        fn fed_auth_info<C>(
            &self,
            _client: &C,
            login: &LoginMessage<'_>,
        ) -> Option<TokenFedAuthInfo>
        where
            C: TdsConnectionContext,
        {
            let force_fedauth =
                std::env::var("TDS_DUMMY_FORCE_FEDAUTH").ok().as_deref() == Some("1");
            let wants_fedauth = login.fed_auth_token().is_some() || login.fed_auth_nonce().is_some();

            if !force_fedauth && !wants_fedauth {
                return None;
            }

            if (login.tds_version() as u32) < TDS_VER_74 {
                log_event("login: skipping FedAuthInfo (tds<7.4)");
                return None;
            }

            log_event("login: sending FedAuthInfo");
            Some(TokenFedAuthInfo {
                options: vec![
                    FedAuthInfoOption::StsUrl("https://dummy".into()),
                    FedAuthInfoOption::Spn("MSSQLSvc/dummy:1433".into()),
                ],
            })
        }
    }

    #[derive(Debug)]
    struct DummySqlAuth {
        expected_user: Option<String>,
        expected_password: Option<String>,
    }

    impl DummySqlAuth {
        fn new() -> Self {
            Self {
                expected_user: std::env::var("TDS_DUMMY_SQL_USER").ok(),
                expected_password: std::env::var("TDS_DUMMY_SQL_PASSWORD").ok(),
            }
        }
    }

    #[async_trait]
    impl SqlAuthSource for DummySqlAuth {
        async fn authenticate(
            &self,
            login: &LoginInfo,
            password: &str,
        ) -> std::result::Result<AuthSuccess, AuthError> {
            if let Some(expected_user) = self.expected_user.as_deref() {
                if login.user() != Some(expected_user) {
                    return Err(AuthError::login_failed(login.user()));
                }
            }

            if let Some(expected_password) = self.expected_password.as_deref() {
                if password != expected_password {
                    return Err(AuthError::login_failed(login.user()));
                }
            }

            log_event(&format!(
                "auth: sql user={} password_len={}",
                login.user().unwrap_or("<none>"),
                password.len()
            ));
            Ok(AuthSuccess::default())
        }
    }

    #[derive(Debug, Default)]
    struct DummyFedAuth;

    #[async_trait]
    impl FedAuthValidator for DummyFedAuth {
        async fn validate(
            &self,
            login: &LoginInfo,
            token: &str,
        ) -> std::result::Result<AuthSuccess, AuthError> {
            log_event(&format!(
                "auth: fed user={} token_len={}",
                login.user().unwrap_or("<none>"),
                token.len()
            ));
            Ok(AuthSuccess::default())
        }
    }

    #[derive(Debug, Default)]
    struct DummySspi;

    impl SspiAcceptor for DummySspi {
        fn start(
            &self,
            login: &LoginInfo,
            token: &[u8],
        ) -> std::result::Result<SspiStart, AuthError> {
            log_event(&format!(
                "auth: sspi start user={} token_len={}",
                login.user().unwrap_or("<none>"),
                token.len()
            ));
            Ok(SspiStart {
                step: SspiStep {
                    response: Some(token.to_vec()),
                    complete: true,
                    session_user: login.user().map(|user| user.to_string()),
                },
                session: None,
            })
        }
    }

    struct DummyAuth {
        inner: TdsAuthHandler<DummyEnvChangeProvider>,
    }

    impl DummyAuth {
        fn new(encryption: EncryptionLevel) -> Self {
            let env_provider = DummyEnvChangeProvider::new();

            let mut builder = AuthBuilder::new(env_provider)
                .encryption(encryption)
                .with_sql_auth(Arc::new(DummySqlAuth::new()))
                .with_fed_auth(Arc::new(DummyFedAuth::default()))
                .with_sspi(Arc::new(DummySspi::default()));

            if std::env::var("TDS_DUMMY_ALLOW_TRUST").ok().as_deref() == Some("1") {
                builder = builder.allow_trust();
            }

            Self {
                inner: builder.build(),
            }
        }
    }

    impl AuthHandler for DummyAuth {
        fn on_prelogin<'a, C>(
            &'a self,
            client: &'a mut C,
            message: PreloginMessage,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>
        where
            C: TdsConnectionContext
                + futures_util::sink::Sink<TdsBackendMessage, Error = tiberius::error::Error>
                + Unpin
                + Send
                + 'a,
        {
            Box::pin(async move {
                log_event(&format!(
                    "prelogin from={} encryption={:?} mars={} fed_auth_required={} instance={}",
                    client.socket_addr(),
                    message.encryption,
                    message.mars,
                    message.fed_auth_required,
                    message.instance_name.as_deref().unwrap_or("<none>")
                ));
                self.inner.on_prelogin(client, message).await
            })
        }

        fn on_login<'a, C>(
            &'a self,
            client: &'a mut C,
            message: LoginMessage<'static>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>
        where
            C: TdsConnectionContext
                + futures_util::sink::Sink<TdsBackendMessage, Error = tiberius::error::Error>
                + Unpin
                + Send
                + 'a,
        {
            Box::pin(async move {
                let db_name = message.db_name_ref();
                let db_name = if db_name.is_empty() { "master" } else { db_name };

                log_event(&format!(
                    "login from={} user={} app={} db={} tds_version={:?} packet_size={}",
                    client.socket_addr(),
                    message.user_name_ref(),
                    message.app_name_ref(),
                    db_name,
                    message.tds_version(),
                    message.packet_size()
                ));
                log_event(&format!(
                    "login state: secure={} encryption={:?}",
                    client.is_secure(),
                    client.encryption()
                ));

                self.inner.on_login(client, message).await
            })
        }

        fn on_sspi<'a, C>(
            &'a self,
            client: &'a mut C,
            token: tiberius::TokenSspi,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>
        where
            C: TdsConnectionContext
                + futures_util::sink::Sink<TdsBackendMessage, Error = tiberius::error::Error>
                + Unpin
                + Send
                + 'a,
        {
            Box::pin(async move {
                log_event(&format!(
                    "sspi from={} token_len={}",
                    client.socket_addr(),
                    token.as_ref().len()
                ));
                self.inner.on_sspi(client, token).await
            })
        }
    }

    struct DummySqlBatch;

    impl SqlBatchHandler for DummySqlBatch {
        fn on_sql_batch<'a, C>(
            &'a self,
            client: &'a mut C,
            message: tiberius::server::SqlBatchMessage,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>
        where
            C: TdsConnectionContext
                + futures_util::sink::Sink<TdsBackendMessage, Error = tiberius::error::Error>
                + Unpin
                + Send
                + 'a,
        {
            Box::pin(async move {
                log_event(&format!(
                    "sql_batch from={} batch={:?} reset={} skip_tran={}",
                    client.socket_addr(),
                    message.batch,
                    message.request_flags.reset_connection,
                    message.request_flags.reset_connection_skip_tran,
                ));
                let lower = message.batch.to_ascii_lowercase();
                let collation = Some(Collation::new(13632521, 52));

                if lower.contains("tds_info") {
                    log_event("sql_batch: tds_info");
                    let info = TokenInfo::new(
                        5701,
                        0,
                        0,
                        "dummy info token",
                        "tiberius",
                        "tds_dummy",
                        1,
                    );
                    client
                        .send(TdsBackendMessage::Token(tiberius::server::BackendToken::Info(
                            info,
                        )))
                        .await?;
                }

                if lower.contains("tds_multi") {
                    log_event("sql_batch: tds_multi");
                    let columns = vec![
                        meta_fixed("id", FixedLenType::Int4),
                        meta_var("label", VarLenType::NVarchar, 200, collation),
                    ];
                    let mut writer = ResultSetWriter::start(client, columns).await?;
                    writer
                        .send_batch_rows(2, |row, col| match (row, col) {
                            (0, 0) => ColumnData::I32(Some(1)),
                            (0, 1) => ColumnData::String(Some("alpha".into())),
                            (1, 0) => ColumnData::I32(Some(2)),
                            (1, 1) => ColumnData::String(Some("beta".into())),
                            _ => ColumnData::I32(None),
                        })
                        .await?;
                    writer.finish_more(2).await?;

                    let columns = vec![
                        meta_fixed("code", FixedLenType::Int4),
                        meta_var("note", VarLenType::NVarchar, 200, collation),
                    ];
                    let mut writer = ResultSetWriter::start(client, columns).await?;
                    writer
                        .send_row_iter([ColumnData::I32(Some(100)), ColumnData::String(Some(
                            "gamma".into(),
                        ))])
                        .await?;
                    writer.finish(1).await?;
                    return Ok(());
                }

                if lower.contains("tds_types") {
                    log_event("sql_batch: tds_types");
                    let num0 = Numeric::new_with_scale(12345, 2);
                    let dec0 = Numeric::new_with_scale(9876, 2);
                    let guid0 = Uuid::from_u128(1);
                    let dt0 = DateTime::new(0, 0);
                    let dt1 = DateTime::new(10, 600);
                    let sdt0 = SmallDateTime::new(1, 300);
                    let sdt1 = SmallDateTime::new(2, 450);
                    let date0 = Date::new(20000);
                    let time0 = Time::new(123456, 7);
                    let dt2_0 = DateTime2::new(date0, time0);
                    let dto0 = DateTimeOffset::new(dt2_0, -8);
                    let legacy_env =
                        std::env::var("TDS_DUMMY_INCLUDE_LEGACY").ok().as_deref() == Some("1");
                    let force_legacy =
                        std::env::var("TDS_DUMMY_FORCE_LEGACY").ok().as_deref() == Some("1");
                    let legacy_allowed = (client.tds_version() as u32) < TDS_VER_70;
                    let include_legacy = force_legacy || (legacy_env && legacy_allowed);
                    if legacy_env && !legacy_allowed && !force_legacy {
                        log_event("tds_types: legacy types suppressed for tds>=7");
                    }

                    let mut columns = vec![
                        meta_fixed("tinyint_col", FixedLenType::Int1),
                        meta_fixed("smallint_col", FixedLenType::Int2),
                        meta_fixed("int_col", FixedLenType::Int4),
                        meta_fixed("bigint_col", FixedLenType::Int8),
                        meta_var("intn_col", VarLenType::Intn, 4, None),
                        meta_var("intn1_col", VarLenType::Intn, 1, None),
                        meta_var("intn2_col", VarLenType::Intn, 2, None),
                        meta_var("intn8_col", VarLenType::Intn, 8, None),
                        meta_fixed("real_col", FixedLenType::Float4),
                        meta_fixed("float_col", FixedLenType::Float8),
                        meta_var("floatn_col", VarLenType::Floatn, 8, None),
                        meta_var("floatn4_col", VarLenType::Floatn, 4, None),
                        meta_fixed("bit_col", FixedLenType::Bit),
                        meta_var("bitn_col", VarLenType::Bitn, 1, None),
                        meta_fixed("money_col", FixedLenType::Money),
                        meta_fixed("smallmoney_col", FixedLenType::Money4),
                        meta_var("money_var_col", VarLenType::Money, 8, None),
                        meta_var("money_var4_col", VarLenType::Money, 4, None),
                        meta_fixed("datetime_col", FixedLenType::Datetime),
                        meta_fixed("smalldatetime_col", FixedLenType::Datetime4),
                        meta_var("datetimen_col", VarLenType::Datetimen, 8, None),
                        meta_var("datetimen4_col", VarLenType::Datetimen, 4, None),
                        meta_var("date_col", VarLenType::Daten, 3, None),
                        meta_var("time_col", VarLenType::Timen, 7, None),
                        meta_var("datetime2_col", VarLenType::Datetime2, 7, None),
                        meta_var("datetimeoffset_col", VarLenType::DatetimeOffsetn, 7, None),
                        meta_var("nvarchar_col", VarLenType::NVarchar, 200, collation),
                        meta_var("nchar_col", VarLenType::NChar, 40, collation),
                        meta_var("nvarchar_max_col", VarLenType::NVarchar, 0xffff, collation),
                        meta_var("varchar_col", VarLenType::BigVarChar, 200, collation),
                        meta_var("char_col", VarLenType::BigChar, 40, collation),
                        meta_var("varchar_max_col", VarLenType::BigVarChar, 0xffff, collation),
                        meta_var("varbinary_col", VarLenType::BigVarBin, 32, None),
                        meta_var("binary_col", VarLenType::BigBinary, 32, None),
                        meta_var("varbinary_max_col", VarLenType::BigVarBin, 0xffff, None),
                        meta_var("guid_col", VarLenType::Guid, 16, None),
                        meta_numeric("numeric_col", num0.precision(), num0.scale()),
                        meta_decimal("decimal_col", dec0.precision(), dec0.scale()),
                    ];

                    if include_legacy {
                        columns.push(meta_var(
                            "varchar_legacy_col",
                            VarLenType::VarChar,
                            120,
                            collation,
                        ));
                        columns.push(meta_var("char_legacy_col", VarLenType::Char, 10, collation));
                        columns.push(meta_var(
                            "varbinary_legacy_col",
                            VarLenType::VarBinary,
                            16,
                            None,
                        ));
                        columns.push(meta_var(
                            "binary_legacy_col",
                            VarLenType::Binary,
                            16,
                            None,
                        ));

                        let num1 = Numeric::new_with_scale(1234, 1);
                        let dec1 = Numeric::new_with_scale(5678, 2);
                        columns.push(meta_numeric_legacy(
                            "numeric_legacy_col",
                            num1.precision(),
                            num1.scale(),
                        ));
                        columns.push(meta_decimal_legacy(
                            "decimal_legacy_col",
                            dec1.precision(),
                            dec1.scale(),
                        ));
                    }

                    let mut writer = ResultSetWriter::start(client, columns).await?;
                    let mut row = vec![
                        ColumnData::U8(Some(1)),
                        ColumnData::I16(Some(2)),
                        ColumnData::I32(Some(42)),
                        ColumnData::I64(Some(9001)),
                        ColumnData::I32(Some(314)),
                        ColumnData::U8(Some(7)),
                        ColumnData::I16(Some(1234)),
                        ColumnData::I64(Some(123456789012)),
                        ColumnData::F32(Some(3.5)),
                        ColumnData::F64(Some(3.14159)),
                        ColumnData::F64(Some(2.71828)),
                        ColumnData::F32(Some(6.25)),
                        ColumnData::Bit(Some(true)),
                        ColumnData::Bit(Some(false)),
                        ColumnData::F64(Some(12.34)),
                        ColumnData::F64(Some(5.67)),
                        ColumnData::F64(Some(99.99)),
                        ColumnData::F64(Some(1.23)),
                        ColumnData::DateTime(Some(dt0)),
                        ColumnData::SmallDateTime(Some(sdt0)),
                        ColumnData::DateTime(Some(dt1)),
                        ColumnData::SmallDateTime(Some(sdt1)),
                        ColumnData::Date(Some(date0)),
                        ColumnData::Time(Some(time0)),
                        ColumnData::DateTime2(Some(dt2_0)),
                        ColumnData::DateTimeOffset(Some(dto0)),
                        ColumnData::String(Some("hello".into())),
                        ColumnData::String(Some("hi".into())),
                        ColumnData::String(Some("nv-max".into())),
                        ColumnData::String(Some("ascii".into())),
                        ColumnData::String(Some("ch".into())),
                        ColumnData::String(Some("v-max".into())),
                        ColumnData::Binary(Some(vec![1, 2, 3].into())),
                        ColumnData::Binary(Some(vec![4, 5, 6].into())),
                        ColumnData::Binary(Some(vec![10, 11, 12].into())),
                        ColumnData::Guid(Some(guid0)),
                        ColumnData::Numeric(Some(num0)),
                        ColumnData::Numeric(Some(dec0)),
                    ];

                    if include_legacy {
                        let num1 = Numeric::new_with_scale(1234, 1);
                        let dec1 = Numeric::new_with_scale(5678, 2);
                        row.push(ColumnData::String(Some("legacy-v".into())));
                        row.push(ColumnData::String(Some("lc".into())));
                        row.push(ColumnData::Binary(Some(vec![13, 14].into())));
                        row.push(ColumnData::Binary(Some(vec![15, 16].into())));
                        row.push(ColumnData::Numeric(Some(num1)));
                        row.push(ColumnData::Numeric(Some(dec1)));
                    }

                    writer.send_row_iter(row).await?;
                    writer.finish(1).await?;
                    return Ok(());
                }

                if lower.contains("tds_metadata") {
                    log_event("sql_batch: tds_metadata");
                    let collation = Some(Collation::new(13632521, 52));
                    let num0 = Numeric::new_with_scale(1234567000, 3);
                    let dec0 = Numeric::new_with_scale(987650, 2);
                    let table_name = Some(vec![
                        "dummy_db".to_string(),
                        "dbo".to_string(),
                        "dummy_table".to_string(),
                    ]);
                    log_event("tds_metadata: table_name=dummy_db.dbo.dummy_table");
                    let columns = vec![
                        meta_type_flags_table(
                            "identity_col",
                            TypeInfo::FixedLen(FixedLenType::Int4),
                            (ColumnFlag::Identity | ColumnFlag::Updateable).into(),
                            table_name.clone(),
                        ),
                        meta_type_flags(
                            "hidden_col",
                            TypeInfo::FixedLen(FixedLenType::Int4),
                            ColumnFlag::Hidden.into(),
                        ),
                        meta_var_flags(
                            "nullable_col",
                            VarLenType::Intn,
                            4,
                            None,
                            ColumnFlag::Nullable.into(),
                        ),
                        meta_type_flags_table(
                            "varchar_cp_col",
                            TypeInfo::VarLenSized(VarLenContext::new(
                                VarLenType::BigVarChar,
                                200,
                                collation,
                            )),
                            ColumnFlag::Nullable.into(),
                            table_name.clone(),
                        ),
                        meta_type_flags(
                            "numeric_prec_col",
                            TypeInfo::VarLenSizedPrecision {
                                ty: VarLenType::Numericn,
                                size: numeric_len(num0.precision()),
                                precision: num0.precision(),
                                scale: num0.scale(),
                            },
                            ColumnFlag::Nullable.into(),
                        ),
                        meta_type_flags(
                            "decimal_prec_col",
                            TypeInfo::VarLenSizedPrecision {
                                ty: VarLenType::Decimaln,
                                size: numeric_len(dec0.precision()),
                                precision: dec0.precision(),
                                scale: dec0.scale(),
                            },
                            ColumnFlag::Nullable.into(),
                        ),
                    ];

                    let mut writer = ResultSetWriter::start(client, columns).await?;
                    writer
                        .send_row_iter([
                            ColumnData::I32(Some(1)),
                            ColumnData::I32(Some(2)),
                            ColumnData::I32(None),
                            ColumnData::String(Some("caf\u{00e9}".into())),
                            ColumnData::Numeric(Some(num0)),
                            ColumnData::Numeric(Some(dec0)),
                        ])
                        .await?;
                    writer.finish(1).await?;
                    return Ok(());
                }

                if lower.contains("tds_varlen") {
                    log_event("sql_batch: tds_varlen");
                    let legacy_env =
                        std::env::var("TDS_DUMMY_INCLUDE_LEGACY").ok().as_deref() == Some("1");
                    let force_legacy =
                        std::env::var("TDS_DUMMY_FORCE_LEGACY").ok().as_deref() == Some("1");
                    let legacy_allowed = (client.tds_version() as u32) < TDS_VER_70;
                    let include_legacy = force_legacy || (legacy_env && legacy_allowed);
                    if legacy_env && !legacy_allowed && !force_legacy {
                        log_event("tds_varlen: legacy char/varchar suppressed for tds>=7");
                    }

                    let mut columns = vec![
                        meta_var("varchar_big_col", VarLenType::BigVarChar, 50, collation),
                        meta_var("char_big_col", VarLenType::BigChar, 20, collation),
                    ];
                    if include_legacy {
                        columns.push(meta_var("varchar_short_col", VarLenType::VarChar, 50, collation));
                        columns.push(meta_var("char_short_col", VarLenType::Char, 20, collation));
                    }
                    let mut writer = ResultSetWriter::start(client, columns).await?;
                    let mut row = vec![
                        ColumnData::String(Some("caf\u{00e9}".into())),
                        ColumnData::String(Some("caf\u{00e9}".into())),
                    ];
                    if include_legacy {
                        row.push(ColumnData::String(Some("caf\u{00e9}".into())));
                        row.push(ColumnData::String(Some("caf\u{00e9}".into())));
                    }
                    writer.send_row_iter(row).await?;
                    writer.finish(1).await?;
                    return Ok(());
                }

                if lower.contains("tds_variant") {
                    log_event("sql_batch: tds_variant");
                    let num0 = Numeric::new_with_scale(12345, 2);
                    let variant_int = VariantData::from_typed(
                        TypeInfo::FixedLen(FixedLenType::Int4),
                        ColumnData::I32(Some(42)),
                    )?;
                    let variant_numeric = VariantData::from_typed(
                        TypeInfo::VarLenSizedPrecision {
                            ty: VarLenType::Numericn,
                            size: numeric_len(num0.precision()),
                            precision: num0.precision(),
                            scale: num0.scale(),
                        },
                        ColumnData::Numeric(Some(num0)),
                    )?;
                    let variant_varchar = VariantData::from_typed(
                        TypeInfo::VarLenSized(VarLenContext::new(
                            VarLenType::BigVarChar,
                            50,
                            collation,
                        )),
                        ColumnData::String(Some("variant".into())),
                    )?;
                    let columns = vec![
                        meta_variant("variant_int", 8016),
                        meta_variant("variant_numeric", 8016),
                        meta_variant("variant_varchar", 8016),
                        meta_variant("variant_null", 8016),
                    ];
                    let mut writer = ResultSetWriter::start(client, columns).await?;
                    writer
                        .send_row_iter([
                            ColumnData::Variant(Some(variant_int)),
                            ColumnData::Variant(Some(variant_numeric)),
                            ColumnData::Variant(Some(variant_varchar)),
                            ColumnData::Variant(None),
                        ])
                        .await?;
                    writer.finish(1).await?;
                    return Ok(());
                }

                if lower.contains("tds_tvp") {
                    log_event("sql_batch: tds_tvp");
                    let tvp_columns = vec![
                        TvpColumn {
                            name: "tvp_id".into(),
                            user_type: 0,
                            flags: ColumnFlag::Nullable.into(),
                            ty: TypeInfo::FixedLen(FixedLenType::Int4),
                        },
                        TvpColumn {
                            name: "tvp_label".into(),
                            user_type: 0,
                            flags: ColumnFlag::Nullable.into(),
                            ty: TypeInfo::VarLenSized(VarLenContext::new(
                                VarLenType::NVarchar,
                                50,
                                collation,
                            )),
                        },
                    ];
                    let tvp_rows = vec![
                        vec![
                            ColumnData::I32(Some(1)),
                            ColumnData::String(Some("alpha".into())),
                        ],
                        vec![
                            ColumnData::I32(Some(2)),
                            ColumnData::String(Some("beta".into())),
                        ],
                    ];
                    let tvp = TvpData::new("demo_tvp")
                        .schema("dbo")
                        .columns(tvp_columns)
                        .rows(tvp_rows);
                    let columns = vec![meta_type(
                        "tvp_col",
                        TypeInfo::Tvp(TvpInfo {
                            db_name: "dummy".into(),
                            schema: "dbo".into(),
                            type_name: "demo_tvp".into(),
                        }),
                    )];
                    let mut writer = ResultSetWriter::start(client, columns).await?;
                    writer
                        .send_row_iter([ColumnData::Tvp(Some(tvp))])
                        .await?;
                    writer.finish(1).await?;
                    return Ok(());
                }

                if lower.contains("tds_columnar") {
                    log_event("sql_batch: tds_columnar");
                    log_event("tds_columnar: send_row_values");
                    let payload = [0x01, 0x02, 0x03, 0x04];
                    let columns = vec![
                        meta_fixed("id", FixedLenType::Int4),
                        meta_var("label", VarLenType::NVarchar, 200, collation),
                        meta_var("payload", VarLenType::BigVarBin, 32, None),
                    ];
                    let mut writer = ResultSetWriter::start(client, columns).await?;
                    writer
                        .send_row_values([
                            ColumnData::I32(Some(101)),
                            ColumnData::String(Some(Cow::Borrowed("columnar"))),
                            ColumnData::Binary(Some(Cow::Borrowed(payload.as_slice()))),
                        ])
                        .await?;
                    writer.finish(1).await?;
                    return Ok(());
                }

                if lower.contains("tds_exotic") {
                    log_event("sql_batch: tds_exotic");
                    let variant_payload = VariantData::from_typed(
                        TypeInfo::FixedLen(FixedLenType::Int4),
                        ColumnData::I32(Some(42)),
                    )?;
                    let columns = vec![
                        meta_clr_udt("geometry_col", 0xffff, "geometry"),
                        meta_clr_udt("geography_col", 0xffff, "geography"),
                        meta_clr_udt("hierarchyid_col", 0xffff, "hierarchyid"),
                        meta_variant("variant_col", 8016),
                    ];
                    let mut writer = ResultSetWriter::start(client, columns).await?;
                    writer
                        .send_row_iter([
                            ColumnData::Udt(None),
                            ColumnData::Udt(None),
                            ColumnData::Udt(None),
                            ColumnData::Variant(Some(variant_payload)),
                        ])
                        .await?;
                    writer.finish(1).await?;
                    return Ok(());
                }

                if lower.contains("tds_lob_stream") {
                    log_event("sql_batch: tds_lob_stream");
                    let xml0 = XmlData::new("<stream>1</stream>");
                    let big_text = format!("stream-text-{}", "x".repeat(8192));
                    let big_ntext = format!("stream-ntext-{}", "y".repeat(8192));
                    let big_image = vec![0x5a; 16384];
                    let columns = vec![
                        meta_var("text_col", VarLenType::Text, 0x7fff_ffff, collation),
                        meta_var("ntext_col", VarLenType::NText, 0x7fff_ffff, collation),
                        meta_var("image_col", VarLenType::Image, 0x7fff_ffff, None),
                        meta_xml("xml_col"),
                    ];
                    let mut writer = ResultSetWriter::start(client, columns).await?;
                    log_event("tds_lob_stream: chunked writes");
                    writer
                        .send_row_values_chunked(
                            [
                                ColumnData::String(Some(big_text.into())),
                                ColumnData::String(Some(big_ntext.into())),
                                ColumnData::Binary(Some(big_image.into())),
                                ColumnData::Xml(Some(Cow::Owned(xml0))),
                            ],
                            512,
                        )
                        .await?;
                    writer.finish(1).await?;
                    return Ok(());
                }

                if lower.contains("tds_lob") {
                    log_event("sql_batch: tds_lob");
                    let xml0 = XmlData::new("<a>1</a>");
                    let columns = vec![
                        meta_var("text_col", VarLenType::Text, 0x7fff_ffff, collation),
                        meta_var("ntext_col", VarLenType::NText, 0x7fff_ffff, collation),
                        meta_var("image_col", VarLenType::Image, 0x7fff_ffff, None),
                        meta_xml("xml_col"),
                    ];
                    let mut writer = ResultSetWriter::start(client, columns).await?;
                    writer
                        .send_row_iter([
                            ColumnData::String(Some("text".into())),
                            ColumnData::String(Some("ntext".into())),
                            ColumnData::Binary(Some(vec![7, 8, 9].into())),
                            ColumnData::Xml(Some(Cow::Owned(xml0))),
                        ])
                        .await?;
                    writer.finish(1).await?;
                    return Ok(());
                }

                if lower.contains("tds_nulls") {
                    log_event("sql_batch: tds_nulls");
                    let num = Numeric::new_with_scale(0, 2);
                    let columns = vec![
                        meta_var("int_null", VarLenType::Intn, 4, None),
                        meta_var("bit_null", VarLenType::Bitn, 1, None),
                        meta_var("float_null", VarLenType::Floatn, 8, None),
                        meta_var("nvarchar_null", VarLenType::NVarchar, 200, collation),
                        meta_var("binary_null", VarLenType::BigVarBin, 32, None),
                        meta_numeric("numeric_null", num.precision(), num.scale()),
                    ];
                    let mut writer = ResultSetWriter::start(client, columns).await?;
                    writer
                        .send_row_iter_nbc([
                            ColumnData::I32(None),
                            ColumnData::Bit(None),
                            ColumnData::F64(None),
                            ColumnData::String(None),
                            ColumnData::Binary(None),
                            ColumnData::Numeric(None),
                        ])
                        .await?;
                    writer.finish(1).await?;
                    return Ok(());
                }

                if lower.contains("tds_tokens_extra") {
                    log_event("sql_batch: tds_tokens_extra");
                    let columns = vec![meta_fixed("value", FixedLenType::Int4)];
                    let col_meta = TokenColMetaData {
                        columns: columns.clone(),
                    };
                    client
                        .send(TdsBackendMessage::Token(tiberius::server::BackendToken::ColMetaData(
                            col_meta,
                        )))
                        .await?;

                    let force_colname = std::env::var("TDS_DUMMY_FORCE_COLNAME")
                        .ok()
                        .as_deref()
                        == Some("1");
                    let legacy_colname = (client.tds_version() as u32) < TDS_VER_70;
                    if force_colname || legacy_colname {
                        client
                            .send(TdsBackendMessage::Token(
                                tiberius::server::BackendToken::ColName(TokenColName {
                                    names: vec!["value".into()],
                                }),
                            ))
                            .await?;
                    } else {
                        log_event("tds_tokens_extra: skipping colname token (tds>=7)");
                    }

                    client
                        .send(TdsBackendMessage::Token(tiberius::server::BackendToken::TabName(
                            TokenTabName {
                                tables: vec![vec!["dummy_table".into()]],
                            },
                        )))
                        .await?;

                    let mut colinfo = BytesMut::with_capacity(3);
                    colinfo.put_u8(1); // col #1
                    colinfo.put_u8(0); // table #0 (expression)
                    colinfo.put_u8(0x04); // EXPRESSION status
                    client
                        .send(TdsBackendMessage::Token(tiberius::server::BackendToken::ColInfo(
                            TokenColInfo { data: colinfo },
                        )))
                        .await?;

                    client
                        .send(TdsBackendMessage::Token(tiberius::server::BackendToken::Order(
                            TokenOrder::new(vec![1]),
                        )))
                        .await?;

                    let mut row = TokenRow::with_capacity(1);
                    row.push(ColumnData::I32(Some(66)));
                    client
                        .send(TdsBackendMessage::Token(tiberius::server::BackendToken::Row(row)))
                        .await?;

                    client
                        .send(TdsBackendMessage::Token(tiberius::server::BackendToken::Done(
                            TokenDone::with_rows(1),
                        )))
                        .await?;
                    return Ok(());
                }

                if lower.contains("tds_compute") {
                    log_event("sql_batch: tds_compute");
                    let columns = vec![meta_fixed("value", FixedLenType::Int4)];
                    let col_meta = TokenColMetaData {
                        columns: columns.clone(),
                    };
                    client
                        .send(TdsBackendMessage::Token(tiberius::server::BackendToken::ColMetaData(
                            col_meta,
                        )))
                        .await?;

                    let alt_column = meta_fixed("alt_value", FixedLenType::Int4);
                    let alt_meta = TokenAltMetaData {
                        id: 1,
                        by_cols: Vec::new(),
                        columns: vec![AltMetaDataColumn {
                            operator: 1,
                            operand: 1,
                            column: alt_column,
                        }],
                    };
                    log_event("tds_compute: sending alt metadata");
                    client
                        .send(TdsBackendMessage::Token(
                            tiberius::server::BackendToken::AltMetaData(alt_meta),
                        ))
                        .await?;

                    let mut row = TokenRow::with_capacity(1);
                    row.push(ColumnData::I32(Some(10)));
                    client
                        .send(TdsBackendMessage::Token(tiberius::server::BackendToken::Row(row)))
                        .await?;

                    let mut alt_row = TokenAltRow::with_capacity(1, 1);
                    alt_row.push(ColumnData::I32(Some(20)));
                    log_event("tds_compute: sending alt row");
                    client
                        .send(TdsBackendMessage::Token(
                            tiberius::server::BackendToken::AltRow(alt_row),
                        ))
                        .await?;

                    client
                        .send(TdsBackendMessage::Token(tiberius::server::BackendToken::Done(
                            TokenDone::with_rows(1),
                        )))
                        .await?;
                    return Ok(());
                }

                if lower.contains("tds_session_state") {
                    log_event("sql_batch: tds_session_state");
                    let session_state = TokenSessionState {
                        sequence_number: 1,
                        status: 0,
                        entries: vec![SessionStateEntry {
                            id: 1,
                            data: vec![1, 2, 3],
                        }],
                    };
                    client
                        .send(TdsBackendMessage::Token(
                            tiberius::server::BackendToken::SessionState(session_state),
                        ))
                        .await?;
                    client
                        .send(TdsBackendMessage::Token(tiberius::server::BackendToken::Done(
                            TokenDone::default(),
                        )))
                        .await?;
                    return Ok(());
                }

                if lower.contains("tds_fedauth") {
                    log_event("sql_batch: tds_fedauth");
                    log_event("tds_fedauth: FedAuthInfo is login-only; skipping in batch");
                    client
                        .send(TdsBackendMessage::Token(tiberius::server::BackendToken::Done(
                            TokenDone::default(),
                        )))
                        .await?;
                    return Ok(());
                }

                if lower.contains("tds_tokens") {
                    log_event("sql_batch: tds_tokens");
                    let columns = vec![meta_fixed("value", FixedLenType::Int4)];
                    let col_meta = TokenColMetaData {
                        columns: columns.clone(),
                    };
                    client
                        .send(TdsBackendMessage::Token(tiberius::server::BackendToken::ColMetaData(
                            col_meta,
                        )))
                        .await?;

                    client
                        .send(TdsBackendMessage::Token(tiberius::server::BackendToken::TabName(
                            TokenTabName {
                                tables: vec![vec!["dummy_table".into()]],
                            },
                        )))
                        .await?;

                    let mut colinfo = BytesMut::with_capacity(3);
                    colinfo.put_u8(1); // col #1
                    colinfo.put_u8(1); // table #1
                    colinfo.put_u8(0x00); // no flags
                    client
                        .send(TdsBackendMessage::Token(tiberius::server::BackendToken::ColInfo(
                            TokenColInfo { data: colinfo },
                        )))
                        .await?;

                    client
                        .send(TdsBackendMessage::Token(tiberius::server::BackendToken::Order(
                            TokenOrder::new(vec![1]),
                        )))
                        .await?;

                    let mut row = TokenRow::with_capacity(1);
                    row.push(ColumnData::I32(Some(55)));
                    client
                        .send(TdsBackendMessage::Token(tiberius::server::BackendToken::Row(row)))
                        .await?;
                    client
                        .send(TdsBackendMessage::Token(tiberius::server::BackendToken::Done(
                            TokenDone::with_rows(1),
                        )))
                        .await?;
                    return Ok(());
                }

                if lower.contains("tds_envchange_full") {
                    log_event("sql_batch: tds_envchange_full");
                    let tx_desc = [1u8, 2, 3, 4, 5, 6, 7, 8];
                    let tx_desc_old = vec![8u8, 7, 6, 5, 4, 3, 2, 1];
                    let tx_desc_new = vec![1u8, 1, 1, 1, 1, 1, 1, 1];
                    let collation_old = Some(Collation::new(13632521, 52));
                    let collation_new = Some(Collation::new(13632521, 53));

                    let mut tokens = vec![
                        tiberius::server::BackendToken::EnvChange(TokenEnvChange::Database(
                            "dummy_db".into(),
                            "master".into(),
                        )),
                        tiberius::server::BackendToken::EnvChange(TokenEnvChange::Language(
                            "us_english".into(),
                            "en".into(),
                        )),
                        tiberius::server::BackendToken::EnvChange(TokenEnvChange::CharacterSet(
                            "utf-8".into(),
                            "iso-8859-1".into(),
                        )),
                        tiberius::server::BackendToken::EnvChange(TokenEnvChange::PacketSize(
                            8192,
                            4096,
                        )),
                        tiberius::server::BackendToken::EnvChange(
                            TokenEnvChange::UnicodeDataSortingLID(
                                "0x0409".into(),
                                "0x0000".into(),
                            ),
                        ),
                        tiberius::server::BackendToken::EnvChange(
                            TokenEnvChange::UnicodeDataSortingCFL(
                                "0x0001".into(),
                                "0x0000".into(),
                            ),
                        ),
                        tiberius::server::BackendToken::EnvChange(TokenEnvChange::SqlCollation {
                            old: collation_old,
                            new: collation_new,
                        }),
                        tiberius::server::BackendToken::EnvChange(
                            TokenEnvChange::BeginTransaction(tx_desc),
                        ),
                        tiberius::server::BackendToken::EnvChange(
                            TokenEnvChange::EnlistDtcTransaction(tx_desc),
                        ),
                        tiberius::server::BackendToken::EnvChange(
                            TokenEnvChange::CommitTransaction {
                                new: tx_desc_new.clone(),
                                old: tx_desc_old.clone(),
                            },
                        ),
                        tiberius::server::BackendToken::EnvChange(
                            TokenEnvChange::RollbackTransaction {
                                new: tx_desc_new.clone(),
                                old: tx_desc_old.clone(),
                            },
                        ),
                        tiberius::server::BackendToken::EnvChange(
                            TokenEnvChange::DefectTransaction {
                                new: tx_desc_new.clone(),
                                old: tx_desc_old.clone(),
                            },
                        ),
                        tiberius::server::BackendToken::EnvChange(
                            TokenEnvChange::PromoteTransaction {
                                old: tx_desc_old.clone(),
                                dtc: tx_desc_new.clone(),
                            },
                        ),
                        tiberius::server::BackendToken::EnvChange(
                            TokenEnvChange::TransactionManagerAddress {
                                old: vec![1, 2, 3, 4],
                                address: vec![5, 6, 7, 8],
                            },
                        ),
                        tiberius::server::BackendToken::EnvChange(
                            TokenEnvChange::TransactionEnded {
                                old: tx_desc_old.clone(),
                                new: tx_desc_new.clone(),
                            },
                        ),
                        tiberius::server::BackendToken::EnvChange(
                            TokenEnvChange::ResetConnection,
                        ),
                        tiberius::server::BackendToken::EnvChange(TokenEnvChange::UserName(
                            "dummy_user".into(),
                            "old_user".into(),
                        )),
                    ];

                    if std::env::var("TDS_DUMMY_FORCE_MIRROR").ok().as_deref() == Some("1") {
                        tokens.push(tiberius::server::BackendToken::EnvChange(
                            TokenEnvChange::ChangeMirror("dummy-mirror".into()),
                        ));
                    }

                    if std::env::var("TDS_DUMMY_FORCE_ROUTING").ok().as_deref() == Some("1") {
                        tokens.push(tiberius::server::BackendToken::EnvChange(
                            TokenEnvChange::Routing {
                                host: "dummy-host".into(),
                                port: 1433,
                            },
                        ));
                    }

                    tokens.push(tiberius::server::BackendToken::Done(TokenDone::default()));
                    client.send(TdsBackendMessage::Tokens(tokens)).await?;
                    return Ok(());
                }

                if lower.contains("tds_envchange") {
                    log_event("sql_batch: tds_envchange");
                    let tx_desc = [1u8, 2, 3, 4, 5, 6, 7, 8];
                    let tx_desc_old = tx_desc.to_vec();
                    let tx_desc_new = vec![0u8; 8];
                    let mut tokens = vec![
                        tiberius::server::BackendToken::EnvChange(
                            TokenEnvChange::BeginTransaction(tx_desc),
                        ),
                        tiberius::server::BackendToken::EnvChange(
                            TokenEnvChange::CommitTransaction {
                                new: tx_desc_new.clone(),
                                old: tx_desc_old.clone(),
                            },
                        ),
                        tiberius::server::BackendToken::EnvChange(
                            TokenEnvChange::RollbackTransaction {
                                new: tx_desc_new.clone(),
                                old: tx_desc_old.clone(),
                            },
                        ),
                        tiberius::server::BackendToken::EnvChange(
                            TokenEnvChange::DefectTransaction {
                                new: tx_desc_new.clone(),
                                old: tx_desc_old.clone(),
                            },
                        ),
                    ];

                    if std::env::var("TDS_DUMMY_FORCE_MIRROR").ok().as_deref() == Some("1") {
                        tokens.push(tiberius::server::BackendToken::EnvChange(
                            TokenEnvChange::ChangeMirror("dummy-mirror".into()),
                        ));
                    }

                    if std::env::var("TDS_DUMMY_FORCE_ROUTING").ok().as_deref() == Some("1") {
                        tokens.push(tiberius::server::BackendToken::EnvChange(
                            TokenEnvChange::Routing {
                                host: "dummy-host".into(),
                                port: 1433,
                            },
                        ));
                    }

                    tokens.push(tiberius::server::BackendToken::Done(TokenDone::default()));
                    client.send(TdsBackendMessage::Tokens(tokens)).await?;
                    return Ok(());
                }

                if lower.contains("tds_begin") {
                    log_event("sql_batch: tds_begin");
                    let tx_desc = [9u8, 8, 7, 6, 5, 4, 3, 2];
                    let tokens = vec![
                        tiberius::server::BackendToken::EnvChange(
                            TokenEnvChange::BeginTransaction(tx_desc),
                        ),
                        tiberius::server::BackendToken::Done(TokenDone::default()),
                    ];
                    client.send(TdsBackendMessage::Tokens(tokens)).await?;
                    return Ok(());
                }

                if lower.contains("tds_headers") {
                    log_event("sql_batch: tds_headers");
                    let headers = client.last_request_headers();
                    let tx_desc = headers
                        .transaction_descriptor
                        .as_ref()
                        .map(|tx| format!("{:02x?}", tx.descriptor))
                        .unwrap_or_else(|| "<none>".to_string());
                    let query_len = headers
                        .query_descriptor
                        .as_ref()
                        .map(|value| value.len())
                        .unwrap_or(0);
                    let trace_present = headers.trace_activity.is_some();
                    let unknown = headers.unknown.len();
                    log_event(&format!(
                        "tds_headers: tx_desc={} query_desc_len={} trace={} unknown={} reset={} skip_tran={}",
                        tx_desc,
                        query_len,
                        trace_present,
                        unknown,
                        message.request_flags.reset_connection,
                        message.request_flags.reset_connection_skip_tran
                    ));

                    let columns = vec![meta_fixed("value", FixedLenType::Int4)];
                    let mut writer = ResultSetWriter::start(client, columns).await?;
                    writer.send_row_iter([ColumnData::I32(Some(2))]).await?;
                    writer.finish(1).await?;
                    return Ok(());
                }

                if lower.contains("tds_commit") {
                    log_event("sql_batch: tds_commit");
                    let tx_desc_old = vec![9u8, 8, 7, 6, 5, 4, 3, 2];
                    let tx_desc_new = vec![0u8; 8];
                    let tokens = vec![
                        tiberius::server::BackendToken::EnvChange(
                            TokenEnvChange::CommitTransaction {
                                new: tx_desc_new,
                                old: tx_desc_old,
                            },
                        ),
                        tiberius::server::BackendToken::Done(TokenDone::default()),
                    ];
                    client.send(TdsBackendMessage::Tokens(tokens)).await?;
                    return Ok(());
                }

                if lower.contains("tds_error") {
                    log_event("sql_batch: tds_error");
                    let err = TokenError::new(
                        50000,
                        1,
                        16,
                        "dummy error",
                        "tiberius",
                        "tds_error",
                        1,
                    );
                    client
                        .send(TdsBackendMessage::Token(tiberius::server::BackendToken::Error(
                            err,
                        )))
                        .await?;
                    client
                        .send(TdsBackendMessage::Token(tiberius::server::BackendToken::Done(
                            TokenDone::with_status(DoneStatus::Error.into(), 0),
                        )))
                        .await?;
                    return Ok(());
                }

                if lower.contains("tds_attention") {
                    log_event("sql_batch: tds_attention");
                    let columns = vec![
                        meta_fixed("seq", FixedLenType::Int4),
                        meta_var("note", VarLenType::NVarchar, 200, collation),
                    ];
                    let mut writer = ResultSetWriter::start(client, columns).await?;
                    let mut sent = 0u64;
                    for idx in 0..200i32 {
                        if !writer
                            .send_row_iter_checked([
                                ColumnData::I32(Some(idx)),
                                ColumnData::String(Some("tick".into())),
                            ])
                            .await?
                        {
                            log_event("tds_attention: attention received");
                            writer.finish_attention_and_ready(sent).await?;
                            return Ok(());
                        }
                        sent += 1;
                        Timer::after(std::time::Duration::from_millis(25)).await;
                    }

                    writer.finish_or_attention(sent).await?;
                    return Ok(());
                }

                if lower.contains("tds_rpc") {
                    log_event("sql_batch: tds_rpc");
                    let columns = vec![meta_fixed("sql_value", FixedLenType::Int4)];
                    let mut writer = ResultSetWriter::start(client, columns).await?;
                    writer.send_row_iter([ColumnData::I32(Some(99))]).await?;
                    writer.finish(1).await?;
                    return Ok(());
                }

                if !lower.contains("select") {
                    log_event("sql_batch: non-select done");
                    client
                        .send(TdsBackendMessage::Token(tiberius::server::BackendToken::Done(
                            TokenDone::default(),
                        )))
                        .await?;
                    return Ok(());
                }

                log_event("sql_batch: default select");
                let columns = vec![meta_fixed("value", FixedLenType::Int4)];
                let mut writer = ResultSetWriter::start(client, columns).await?;
                writer.send_row_iter([ColumnData::I32(Some(1))]).await?;
                writer.finish(1).await?;
                Ok(())
            })
        }
    }

    struct DummyRpc;

    impl RpcHandler for DummyRpc {
        fn on_rpc<'a, C>(
            &'a self,
            client: &'a mut C,
            message: tiberius::server::RpcMessage,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>
        where
            C: TdsConnectionContext
                + futures_util::sink::Sink<TdsBackendMessage, Error = tiberius::error::Error>
                + Unpin
                + Send
                + 'a,
        {
            Box::pin(async move {
                let headers = client.last_request_headers();
                let tx_desc = headers
                    .transaction_descriptor
                    .as_ref()
                    .map(|tx| format!("{:02x?}", tx.descriptor))
                    .unwrap_or_else(|| "<none>".to_string());
                let query_len = headers
                    .query_descriptor
                    .as_ref()
                    .map(|value| value.len())
                    .unwrap_or(0);
                let trace_present = headers.trace_activity.is_some();
                let unknown = headers.unknown.len();
                log_event(&format!(
                    "rpc from={} proc_id={:?} proc_name={:?} flags={:?} params_len={} headers={{tx_desc={} query_len={} trace={} unknown={}}} reset={} skip_tran={}",
                    client.socket_addr(),
                    message.proc_id,
                    message.proc_name.as_deref().unwrap_or("<none>"),
                    message.flags,
                    message.params.len(),
                    tx_desc,
                    query_len,
                    trace_present,
                    unknown,
                    message.request_flags.reset_connection,
                    message.request_flags.reset_connection_skip_tran
                ));

                let params = decode_rpc_params(message.params).await?;
                if !params.is_empty() {
                    log_event(&format!("rpc params decoded={}", params.len()));
                }
                let proc_name = message.proc_name.as_deref().unwrap_or("");
                let mut output_only = proc_name.eq_ignore_ascii_case("tds_rpc_out");
                let output_first = proc_name.eq_ignore_ascii_case("tds_rpc_out_first");
                let is_tvp = proc_name.eq_ignore_ascii_case("tds_rpc_tvp");
                let is_executesql = proc_name.eq_ignore_ascii_case("sp_executesql");
                let is_prepare = proc_name.eq_ignore_ascii_case("sp_prepare");
                let is_execute = proc_name.eq_ignore_ascii_case("sp_execute");
                let is_prepexec = proc_name.eq_ignore_ascii_case("sp_prepexec");
                let is_exec_family = is_executesql || is_execute || is_prepexec;
                let suppress_param_echo =
                    is_executesql || is_prepare || is_execute || is_prepexec;
                if is_prepare {
                    output_only = true;
                }

                let tvp_stats = if is_tvp {
                    let stats = params.iter().find_map(|param| {
                        if let ColumnData::Tvp(Some(tvp)) = &param.value {
                            Some((tvp.columns.len() as i32, tvp.rows.len() as i32))
                        } else {
                            None
                        }
                    });
                    if stats.is_none() {
                        log_event("tds_rpc_tvp: no tvp param found");
                    }
                    stats
                } else {
                    None
                };

                if is_executesql {
                    if let Some(stmt) = params.first() {
                        log_event(&format!(
                            "sp_executesql stmt={}",
                            param_value_to_string(&stmt.value)
                        ));
                    }
                }
                if is_prepare {
                    if params.len() > 2 {
                        log_event(&format!(
                            "sp_prepare stmt={}",
                            param_value_to_string(&params[2].value)
                        ));
                    }
                }
                if is_execute {
                    if let Some(handle) = params.first() {
                        log_event(&format!(
                            "sp_execute handle={}",
                            param_value_to_string(&handle.value)
                        ));
                    }
                }

                let info = TokenInfo::new(
                    8127,
                    0,
                    0,
                    "dummy rpc info",
                    "tiberius",
                    "tds_rpc",
                    1,
                );
                client
                    .send(TdsBackendMessage::Token(tiberius::server::BackendToken::Info(
                        info,
                    )))
                    .await?;

                let mut pending_return_tokens = {
                    let mut tokens = Vec::new();
                    tokens.push(tiberius::server::BackendToken::ReturnStatus(0));
                    for (idx, param) in params.iter().enumerate() {
                        if !param.flags.contains(RpcStatus::ByRefValue) {
                            continue;
                        }

                        let ordinal = (idx + 1) as u16;
                        let name = if param.name.is_empty() {
                            format!("@P{ordinal}")
                        } else {
                            param.name.clone()
                        };
                        let meta = BaseMetaDataColumn {
                            user_type: 0,
                            flags: ColumnFlag::Nullable.into(),
                            ty: param.ty.clone(),
                            table_name: None,
                        };
                        let value = rpc_output_value(param);

                        tokens.push(tiberius::server::BackendToken::ReturnValue(
                            TokenReturnValue {
                                param_ordinal: ordinal,
                                param_name: name,
                                udf: false,
                                meta,
                                value,
                            },
                        ));
                    }
                    Some(tokens)
                };

                if output_first {
                    log_event("rpc output-first mode enabled");
                    if let Some(tokens) = pending_return_tokens.take() {
                        client.send(TdsBackendMessage::Tokens(tokens)).await?;
                    }
                }

                if !output_only && !params.is_empty() && !suppress_param_echo {
                    let collation = Some(Collation::new(13632521, 52));
                    let columns = vec![
                        meta_fixed("param_ordinal", FixedLenType::Int4),
                        meta_var("param_name", VarLenType::NVarchar, 200, collation),
                        meta_fixed("param_flags", FixedLenType::Int4),
                        meta_var("param_type", VarLenType::NVarchar, 512, collation),
                        meta_var("param_value", VarLenType::NVarchar, 1024, collation),
                    ];
                    let mut writer = ResultSetWriter::start(client, columns).await?;
                    for (idx, param) in params.iter().enumerate() {
                        let ordinal = (idx + 1) as i32;
                        let name = if param.name.is_empty() {
                            format!("@P{ordinal}")
                        } else {
                            param.name.clone()
                        };
                        let flags = param.flags.bits() as i32;
                        let ty = format!("{:?}", param.ty);
                        let value = param_value_to_string(&param.value);

                        writer
                            .send_row_iter([
                                ColumnData::I32(Some(ordinal)),
                                ColumnData::String(Some(name.into())),
                                ColumnData::I32(Some(flags)),
                                ColumnData::String(Some(ty.into())),
                                ColumnData::String(Some(value.into())),
                            ])
                            .await?;
                    }
                    writer.finish_more_in_proc(params.len() as u64).await?;
                }

                if is_tvp {
                    let (cols, rows) = tvp_stats.unwrap_or((0, 0));
                    let columns = vec![
                        meta_fixed("tvp_cols", FixedLenType::Int4),
                        meta_fixed("tvp_rows", FixedLenType::Int4),
                    ];
                    let mut writer = ResultSetWriter::start(client, columns).await?;
                    writer
                        .send_row_iter([ColumnData::I32(Some(cols)), ColumnData::I32(Some(rows))])
                        .await?;
                    writer.finish_more_in_proc(1).await?;
                } else if is_exec_family {
                    let columns = vec![meta_fixed("exec_value", FixedLenType::Int4)];
                    let mut writer = ResultSetWriter::start(client, columns).await?;
                    writer.send_row_iter([ColumnData::I32(Some(123))]).await?;
                    writer.finish_more_in_proc(1).await?;
                } else if !output_only {
                    let collation = Some(Collation::new(13632521, 52));
                    let columns = vec![
                        meta_fixed("rpc_value", FixedLenType::Int4),
                        meta_var("rpc_note", VarLenType::NVarchar, 200, collation),
                    ];
                    let mut writer = ResultSetWriter::start(client, columns).await?;
                    writer
                        .send_row_iter([
                            ColumnData::I32(Some(7)),
                            ColumnData::String(Some("rpc".into())),
                        ])
                        .await?;
                    writer.finish_more_in_proc(1).await?;
                }

                if let Some(tokens) = pending_return_tokens.take() {
                    client.send(TdsBackendMessage::Tokens(tokens)).await?;
                }

                client
                    .send(TdsBackendMessage::Token(tiberius::server::BackendToken::DoneProc(
                        TokenDone::with_rows(1),
                    )))
                    .await
            })
        }
    }

    struct DummyBulk;

    impl BulkLoadHandler for DummyBulk {
        fn on_bulk_load<'a, C>(
            &'a self,
            client: &'a mut C,
            _payload: bytes::BytesMut,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>
        where
            C: TdsConnectionContext
                + futures_util::sink::Sink<TdsBackendMessage, Error = tiberius::error::Error>
                + Unpin
                + Send
                + 'a,
        {
            Box::pin(async move {
                client
                    .send(TdsBackendMessage::Token(tiberius::server::BackendToken::Done(
                        TokenDone::default(),
                    )))
                    .await
            })
        }
    }

    struct DummyAttention;

    impl AttentionHandler for DummyAttention {
        fn on_attention<'a, C>(
            &'a self,
            client: &'a mut C,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>
        where
            C: TdsConnectionContext
                + futures_util::sink::Sink<TdsBackendMessage, Error = tiberius::error::Error>
                + Unpin
                + Send
                + 'a,
        {
            Box::pin(async move {
                client.clear_attention();
                let status = DoneStatus::Attention;
                client
                    .send(TdsBackendMessage::Token(tiberius::server::BackendToken::Done(
                        TokenDone::with_status(status.into(), 0),
                    )))
                    .await?;
                client.set_state(TdsConnectionState::ReadyForQuery);
                Ok(())
            })
        }
    }

    struct DummyErrorHandler;

    impl ErrorHandler for DummyErrorHandler {
        fn on_error(&self, _client: &dyn TdsConnectionContext, error: &mut tiberius::error::Error) {
            eprintln!("tds dummy server error: {error}");
        }
    }

    #[cfg(feature = "server-rustls")]
    fn resolve_encryption(tls_acceptor: &Option<RustlsAcceptor>) -> EncryptionLevel {
        let requested = std::env::var("TDS_DUMMY_ENCRYPTION")
            .ok()
            .and_then(|value| parse_encryption(&value));

        match (tls_acceptor.is_some(), requested) {
            (false, Some(level)) => {
                log_event(&format!(
                    "TLS disabled; ignoring requested encryption={level:?}"
                ));
                EncryptionLevel::NotSupported
            }
            (false, None) => EncryptionLevel::NotSupported,
            (true, Some(level)) => level,
            (true, None) => EncryptionLevel::On,
        }
    }

    #[cfg(feature = "server-rustls")]
    fn parse_encryption(value: &str) -> Option<EncryptionLevel> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" => Some(EncryptionLevel::Off),
            "on" | "request" => Some(EncryptionLevel::On),
            "required" | "require" => Some(EncryptionLevel::Required),
            "none" | "not_supported" | "disabled" => Some(EncryptionLevel::NotSupported),
            _ => None,
        }
    }

    #[cfg(feature = "server-rustls")]
    fn load_tls_acceptor() -> Option<RustlsAcceptor> {
        let cert_path = std::env::var("TDS_DUMMY_TLS_CERT").ok()?;
        let key_path = std::env::var("TDS_DUMMY_TLS_KEY").ok()?;
        let tls12_only = std::env::var("TDS_DUMMY_TLS12_ONLY")
            .ok()
            .as_deref()
            == Some("1");
        let tls13_only = std::env::var("TDS_DUMMY_TLS13_ONLY")
            .ok()
            .as_deref()
            == Some("1");

        if tls12_only && tls13_only {
            log_event("TLS config: both TLS12_ONLY and TLS13_ONLY set; using TLS 1.3");
        }

        let certs = load_certs(&cert_path)?;
        let key = load_private_key(&key_path)?;

        let builder = if tls13_only {
            ServerConfig::builder()
                .with_safe_default_cipher_suites()
                .with_safe_default_kx_groups()
                .with_protocol_versions(&[&version::TLS13])
                .map_err(|err| {
                    log_event(&format!("TLS config error: {err}"));
                    err
                })
                .ok()?
        } else if tls12_only {
            ServerConfig::builder()
                .with_safe_default_cipher_suites()
                .with_safe_default_kx_groups()
                .with_protocol_versions(&[&version::TLS12])
                .map_err(|err| {
                    log_event(&format!("TLS config error: {err}"));
                    err
                })
                .ok()?
        } else {
            ServerConfig::builder().with_safe_defaults()
        };

        let config = builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|err| {
                log_event(&format!("TLS config error: {err}"));
                err
            })
            .ok()?;

        Some(RustlsAcceptor::new(Arc::new(config)))
    }

    #[cfg(feature = "server-rustls")]
    fn load_certs(path: &str) -> Option<Vec<Certificate>> {
        let file = File::open(path).ok()?;
        let mut reader = BufReader::new(file);
        let certs = rustls_pemfile::certs(&mut reader).ok()?;
        if certs.is_empty() {
            log_event(&format!("TLS cert file empty: {path}"));
            return None;
        }
        Some(certs.into_iter().map(Certificate).collect())
    }

    #[cfg(feature = "server-rustls")]
    fn load_private_key(path: &str) -> Option<PrivateKey> {
        let file = File::open(path).ok()?;
        let mut reader = BufReader::new(file);
        let mut keys = rustls_pemfile::pkcs8_private_keys(&mut reader).ok()?;
        if let Some(key) = keys.pop() {
            return Some(PrivateKey(key));
        }

        let file = File::open(path).ok()?;
        let mut reader = BufReader::new(file);
        let mut keys = rustls_pemfile::rsa_private_keys(&mut reader).ok()?;
        if let Some(key) = keys.pop() {
            return Some(PrivateKey(key));
        }

        log_event(&format!("TLS key file missing usable keys: {path}"));
        None
    }

    pub fn run() {
        future::block_on(async {
            let listener = SmolNetBackend::bind("0.0.0.0:14333")
                .await
                .expect("bind failed");
            log_event("Dummy TDS server listening on 0.0.0.0:14333");

            #[cfg(feature = "server-rustls")]
            let tls_acceptor = load_tls_acceptor();
            #[cfg(feature = "server-rustls")]
            let encryption = resolve_encryption(&tls_acceptor);

            #[cfg(not(feature = "server-rustls"))]
            let encryption = EncryptionLevel::NotSupported;

            log_event(&format!("encryption policy: {encryption:?}"));
            #[cfg(feature = "server-rustls")]
            log_event(&format!(
                "TLS acceptor: {}",
                if tls_acceptor.is_some() { "enabled" } else { "disabled" }
            ));

            loop {
                let (stream, _addr) = listener.accept().await.expect("accept failed");
                let stream = TraceStream::new(stream);
                log_event(&format!("accepted connection from {}", _addr));
                #[cfg(feature = "server-rustls")]
                {
                    let tls = tls_acceptor.clone();
                    smol::spawn(async move {
                        let handlers = DummyHandlers::new(encryption);
                        if let Err(err) = process_connection(stream, tls, &handlers).await {
                            eprintln!("connection error: {err}");
                        }
                    })
                    .detach();
                }

                #[cfg(not(feature = "server-rustls"))]
                {
                    smol::spawn(async move {
                        let handlers = DummyHandlers::new(encryption);
                        if let Err(err) = process_connection(
                            stream,
                            Option::<tiberius::server::NoTls>::None,
                            &handlers,
                        )
                        .await
                        {
                            eprintln!("connection error: {err}");
                        }
                    })
                    .detach();
                }
            }
        });
    }
}

#[cfg(feature = "server-smol")]
fn main() {
    server::run();
}
