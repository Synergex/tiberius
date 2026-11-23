#![cfg(unix)]
use std::sync::Once;
use tiberius::{AuthMethod, Client, Config, EncryptionLevel, Result};
use tokio::{net::TcpStream, runtime::Runtime};
use tokio_util::compat::TokioAsyncWriteCompatExt;

#[allow(dead_code)]
static LOGGER_SETUP: Once = Once::new();

/// The port of the server built from `docker/`, taken from
/// `TIBERIUS_TEST_CONNECTION_STRING` when set so the container can run on a
/// port other than 1433. The host stays `localhost`, the only name in
/// `docker/certs/server.crt`.
fn server_port() -> u16 {
    std::env::var("TIBERIUS_TEST_CONNECTION_STRING")
        .ok()
        .and_then(|conn_str| Config::from_ado_string(&conn_str).ok())
        .and_then(|config| config.get_addr().rsplit_once(':')?.1.parse().ok())
        .unwrap_or(1433)
}

#[test]
#[cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]
fn connect_to_custom_cert_instance_ado() -> Result<()> {
    LOGGER_SETUP.call_once(|| {
        env_logger::init();
    });

    let rt = Runtime::new()?;

    rt.block_on(async {
        let mut config = Config::from_ado_string(&format!(
            "server=tcp:localhost,{};IntegratedSecurity=true;TrustServerCertificateCA=docker/certs/customCA.crt",
            server_port()
        ))?;
        config.authentication(AuthMethod::sql_server(
            "sa",
            "<YourStrong@Passw0rd>",
        ));

        let tcp = TcpStream::connect(config.get_addr()).await?;

        let mut client = Client::connect(config, tcp.compat_write()).await?;

        let row = client
            .query("SELECT @P1", &[&-4i32])
            .await?
            .into_row()
            .await?
            .unwrap();

        assert_eq!(Some(-4i32), row.get(0));
        Ok(())
    })
}

#[test]
#[cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]
fn connect_to_custom_cert_instance_jdbc() -> Result<()> {
    LOGGER_SETUP.call_once(|| {
        env_logger::init();
    });

    let rt = Runtime::new()?;

    rt.block_on(async {
        // Careful: the / in the TrustServerCertificateCA needs to be escaped
        let mut config = Config::from_jdbc_string(&format!(
            "jdbc:sqlserver://localhost:{};TrustServerCertificateCA=docker{{/}}certs{{/}}customCA.crt",
            server_port()
        ))?;
        config.authentication(AuthMethod::sql_server("sa", "<YourStrong@Passw0rd>"));

        let tcp = TcpStream::connect(config.get_addr()).await?;

        let mut client = Client::connect(config, tcp.compat_write()).await?;

        let row = client
            .query("SELECT @P1", &[&-4i32])
            .await?
            .into_row()
            .await?
            .unwrap();

        assert_eq!(Some(-4i32), row.get(0));
        Ok(())
    })
}

#[test]
fn connect_to_custom_cert_instance_without_ca() -> Result<()> {
    LOGGER_SETUP.call_once(|| {
        env_logger::init();
    });

    let rt = Runtime::new()?;

    rt.block_on(async {
        let mut config = Config::new();
        config.authentication(AuthMethod::sql_server("sa", "<YourStrong@Passw0rd>"));
        config.encryption(EncryptionLevel::On);
        config.host("localhost");
        config.port(server_port());

        let tcp = TcpStream::connect(config.get_addr()).await?;

        let client = Client::connect(config, tcp.compat_write()).await;

        assert!(client.is_err());
        Ok(())
    })
}
