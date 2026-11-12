#![cfg(feature = "native-tls")]

use std::{io::Read, net::TcpListener, path::PathBuf, thread, time::Duration};
use tiberius::error::Error;
use tiberius::{AuthMethod, Client, Config};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/security-fixtures")
        .join(name)
        .to_str()
        .unwrap()
        .to_owned()
}

// The peer stops after TLS and the first TDS bytes: no SQL Server or credentials
// are needed. Seeing PRELOGIN proves verification completed before any login.
async fn connect_to_peer(mut config: Config) -> (Error, Vec<u8>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let peer = thread::spawn(move || {
        let identity = native_tls_crate::Identity::from_pkcs12(
            include_bytes!("security-fixtures/server.p12"),
            "",
        )
        .unwrap();
        let acceptor = native_tls_crate::TlsAcceptor::new(identity).unwrap();
        let (socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut tls = match acceptor.accept(socket) {
            Ok(tls) => tls,
            Err(_) => return Vec::new(),
        };
        let mut received = [0; 8];
        match tls.read(&mut received) {
            Ok(count) => received[..count].to_vec(),
            Err(_) => Vec::new(),
        }
    });
    // TCP always goes to loopback; only the verification/SNI name changes.
    config.host("127.0.0.1");
    config.strict_encryption(true);
    config.authentication(AuthMethod::sql_server("never-sent", "never-sent"));
    let socket = TcpStream::connect(address).await.unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        Client::connect(config, socket.compat_write()),
    )
    .await
    .unwrap();
    let error = match result {
        Ok(_) => panic!("The test peer does not send a SQL Server login response"),
        Err(error) => error,
    };
    (error, peer.join().unwrap())
}

#[tokio::test]
async fn custom_ca_and_hostname_override_allow_prelogin() {
    let mut config = Config::new();
    config.trust_cert_ca(fixture("ca.pem"));
    config.certificate_hostname("sql.test");
    let (_, received) = connect_to_peer(config).await;
    assert_eq!(
        received.first(),
        Some(&0x12),
        "verified TLS must precede PRELOGIN"
    );
}

#[tokio::test]
async fn custom_ca_does_not_disable_hostname_validation() {
    let mut config = Config::new();
    config.trust_cert_ca(fixture("ca.pem"));
    let (error, received) = connect_to_peer(config).await;
    assert!(matches!(error, Error::Tls(_)));
    assert!(
        received.is_empty(),
        "a wrong hostname must stop TDS before PRELOGIN"
    );
}

#[tokio::test]
async fn hostname_override_does_not_disable_chain_validation() {
    let mut config = Config::new();
    config.certificate_hostname("sql.test");
    let (error, received) = connect_to_peer(config).await;
    assert!(matches!(error, Error::Tls(_)));
    assert!(
        received.is_empty(),
        "the test CA is not in the OS trust store"
    );
}

#[tokio::test]
async fn explicit_wrong_hostname_is_rejected_with_trusted_ca() {
    let mut config = Config::new();
    config.trust_cert_ca(fixture("ca.pem"));
    config.certificate_hostname("wrong.invalid");
    let (error, received) = connect_to_peer(config).await;
    assert!(matches!(error, Error::Tls(_)));
    assert!(received.is_empty());
}

#[tokio::test]
async fn exact_leaf_pem_and_der_pins_replace_chain_and_hostname_checks() {
    for certificate in ["server.pem", "server.der"] {
        let mut config = Config::new();
        config.server_certificate(fixture(certificate));
        let (_, received) = connect_to_peer(config).await;
        assert_eq!(received.first(), Some(&0x12));
    }
}

#[tokio::test]
async fn pinning_the_issuer_instead_of_the_leaf_is_rejected_before_tds() {
    let mut config = Config::new();
    config.server_certificate(fixture("ca.pem"));
    let (error, received) = connect_to_peer(config).await;
    assert!(matches!(error, Error::Tls(_)));
    assert!(
        received.is_empty(),
        "a mismatched pin must not send PRELOGIN or credentials"
    );
}

#[tokio::test]
async fn missing_pin_file_has_no_fallback_or_path_disclosure() {
    let mut config = Config::new();
    let missing = fixture("missing-pin-sensitive-path.pem");
    config.server_certificate(&missing);
    let (error, received) = connect_to_peer(config).await;
    assert!(matches!(error, Error::Tls(_)));
    assert!(!error.to_string().contains(&missing));
    assert!(!error.to_string().contains("missing-pin-sensitive-path"));
    assert!(received.is_empty());
}

#[tokio::test]
async fn malformed_pin_file_has_no_fallback() {
    let mut config = Config::new();
    config.server_certificate(fixture("malformed.pem"));
    let (error, received) = connect_to_peer(config).await;
    assert!(matches!(error, Error::Tls(_)));
    assert!(received.is_empty());
}

#[tokio::test]
async fn malformed_or_missing_custom_ca_has_no_fallback() {
    for file in ["malformed.pem", "missing-ca-sensitive-path.pem"] {
        let mut config = Config::new();
        config.certificate_hostname("sql.test");
        config.trust_cert_ca(fixture(file));
        let (error, received) = connect_to_peer(config).await;
        assert!(matches!(error, Error::Tls(_)));
        assert!(!error.to_string().contains(file));
        assert!(received.is_empty());
    }
}
