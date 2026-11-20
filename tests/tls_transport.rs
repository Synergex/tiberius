use futures_util::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::time::Duration;
use tiberius::{AuthMethod, Client, Config, EncryptionLevel};
use tokio_util::compat::TokioAsyncReadCompatExt;

async fn read_packet<S: AsyncRead + Unpin>(stream: &mut S) -> (u8, Vec<u8>) {
    let mut header = [0; 8];
    stream.read_exact(&mut header).await.unwrap();
    let length = u16::from_be_bytes([header[2], header[3]]) as usize;
    assert!(length >= 8);
    let mut payload = vec![0; length - 8];
    stream.read_exact(&mut payload).await.unwrap();
    (header[0], payload)
}

async fn prelogin_response<S: AsyncWrite + Unpin>(stream: &mut S, encryption: u8) {
    // VERSION and ENCRYPTION options, followed by their values.
    stream
        .write_all(&[
            4, 1, 0, 26, 0, 0, 1, 0, 0, 0, 11, 0, 6, 1, 0, 17, 0, 1, 255, 16, 0, 0, 0, 0, 0,
            encryption,
        ])
        .await
        .unwrap();
    stream.flush().await.unwrap();
}

fn config(encryption: EncryptionLevel) -> Config {
    let mut config = Config::new();
    config.host("localhost");
    config.encryption(encryption);
    config.authentication(AuthMethod::sql_server(
        "wire-test-user",
        "wire-test-password",
    ));
    config
}

#[cfg(any(
    feature = "native-tls",
    feature = "rustls",
    feature = "vendored-openssl"
))]
#[tokio::test]
async fn mandatory_refuses_downgrades_before_sending_credentials() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for requested in [EncryptionLevel::On, EncryptionLevel::Required] {
            for offered in [0, 2] {
                let (client, server) = tokio::io::duplex(65536);
                let peer = tokio::spawn(async move {
                    let mut server = server.compat();
                    assert_eq!(read_packet(&mut server).await.0, 0x12);
                    prelogin_response(&mut server, offered).await;
                    let mut remaining = Vec::new();
                    server.read_to_end(&mut remaining).await.unwrap();
                    assert!(remaining.is_empty(), "sent data after refusing encryption");
                });
                let result = Client::connect(config(requested), client.compat()).await;
                assert!(matches!(result, Err(tiberius::error::Error::Tls(_))));
                peer.await.unwrap();
            }
        }
    })
    .await
    .unwrap();
}

#[cfg(any(
    feature = "native-tls",
    feature = "rustls",
    feature = "vendored-openssl"
))]
#[tokio::test]
async fn optional_can_establish_an_unencrypted_session() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (client, server) = tokio::io::duplex(65536);
        let peer = tokio::spawn(async move {
            let mut server = server.compat();
            assert_eq!(read_packet(&mut server).await.0, 0x12);
            prelogin_response(&mut server, 2).await;
            assert_eq!(read_packet(&mut server).await.0, 0x10);
            // A TDS 7.4 LOGINACK and DONE, without any TLS layer.
            server
                .write_all(&[
                    4, 1, 0, 34, 0, 0, 1, 0, 0xad, 10, 0, 1, 0x74, 0, 0, 4, 0, 16, 0, 0, 0, 0xfd,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ])
                .await
                .unwrap();
            server.flush().await.unwrap();
            assert_eq!(read_packet(&mut server).await.0, 1);
            server
                .write_all(&[
                    4, 1, 0, 21, 0, 0, 1, 0, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ])
                .await
                .unwrap();
            server.flush().await.unwrap();
        });
        let mut client = Client::connect(config(EncryptionLevel::Off), client.compat())
            .await
            .unwrap();
        assert!(!client.is_encrypted());
        client
            .simple_query("SELECT 1")
            .await
            .unwrap()
            .into_results()
            .await
            .unwrap();
        peer.await.unwrap();
    })
    .await
    .unwrap();
}

#[cfg(feature = "native-tls")]
#[tokio::test]
async fn strict_starts_with_raw_tls_and_never_retries_plaintext() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (client, server) = tokio::io::duplex(65536);
        let peer = tokio::spawn(async move {
            let mut server = server.compat();
            let mut header = [0; 5];
            server.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], 0x16, "first bytes must be a raw TLS handshake");
            assert_eq!(header[1], 3);
            let mut hello = vec![0; u16::from_be_bytes([header[3], header[4]]) as usize];
            server.read_exact(&mut hello).await.unwrap();
            assert_eq!(hello[0], 1, "expected ClientHello before PRELOGIN");
            // A legacy/plaintext peer must cause failure, not a TDS 7 retry.
            prelogin_response(&mut server, 2).await;
            let mut remaining = Vec::new();
            server.read_to_end(&mut remaining).await.unwrap();
            while !remaining.is_empty() {
                assert!(remaining.len() >= 5);
                assert!(
                    (0x14..=0x17).contains(&remaining[0]),
                    "non-TLS fallback after failed Strict handshake"
                );
                let length = u16::from_be_bytes([remaining[3], remaining[4]]) as usize + 5;
                assert!(remaining.len() >= length);
                remaining.drain(..length);
            }
        });
        let mut config = config(EncryptionLevel::Required);
        config.strict_encryption(true);
        assert!(Client::connect(config, client.compat()).await.is_err());
        peer.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn strict_bypass_is_rejected_before_transport_io() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (client, server) = tokio::io::duplex(65536);
        let mut config = config(EncryptionLevel::Required);
        config.strict_encryption(true);
        config.trust_cert();
        assert!(Client::connect(config, client.compat()).await.is_err());
        let mut bytes = Vec::new();
        server.compat().read_to_end(&mut bytes).await.unwrap();
        assert!(
            bytes.is_empty(),
            "invalid security settings performed transport I/O"
        );
    })
    .await
    .unwrap();
}
