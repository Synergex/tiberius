use crate::{
    client::{config::Config, TrustConfig},
    error::Error,
};
pub(crate) use async_native_tls::TlsStream;
use async_native_tls::{Certificate, TlsConnector};
use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::io::{AsyncRead, AsyncWrite};
use std::{fs, path::Path};
use tracing::{event, Level};

fn certificate_error() -> Error {
    Error::Tls("Certificate file must contain exactly one valid PEM or DER certificate, with no extra data.".to_owned())
}

// Inspect contents, not extensions. Native parsers can accept trailing data, and
// some platforms accept only the first PEM block, so enforce our file contract
// before calling them.
fn parse_certificate(bytes: &[u8]) -> crate::Result<(Certificate, Vec<u8>)> {
    // A UTF-8 BOM (Windows PowerShell 5.1 `-Encoding utf8`) is text encoding, not PEM data.
    let text = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let trimmed = text.trim_ascii();
    let decoded;
    let der = if trimmed.starts_with(b"-----BEGIN CERTIFICATE-----") {
        let body = trimmed
            .strip_prefix(b"-----BEGIN CERTIFICATE-----")
            .and_then(|body| body.strip_suffix(b"-----END CERTIFICATE-----"))
            .ok_or_else(certificate_error)?;
        let encoded: Vec<u8> = body
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        decoded = STANDARD.decode(encoded).map_err(|_| certificate_error())?;
        decoded.as_slice()
    } else {
        bytes
    };
    // Require one definite-length DER SEQUENCE consuming the entire file.
    // This also prevents permissive OS certificate parsers ignoring a suffix.
    if der.first() != Some(&0x30) || der.len() < 2 {
        return Err(certificate_error());
    }
    let (header, length) = if der[1] < 0x80 {
        (2usize, usize::from(der[1]))
    } else {
        let count = usize::from(der[1] & 0x7f);
        if count == 0
            || count > std::mem::size_of::<usize>()
            || der.len() < 2 + count
            || der[2] == 0
        {
            return Err(certificate_error());
        }
        let mut length = 0usize;
        for byte in &der[2..2 + count] {
            length = length
                .checked_mul(256)
                .and_then(|n| n.checked_add(usize::from(*byte)))
                .ok_or_else(certificate_error)?;
        }
        if length < 128 {
            return Err(certificate_error());
        }
        (2 + count, length)
    };
    if header.checked_add(length) != Some(der.len()) {
        return Err(certificate_error());
    }
    let certificate = Certificate::from_der(der).map_err(|_| certificate_error())?;
    let canonical = certificate.to_der().map_err(|_| certificate_error())?;
    if canonical != der {
        return Err(certificate_error());
    }
    Ok((certificate, canonical))
}

fn load_certificate(path: &Path) -> crate::Result<(Certificate, Vec<u8>)> {
    // Keep the I/O kind (not found, permission denied, ...) but leave out the
    // path: the caller already has it, and it can reveal local names in logs.
    let bytes = fs::read(path).map_err(|e| Error::Io {
        kind: e.kind(),
        message: format!(
            "Could not read the configured certificate file: {}",
            e.kind()
        ),
    })?;
    parse_certificate(&bytes)
}

pub(crate) async fn create_tls_stream<S: AsyncRead + AsyncWrite + Unpin + Send>(
    config: &Config,
    stream: S,
) -> crate::Result<TlsStream<S>> {
    let mut builder = native_tls_crate::TlsConnector::builder();
    if config.strict_encryption {
        builder.min_protocol_version(Some(native_tls_crate::Protocol::Tlsv12));
        builder.request_alpns(&["tds/8.0"]);
    } else {
        // TDS 7.x record protection is incompatible with TLS 1.3.
        builder.max_protocol_version(Some(native_tls_crate::Protocol::Tlsv12));
    }

    let pinned = config
        .server_certificate
        .as_ref()
        .map(|path| load_certificate(path).map(|(_, der)| der))
        .transpose()?;

    match &config.trust {
        TrustConfig::CaCertificateLocation(path) => {
            // add_root_certificate retains the operating system's trust roots.
            builder.add_root_certificate(load_certificate(path)?.0);
        }
        TrustConfig::TrustAll => {
            event!(
                Level::WARN,
                "Trusting the server certificate without validation."
            );
            builder.danger_accept_invalid_certs(true);
            builder.danger_accept_invalid_hostnames(true);
            builder.use_sni(false);
        }
        TrustConfig::Default => {}
    }

    if pinned.is_some() {
        // Pinning deliberately replaces PKI/name verification. No stream is
        // returned to TDS until the authenticated peer's exact DER is checked.
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);
    }
    let hostname = config
        .certificate_hostname
        .as_deref()
        .unwrap_or_else(|| config.get_host());
    let tls = TlsConnector::from(builder)
        .connect(hostname, stream)
        .await?;
    if let Some(expected) = pinned {
        let actual = tls
            .peer_certificate()
            .map_err(|_| {
                Error::Tls("Could not obtain the peer certificate for pinning.".to_owned())
            })?
            .ok_or_else(|| {
                Error::Tls("The TLS peer did not provide a leaf certificate.".to_owned())
            })?
            .to_der()
            .map_err(|_| {
                Error::Tls("Could not encode the peer certificate for pinning.".to_owned())
            })?;
        if actual != expected {
            return Err(Error::Tls(
                "The server leaf certificate does not match the configured certificate pin."
                    .to_owned(),
            ));
        }
    }
    Ok(tls)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::tls::session_tests::peer_config;
    use futures_util::io::AsyncWriteExt;
    use std::{io::Read, net::TcpListener, thread, time::Duration};

    const CERTIFICATE: &[u8] = include_bytes!("../../../tests/security-fixtures/server.pem");
    const DER: &[u8] = include_bytes!("../../../tests/security-fixtures/server.der");

    #[test]
    fn certificate_files_reject_extra_or_malformed_data() {
        assert_eq!(parse_certificate(CERTIFICATE).unwrap().1, DER);
        assert_eq!(parse_certificate(DER).unwrap().1, DER);
        let bom = b"\xEF\xBB\xBF".as_slice();
        assert_eq!(
            parse_certificate(&[bom, CERTIFICATE].concat()).unwrap().1,
            DER
        );
        let bom_der = [bom, DER].concat();
        let bom_bundle = [bom, CERTIFICATE, bom, CERTIFICATE].concat();
        let bundle = [CERTIFICATE, CERTIFICATE].concat();
        let pem_suffix = [CERTIFICATE, b"unparsed suffix"].concat();
        let der_suffix = [DER, b"\0"].concat();
        for invalid in [
            b"".as_slice(),
            b"-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----",
            bundle.as_slice(),
            pem_suffix.as_slice(),
            der_suffix.as_slice(),
            bom_der.as_slice(),
            bom_bundle.as_slice(),
            b"\x30\x80\0\0",
        ] {
            assert!(parse_certificate(invalid).is_err());
        }
    }

    #[async_std::test]
    async fn explicit_bypass_completes_a_real_tls_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let peer = thread::spawn(move || {
            let mut connection =
                async_rustls::rustls::ServerConnection::new(peer_config()).unwrap();
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut tls = async_rustls::rustls::Stream::new(&mut connection, &mut socket);
            let mut marker = [0; 1];
            tls.read_exact(&mut marker).unwrap();
            marker
        });
        let mut config = Config::new();
        config.host("deliberately-wrong.invalid");
        config.trust_cert();
        let socket = async_std::net::TcpStream::connect(address).await.unwrap();
        let mut tls =
            async_std::future::timeout(Duration::from_secs(10), create_tls_stream(&config, socket))
                .await
                .unwrap()
                .unwrap();
        tls.write_all(&[0x7b]).await.unwrap();
        tls.flush().await.unwrap();
        drop(tls);
        assert_eq!(peer.join().unwrap(), [0x7b]);
    }
}
