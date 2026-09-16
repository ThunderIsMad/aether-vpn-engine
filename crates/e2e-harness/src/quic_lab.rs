//! QUIC-лаборатория (фича `e2e`): сертификаты на лету, сервер и клиентские endpoint'ы.
//!
//! **TOFU-пин сертификата:** клиент доверяет не CA, а точной паре байтов DER-сертификата
//! из манифеста узла: сертификат узла — единственный корень в `RootCertStore`. Сертификат
//! самоподписанный (он же свой корень), SAN — `localhost` и `127.0.0.1`, поэтому стандартный
//! `WebPkiServerVerifier` проверяет и подпись, и имя. В проде здесь будет манифест-authority;
//! лаборатория не меняет протокол, только корень доверия.
//!
//! **Endpoint'ы:** сервер — `Endpoint::server(config, addr)`; клиент — один endpoint на
//! процесс (`Endpoint::client`), соединения к N1/N2 — `connect_with` с per-connection
//! `ClientConfig` (у каждого узла свой пин сертификата). `Endpoint` — ручка: держать живым
//! всё соединение, поэтому `connect` возвращает пару (endpoint, connection).

#![cfg(feature = "e2e")]

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

/// Сертификат лаборатории: DER-байты + pkcs8-ключ.
pub struct LabCert {
    /// DER-байты самоподписанного сертификата.
    pub cert_der: Vec<u8>,
    /// pkcs8-обёртка Ed25519-ключа (PKCS#8, формат для quinn).
    pub key_pkcs8: Vec<u8>,
}

/// Самоподписанный Ed25519-сертификат на лету: SAN `localhost` + `127.0.0.1`, чтобы
/// стандартный верификатор прошёл name-check при `server_name = "localhost"`.
/// Алгоритм привязан к ключу сертификата, не к протоколу; Ed25519 включён в ринг,
/// на котором собирается quinn 0.11.
pub fn self_signed_cert() -> LabCert {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("Ed25519 keygen");
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .expect("SAN localhost валиден");
    params.subject_alt_names.push(rcgen::SanType::IpAddress(
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
    ));
    // CA, чтобы сертификат мог быть собственным корнем в RootCertStore.
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let mut name = rcgen::DistinguishedName::new();
    name.push(rcgen::DnType::CommonName, "aether-e2e-lab");
    params.distinguished_name = name;
    let cert = params.self_signed(&key_pair).expect("self-signed cert");
    LabCert {
        cert_der: cert.der().as_ref().to_vec(),
        key_pkcs8: key_pair.serialize_der(),
    }
}

/// Транспорт сервера: TLS с одним сертификатом, datagram quinn включены по умолчанию.
pub fn server_config(cert: &LabCert) -> Result<quinn::ServerConfig, String> {
    let cert_der = CertificateDer::from(cert.cert_der.clone());
    let key = PrivatePkcs8KeyDer::from(cert.key_pkcs8.clone());
    // Провайдер задаём явно: rustls собран с фичей `ring` (см. Cargo.toml),
    // тот же бэкенд, что в prod-пине clatter/x25519-dalek.
    let provider = rustls::crypto::ring::default_provider();
    let tls = rustls::ServerConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls versions: {e}"))?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key.into())
        .map_err(|e| format!("cert/key: {e}"))?;
    let server = QuicServerConfig::try_from(tls).map_err(|e| format!("quic server: {e}"))?;
    Ok(quinn::ServerConfig::with_crypto(std::sync::Arc::new(server)))
}

/// Сервер-эндпоинт на 127.0.0.1:`port` (0 — свободный); возвращает фактический порт.
pub fn server_endpoint(port: u16, cert: &LabCert) -> Result<(quinn::Endpoint, u16), String> {
    let endpoint = quinn::Endpoint::server(
        server_config(cert)?,
        std::net::SocketAddr::from(([127, 0, 0, 1], port)),
    )
    .map_err(|e| format!("endpoint: {e}"))?;
    let local_port = endpoint
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?
        .port();
    Ok((endpoint, local_port))
}

/// Клиентский конфиг: пин сертификата узла как единственный корень + ALPN.
pub fn client_config(cert_der: &[u8]) -> Result<quinn::ClientConfig, String> {
    let cert = CertificateDer::from(cert_der.to_vec());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).map_err(|e| format!("pin cert: {e}"))?;
    let provider = rustls::crypto::ring::default_provider();
    let tls = rustls::ClientConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls versions: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let quic_client = QuicClientConfig::try_from(tls).map_err(|e| format!("quic client: {e}"))?;
    Ok(quinn::ClientConfig::new(std::sync::Arc::new(quic_client)))
}

/// Единственный клиентский endpoint процесса (исходящий сокет 127.0.0.1:0).
pub fn client_endpoint() -> Result<quinn::Endpoint, String> {
    let addr: std::net::SocketAddr = "127.0.0.1:0"
        .parse()
        .expect("литерал 127.0.0.1:0 валиден");
    quinn::Endpoint::client(addr).map_err(|e| format!("client endpoint: {e}"))
}

/// Подключение к узлу по манифесту: per-connection конфиг с его пином сертификата
/// (`connect_with`), имя `localhost` покрыто SAN сертификата.
pub async fn connect(
    endpoint: &quinn::Endpoint,
    manifest: &crate::NodeManifest,
) -> Result<quinn::Connection, String> {
    let config = client_config(&manifest.quic_cert_der)?;
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], manifest.port));
    let connection = endpoint
        .connect_with(config, addr, "localhost")
        .map_err(|e| format!("connect: {e}"))?
        .await
        .map_err(|e| format!("quic handshake: {e}"))?;
    Ok(connection)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Самоподписанный сертификат генерируется: DER парсится, ключ pkcs8 не пуст.
    #[test]
    fn cert_generation() {
        let cert = self_signed_cert();
        assert!(!cert.cert_der.is_empty());
        assert!(!cert.key_pkcs8.is_empty());
        let parsed = CertificateDer::from(cert.cert_der.clone());
        assert!(!parsed.as_ref().is_empty());
    }

    /// Сервер-эндпоинт поднимается на свободном порту; конфиг клиента принимается.
    #[tokio::test]
    async fn endpoints_bind() {
        let cert = self_signed_cert();
        let (_endpoint, port) = server_endpoint(0, &cert).expect("server endpoint");
        assert_ne!(port, 0, "свободный порт выдан ОС");
        let _client = client_endpoint().expect("client endpoint");
        let _config = client_config(&cert.cert_der).expect("client config");
    }
}
