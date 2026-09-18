//! `e2e-harness` — сборка живого E2E-прогона Phase 1 (ручной запуск, не CI job).
//!
//! Два бинарника (`aether-node`, `aether-client`, фича `e2e`) соединяются на localhost
//! через **реальный** `quinn::Endpoint` и проходят протокол из `02-protocols.md`:
//! гибридный Noise_IK handshake (Clatter, `crypto-core`), mint ticket, `RESUME`/`RESUME_ACK`
//! с PoP, пост-ротационный re-key и записи frame-слоя в QUIC-datagram.
//!
//! Прод-логика — прод-крейты; здесь только wire-склейка и настройка лаборатории:
//!
//! * кадры записи — прод-функции `transport_mux::{encode_frame, decode_frame}`
//!   (`len(4B BE) ‖ record.encode()`) — тот же формат, что интеграционный тест `phase0-path`;
//! * `RESUME` — `ClientRotation::build_resume` байт в байт (kind `0x02`, PoP `sig_client`),
//!   проверка `sig_node` ACK — `ClientRotation::accept_response` (`key-coordinator`);
//! * `RESUME_ACK` на стороне узла — прод-эмиттер `key_coordinator::build_resume_ack`
//!   (BLOCKER-2: единственный эмиттер ACK-кадра, harness кадр сам не собирает);
//! * ротация N1→N2: узел N2 держит `eph_node_priv`, выводит `K_session'` той же функцией
//!   `derive_rotated_session`, что и клиент (`02 §3.3`); совпадение видно по логам сторон.
//!
//! Правило ТЗ: если прод-код расходится со спекой `02-protocols` при живом прогоне — это
//! BLOCKER в `QUESTIONS.md`, не молчаливая правка спеки. Все форматы собраны из типов
//! прод-крейтов (`build_resume`, `TicketFactory`, `encode_frame`), а не переизобретены.

#![cfg_attr(not(test), deny(unsafe_code))]

use crypto_core::RecordCrypto;
use frame_session::Session;

#[cfg(feature = "e2e")]
pub mod quic_lab;
pub mod wire;

/// Адаптер `crypto-core` → `frame_session::SessionCrypto` — тот же шаг ratchet и тот же
/// AEAD, что в прод-склейке `rotation-tests/tests/harness` (один код, не копия).
#[derive(Debug, Default)]
pub struct CoreCrypto;

impl frame_session::SessionCrypto for CoreCrypto {
    fn record_key_at(&self, session_id: &[u8; 16], base: &[u8; 32], seq: u64) -> [u8; 32] {
        crypto_core::derive_record_key(session_id, &crypto_core::KSession(*base), seq).0
    }

    fn seal(&self, k_record: &[u8; 32], nonce: [u8; 24], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        crypto_core::RecordAead.seal(
            &crypto_core::KRecord(*k_record),
            &crypto_core::RecordNonce(nonce),
            aad,
            plaintext,
        )
    }

    fn open(
        &self,
        k_record: &[u8; 32],
        nonce: [u8; 24],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, frame_session::RecordError> {
        crypto_core::RecordAead
            .open(
                &crypto_core::KRecord(*k_record),
                &crypto_core::RecordNonce(nonce),
                aad,
                ciphertext,
            )
            .map_err(|_| frame_session::RecordError::OpenFailed)
    }
}

/// Ключи узла лаборатории: static X25519 и identity Ed25519 выводятся из seed
/// детерминированно (одна пара значений у узла и у манифеста клиента), статический
/// KEM-ключ ML-KEM-768 — RNG (детерминированного keygen-from-seed у бэкенда PQClean нет;
/// клиенту нужен только `ek`, он передаётся манифестом — см. `NodeManifest`).
#[derive(Clone)]
pub struct NodeKeys {
    /// Seed узла (CLI: 64 hex-символа).
    pub seed: [u8; 32],
    /// `node_static` X25519 (DH-половина Noise_IK).
    pub static_priv: [u8; 32],
    /// `node_identity` Ed25519 (подпись `sig_node` над RESUME_ACK).
    pub identity_priv: [u8; 32],
    /// Статический KEM-ключ ML-KEM-768 (пред-сообщение S гибридного IK).
    pub kem: crypto_core::MlKem768KeyPair,
}

impl std::fmt::Debug for NodeKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // В Debug не утекают приватные ключи: только хеши.
        f.debug_struct("NodeKeys")
            .field("seed#", &short_hash(&self.seed, 6))
            .finish_non_exhaustive()
    }
}

impl NodeKeys {
    /// Детерминированные ключи узла из seed (кроме KEM — см. шапку структуры).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let static_priv =
            crypto_core::sha256(&[b"aether-e2e-static".as_slice(), seed.as_slice()].concat());
        let identity_priv =
            crypto_core::sha256(&[b"aether-e2e-identity".as_slice(), seed.as_slice()].concat());
        let kem = crypto_core::mlkem768_genkey().expect("ML-KEM-768 genkey (RNG)");
        Self {
            seed,
            static_priv,
            identity_priv,
            kem,
        }
    }

    /// Публичная часть узла: статические ключи и identity.
    pub fn public_part(&self) -> ([u8; 32], [u8; 32], Vec<u8>) {
        (
            crypto_core::ed25519_pubkey(&self.identity_priv).0,
            crypto_core::x25519_keypair(&self.static_priv).public,
            crypto_core::mlkem768_ek_bytes(&self.kem.public),
        )
    }
}

/// «Манифест подписки» лаборатории (`02 §5`): только публичная часть узла + самоподписанный
/// QUIC-сертификат outer-транспорта (в проде сертификат приходил бы с узла так же).
#[derive(Debug, Clone)]
pub struct NodeManifest {
    /// Идентификатор узла флота.
    pub node_id: u32,
    /// Порт QUIC (в лаборатории адрес = 127.0.0.1:порт).
    pub port: u16,
    /// `node_identity` Ed25519 pub (проверка `sig_node`).
    pub identity: [u8; 32],
    /// `node_static` X25519 pub (Noise_IK).
    pub node_static: [u8; 32],
    /// Статический KEM-ключ узла: FIPS 203 ek, `MLKEM768_EK_BYTES` байт.
    pub node_static_kem: Vec<u8>,
    /// DER самоподписанного QUIC-сертификата (outer TLS).
    pub quic_cert_der: Vec<u8>,
}

/// Метка первой строки файла манифеста.
pub const MANIFEST_MAGIC: &str = "aether-e2e-manifest v1";

/// Пишет манифест узла в файл (узел публикует, клиент читает).
pub fn write_manifest(
    keys: &NodeKeys,
    node_id: u32,
    port: u16,
    quic_cert_der: &[u8],
    path: &std::path::Path,
) -> std::io::Result<()> {
    let (identity, node_static, kem_ek) = keys.public_part();
    let text = format!(
        "{MANIFEST_MAGIC}\n\
         node_id {node_id}\n\
         port {port}\n\
         identity {}\n\
         static {}\n\
         kem {}\n\
         quic_cert {}\n",
        hex(&identity),
        hex(&node_static),
        hex(&kem_ek),
        hex(quic_cert_der),
    );
    std::fs::write(path, text)
}

/// Читает манифест узла; любая порча — ошибка, а не частичный разбор.
pub fn read_manifest(path: &std::path::Path) -> Result<NodeManifest, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut lines = text.lines();
    if lines.next() != Some(MANIFEST_MAGIC) {
        return Err(format!("{}: не манифест лаборатории", path.display()));
    }
    let mut fields: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    for line in lines {
        let Some((key, value)) = line.split_once(' ') else {
            return Err(format!("{}: строка без значения: {line:?}", path.display()));
        };
        fields.insert(key, value);
    }
    let field = |name: &str| fields.get(name).copied().ok_or(format!("нет поля {name}"));
    let node_id: u32 = field("node_id")?.parse().map_err(|e| format!("node_id: {e}"))?;
    let port: u16 = field("port")?.parse().map_err(|e| format!("port: {e}"))?;
    let identity: [u8; 32] = unhex(field("identity")?)
        .ok_or("identity: плохой hex")?
        .try_into()
        .map_err(|_| "identity: не 32 байта")?;
    let node_static: [u8; 32] = unhex(field("static")?)
        .ok_or("static: плохой hex")?
        .try_into()
        .map_err(|_| "static: не 32 байта")?;
    let node_static_kem = unhex(field("kem")?).ok_or("kem: плохой hex")?;
    if node_static_kem.len() != crypto_core::MLKEM768_EK_BYTES {
        return Err(format!(
            "kem: {} байт, ожидается {}",
            node_static_kem.len(),
            crypto_core::MLKEM768_EK_BYTES
        ));
    }
    let quic_cert_der = unhex(field("quic_cert")?).ok_or("quic_cert: плохой hex")?;
    Ok(NodeManifest {
        node_id,
        port,
        identity,
        node_static,
        node_static_kem,
        quic_cert_der,
    })
}

/// Параметры лаборатории по умолчанию: порты, `sid`, TTL ticket, ритм прогонов.
/// Ключи (статики, личность, `TFK_epoch`) выводятся из seed'ов CLI — одноразовая
/// лаборатория, а не прод-конфиг; в логи идут только хеши.
#[derive(Debug, Clone)]
pub struct LabConfig {
    /// Порт node N1.
    pub node1_port: u16,
    /// Порт node N2.
    pub node2_port: u16,
    /// server name для outer QUIC (лаборатория: localhost).
    pub server_name: String,
    /// Идентификатор сессии (16 B, детерминированный).
    pub session_id: [u8; 16],
    /// TTL ticket в секундах.
    pub ticket_ttl_seconds: u64,
    /// После скольких записей клиент триггерит ротацию N1 → N2.
    pub rotate_after_records: u64,
    /// Сколько записей отправить после re-key.
    pub records_after_rotation: u64,
    /// «Сейчас» для TTL ticket (unix-секунды); часы лаборатории инжектируются,
    /// как в прод-крейтах (`set_now`).
    pub now: u64,
}

impl LabConfig {
    /// Конфиг по умолчанию из двух портов.
    pub fn new(node1_port: u16, node2_port: u16) -> Self {
        let digest = crypto_core::sha256(b"aether e2e lab sid");
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&digest[..16]);
        Self {
            node1_port,
            node2_port,
            server_name: "localhost".to_string(),
            session_id,
            ticket_ttl_seconds: 3600,
            rotate_after_records: 5,
            records_after_rotation: 5,
            now: 1_700_000_000,
        }
    }

    /// `SocketAddr` узла по id (1 или 2).
    pub fn node_addr(&self, node_id: u32) -> std::net::SocketAddr {
        let port = match node_id {
            1 => self.node1_port,
            _ => self.node2_port,
        };
        std::net::SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// Имя outer-TLS соединения (лаборатория: localhost).
    pub fn default_server_name(&self) -> String {
        self.server_name.clone()
    }
}

/// Флотский ключ эпохи: один у N1 и N2 (`02 §3.2`), детерминированный.
pub fn tfk_epoch() -> [u8; 32] {
    crypto_core::sha256(b"aether e2e tfk epoch")
}

/// Ключи клиента лаборатории из seed: static (Noise_IK) и identity (PoP).
#[derive(Clone)]
pub struct ClientKeys {
    /// Seed клиента (CLI: 64 hex-символа).
    pub seed: [u8; 32],
    /// `client_static` X25519.
    pub static_priv: [u8; 32],
    /// `client_identity` Ed25519 (PoP `sig_client`).
    pub identity_priv: [u8; 32],
}

impl std::fmt::Debug for ClientKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientKeys")
            .field("seed#", &short_hash(&self.seed, 6))
            .finish_non_exhaustive()
    }
}

impl ClientKeys {
    /// Детерминированные ключи клиента из seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            seed,
            static_priv: crypto_core::sha256(
                &[b"aether-e2e-client-static".as_slice(), seed.as_slice()].concat(),
            ),
            identity_priv: crypto_core::sha256(
                &[b"aether-e2e-client-identity".as_slice(), seed.as_slice()].concat(),
            ),
        }
    }

    /// `client_identity` pub — тот, что узел вписывает в ticket и по которому проверяет PoP.
    pub fn identity_pub(&self) -> [u8; 32] {
        crypto_core::ed25519_pubkey(&self.identity_priv).0
    }
}

/// Локальная сессия frame-слоя на заданном `K_session`.
pub fn new_session(session_id: [u8; 16], k_session: [u8; 32]) -> Session {
    Session::new(
        frame_session::SessionId(session_id),
        k_session,
        Box::new(CoreCrypto),
    )
}

/// QUIC payload записи — прод-функция `transport_mux::encode_frame`.
pub fn encode_record_frame(record: &frame_session::Record) -> Vec<u8> {
    transport_mux::encode_frame(record)
}

/// Разбор QUIC payload до записи — прод-функция `transport_mux::decode_frame`.
pub fn decode_record_frame(
    frame: &[u8],
) -> Result<frame_session::Record, transport_mux::BindingError> {
    transport_mux::decode_frame(frame)
}

/// hex-строка первых `n` байтов sha256 (для логов: хеши вместо секретов).
pub fn short_hash(bytes: &[u8], n: usize) -> String {
    let digest = crypto_core::sha256(bytes);
    digest[..n].iter().map(|b| format!("{b:02x}")).collect()
}

/// hex-кодирование байтов (манифесты, CLI-seed).
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// hex → байты; кривая длина/символ — `None`.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// Парсинг 32-байтового seed'а из hex-строки CLI.
pub fn seed_from_hex(s: &str) -> Result<[u8; 32], String> {
    let bytes = unhex(s).ok_or("seed: плохой hex")?;
    let len = bytes.len();
    <[u8; 32]>::try_from(bytes).map_err(|_| format!("seed: {len} байт, нужно 32"))
}

/// Эфемерная пара ротации узла: fresh X25519 из RNG (`02 §3.3`).
/// Приватная половина остаётся на узле, публичная уходит в `RESUME_ACK`.
pub fn fresh_eph_node() -> ([u8; 32], [u8; 32]) {
    let (pub_key, priv_key) = crypto_core::x25519_genkey().expect("rng для eph_node");
    (pub_key.0, priv_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use frame_session::SessionCrypto;

    /// Адаптер CoreCrypto открывает то, что сам запечатал, и отвергает порчу.
    #[test]
    fn core_crypto_roundtrip() {
        let sid = [7u8; 16];
        let k_session = [0x33u8; 32];
        let crypto = CoreCrypto;
        let k_record = crypto.record_key_at(&sid, &k_session, 0);
        let nonce =
            frame_session::record_nonce(frame_session::Seq(0), &frame_session::SessionId(sid));
        let sealed = crypto.seal(&k_record, nonce, b"aad", b"payload");
        assert_eq!(
            crypto.open(&k_record, nonce, b"aad", &sealed),
            Ok(b"payload".to_vec())
        );
        assert_eq!(
            crypto.open(&k_record, nonce, b"aad", b"corrupted"),
            Err(frame_session::RecordError::OpenFailed)
        );
    }

    /// sid лаборатории детерминирован (не RNG), порты не влияют.
    #[test]
    fn lab_config_sid_is_deterministic() {
        let a = LabConfig::new(1000, 1001);
        let b = LabConfig::new(2000, 2001);
        assert_eq!(a.session_id, b.session_id, "sid лаборатории фиксирован");
        assert_eq!(a.node_addr(1).to_string(), "127.0.0.1:1000");
        assert_eq!(b.node_addr(2).to_string(), "127.0.0.1:2001");
        assert_eq!(a.rotate_after_records, 5);
    }

    /// Кадры записей E2E — прод-функции transport-mux: roundtrip.
    #[test]
    fn record_frame_roundtrip_uses_transport_mux() {
        let mut session = new_session([1u8; 16], [2u8; 32]);
        let stream = session.open_stream(frame_session::FlowId(1));
        let record = session.seal_record(stream, b"e2e frame");
        let frame = encode_record_frame(&record);
        assert_eq!(decode_record_frame(&frame), Ok(record));
    }

    /// Короткий хеш стабилен и не печатает секрет целиком.
    #[test]
    fn short_hash_is_prefix_of_sha256() {
        let full = crypto_core::sha256(b"secret");
        let expected: String = full[..6].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(short_hash(b"secret", 6), expected);
        assert_eq!(short_hash(b"secret", 6).len(), 12);
    }

    /// Манифест roundtrip: поля, включая KEM-ek (1184 B) и сертификат, сохраняются.
    #[test]
    fn manifest_roundtrip() {
        let keys = NodeKeys::from_seed([9u8; 32]);
        let cert = vec![0xABu8; 311];
        let path = std::env::temp_dir().join(format!("aether-e2e-manifest-{}.txt", std::process::id()));
        write_manifest(&keys, 2, 4442, &cert, &path).expect("write");
        let manifest = read_manifest(&path).expect("read");
        let _ = std::fs::remove_file(&path);
        assert_eq!(manifest.node_id, 2);
        assert_eq!(manifest.port, 4442);
        let (identity, node_static, kem) = keys.public_part();
        assert_eq!(manifest.identity, identity);
        assert_eq!(manifest.node_static, node_static);
        assert_eq!(manifest.node_static_kem, kem);
        assert_eq!(manifest.node_static_kem.len(), crypto_core::MLKEM768_EK_BYTES);
        assert_eq!(manifest.quic_cert_der, cert);
    }

    /// Кривой манифест (обрезанный) — ошибка, а не частичный разбор.
    #[test]
    fn manifest_rejects_garbage() {
        let path =
            std::env::temp_dir().join(format!("aether-e2e-manifest-bad-{}.txt", std::process::id()));
        std::fs::write(&path, "not a manifest\n").expect("write");
        assert!(read_manifest(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    /// unhex/hex roundtrip и отказ на кривом входе.
    #[test]
    fn unhex_roundtrip() {
        assert_eq!(unhex("00ff10"), Some(vec![0x00, 0xff, 0x10]));
        assert_eq!(unhex("00f"), None, "нечётная длина");
        assert_eq!(unhex("zz"), None, "не hex");
        assert_eq!(hex(&[0x00, 0xff]), "00ff");
        assert!(seed_from_hex(&hex(&[7u8; 32])).is_ok());
        assert!(seed_from_hex(&hex(&[7u8; 31])).is_err());
    }

    /// Клиентские ключи из seed детерминированы, identity pub стабилен.
    #[test]
    fn client_keys_are_deterministic() {
        let a = ClientKeys::from_seed([4u8; 32]);
        let b = ClientKeys::from_seed([4u8; 32]);
        assert_eq!(a.identity_pub(), b.identity_pub());
        assert_ne!(a.static_priv, a.identity_priv);
    }
}
