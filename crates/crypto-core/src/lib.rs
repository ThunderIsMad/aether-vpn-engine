//! `crypto-core` — шумовой handshake Noise_IK (гибрид) и seal/open записей.
//!
//! **In:** session-id (владелец — `frame-session`), свой и парный static из манифеста подписки,
//! выбор KEM.
//! **Out:** `K_session`, seal/open записей.
//! **Deps:** `clatter` (Noise PQ, §Noise), `ml-kem` (KAT-векторы FIPS 203),
//! `chacha20poly1305` (XChaCha20-Poly1305 для записей), `x25519-dalek` и `ed25519-dalek`
//! (статические ключи и PoP-подпись). Версии — `DEPENDENCIES.md` → «Phase 0 pins».
//!
//! **Impl (`03-components.md` §2):** Clatter как Noise_IK-гибрид (`02 §5`); constant-time;
//! KEM registry. Путь через `noise-protocol` требует форка: KEM-токенов в абстрактной
//! реализации нет (находка F9 леджера `crate-feasibility`).
//!
//! Тест, который здесь нужен по-настоящему: KAT-векторы ML-KEM-768 (FIPS 203) **и interop
//! против эталона** — у clatter собственное именование PQ-примитивов, поэтому interop
//! обязателен, а не желателен.
//!
//! Паттерн: **Noise_IK**, не XX — статический ключ узла предраспределён в манифесте
//! (`02 §5`): `-> e, es, s, ss; <- e, ee, se`, два сообщения, один RTT.
//!
//! ## Что реализовано в Phase 0 и где реализация разошлась со спекой
//!
//! 1. **Паттерн — `clatter::handshakepattern::noise_hybrid_ik()`** (в clatter 2.3.0 он
//!    существует: `Skem, E, ES, S, SS` / `Ekem, Skem, E, EE, SE`), то есть гибридный IK есть
//!    готовым, а не собирается из утилит модуля (это снимает половину Q4 в `QUESTIONS.md`).
//!    Порядок токенов и байтовые размеры сообщений при этом **не** совпадают с таблицами
//!    `02 §5`: замер — в `contract_noise_ik_two_messages_one_rtt`, расхождение вынесено в
//!    `QUESTIONS.md` как Phase 0 finding (спека не правится без решения дизайна).
//! 2. **`K_session` выводится из handshake-hash, а не из конкатенации сырых DH/KEM-секретов.**
//!    Формула `02 §5` (`ss_ee ‖ ss_es ‖ ss_se ‖ ss_ss ‖ ss_mlkem`) неисполнима поверх clatter:
//!    библиотека смешивает эти секреты внутри симметричного состояния и наружу их не отдаёт.
//!    Наружу отдаётся `SymmetricState::get_hash()` — хеш, в который уже входят все DH- и
//!    KEM-результаты и весь транскрипт. Ключ выводится как
//!    `K_session = HKDF-Extract(salt = session_id, ikm = handshake_hash) → Expand(label, 32)`,
//!    поэтому свойство «держится, пока держит либо X25519, либо ML-KEM» сохраняется, а формула
//!    в спеке — нет. Решение — `QUESTIONS.md` (Phase 0 finding, требует решения дизайна).
//! 3. **Контракт хендшейка исправлен.** Черновой `Handshake::initiate → (msg1, K_session)` был
//!    гипотезой до паттерна и внутренне противоречив: в IK ключа инициатора до `msg2` не
//!    существует. Теперь `initiate()` отдаёт только `msg1`, а ключ — `finish_initiator(msg2)`.
//!    Правка интерфейса записана в `QUESTIONS.md`.
//! 4. **PQ-бэкенд — PQClean, а не RustCrypto** (фича `use-pqclean-ml-kem`): набор
//!    `use-rust-crypto-ml-kem` тянет транзитивный `ml-kem 0.2.1`, который не собирается
//!    (первый прогон CI, `QUESTIONS.md` Q8). Interop-тест ниже проверяет, что PQClean-бэкенд
//!    clatter и RustCrypto `ml-kem 0.3.2` дают одинаковый общий секрет на общих байтах.
//!
//! Открытые остатки (в `QUESTIONS.md`): ACVP KAT-векторы FIPS 203 в дерево не вшиты —
//! вместо них размеры FIPS 203 Table 3 и двунаправленный interop с эталонной реализацией;
//! вопрос static/ephemeral семантики `Skem`/`Ekem` относительно HNDL-клейма `02 §5`.

#![deny(unsafe_code)]

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use clatter::bytearray::{ByteArray, SensitiveByteArray};
use clatter::crypto::cipher::ChaChaPoly;
use clatter::crypto::dh::X25519;
use clatter::crypto::hash::Sha256 as ClatterSha256;
use clatter::crypto::kem::pqclean_ml_kem::MlKem768 as PqMlKem768;
use clatter::crypto::rng::DefaultRng;
use clatter::handshakepattern::noise_hybrid_ik;
use clatter::rand_core::RngCore;
use clatter::traits::{Dh, Handshaker, Kem};
use clatter::{HybridHandshake, HybridHandshakeParams, KeyPair};
use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// Публичный статический ключ X25519 (DH-половина Noise).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X25519Pub(pub [u8; 32]);

/// Публичный ключ Ed25519 (подписи: `node_identity`, `client_identity`, `authority_sign`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519Pub(pub [u8; 32]);

/// Подпись Ed25519 (64 B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

/// Мастер-ключ сессии (`K_session`, 32 B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KSession(pub [u8; 32]);

/// Ключ записи на шаге ratchet `K_record[n] = HKDF(K_record[n-1])`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KRecord(pub [u8; 32]);

/// Nonce записи: `seq(8B) || sid(16B)` — 24 байта, ровно под XChaCha20-Poly1305 (`02 §1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordNonce(pub [u8; 24]);

impl RecordNonce {
    /// Собирает nonce по `02 §1`: `seq` — big-endian 8 B, затем `sid` 16 B.
    pub fn new(seq: u64, session_id: &[u8; 16]) -> Self {
        let mut nonce = [0u8; 24];
        nonce[..8].copy_from_slice(&seq.to_be_bytes());
        nonce[8..].copy_from_slice(session_id);
        Self(nonce)
    }
}

/// Кейс сессии (`02 §8`): гибрид X25519 + ML-KEM-768.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemChoice {
    /// `X25519MLKEM768`: pk = 1184 B, ct = 1088 B, ss = 32 B (FIPS 203, Table 3).
    X25519MlKem768,
}

/// Кейс Phase 0: единственный реализованный — гибрид `X25519 + ML-KEM-768` (`02 §8`).
pub const KEM_CHOICE: KemChoice = KemChoice::X25519MlKem768;

/// ML-KEM-768 encapsulation key, байт (FIPS 203 Table 3; бюджет `e_kem` в `02 §5`).
pub const MLKEM768_EK_BYTES: usize = 1184;
/// ML-KEM-768 ciphertext, байт (FIPS 203 Table 3; бюджет `kem_ct` в `02 §5`).
pub const MLKEM768_CT_BYTES: usize = 1088;
/// ML-KEM-768 shared secret, байт.
pub const MLKEM768_SS_BYTES: usize = 32;
/// Бюджет буфера сообщения handshake. `02 §5` оценивает 1 RTT в ≈2.4 KB; буфер с запасом,
/// потому что точная раскладка сообщений — свойство библиотеки (замер в тестах).
pub const HANDSHAKE_MSG_BUF: usize = 8 * 1024;

/// Метка KDF сессии (`02 §5`).
pub const LABEL_SESSION: &[u8] = b"aether v3 session";
/// Метка KDF `K_resume` (`02 §3.3`).
pub const LABEL_RESUME: &[u8] = b"aether v3 resume";
/// Метка KDF пост-ротационного re-key (`02 §3.3`).
pub const LABEL_ROTATE: &[u8] = b"aether v3 rotate";
/// Метка KDF ratchet записей (`02 §1`).
pub const LABEL_RECORD: &[u8] = b"aether v3 record";

/// Гибридный IK-хендшейк: X25519 + ML-KEM-768 (PQClean-бэкенд), ChaCha20-Poly1305, SHA-256.
pub type HybridIk = HybridHandshake<X25519, PqMlKem768, PqMlKem768, ChaChaPoly, ClatterSha256>;

/// Пара статических DH-ключей в форме clatter (`Dh::PubKey` для X25519 — `[u8; 32]`).
pub type X25519KeyPair = KeyPair<[u8; 32], SensitiveByteArray<[u8; 32]>>;

/// Публичный статический KEM-ключ ML-KEM-768 (`Kem::PubKey`; ассоциированный тип
/// берётся полностью квалифицированно — короткая запись неоднозначна).
pub type MlKem768Pub = <PqMlKem768 as Kem>::PubKey;

/// Пара статических KEM-ключей в форме clatter.
pub type MlKem768KeyPair = KeyPair<MlKem768Pub, <PqMlKem768 as Kem>::SecretKey>;

/// Тип KEM-ошибки.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// Входные данные неверной длины.
    BadLength,
    /// Вскрытие не прошло аутентификацию (AEAD tag).
    OpenFailed,
    /// Handshake не сошёлся (несовместимый кейс, испорченное сообщение, порядок сообщений).
    HandshakeFailed,
}

/// Контракт IK-хендшейка: клиент — инициатор, узел — респондер.
///
/// **Правка чернового контракта скаффолда** (`QUESTIONS.md`): там `initiate` возвращал
/// `(msg1, K_session)`. В IK это невозможно — два сообщения, и ключ инициатора существует
/// только после `msg2`. Поэтому ключ отдаёт отдельный шаг `finish_initiator`.
///
/// Session-id вшивается в `K_session` через salt (владелец — `frame-session`), поэтому
/// инициатор получает его при создании, а не по сети.
pub trait Handshake {
    /// Инициатор (клиент): `msg1` гибридного IK.
    fn initiate(&mut self) -> Result<Vec<u8>, CryptoError>;

    /// Инициатор: обработка `msg2` → `K_session`.
    fn finish_initiator(&mut self, msg2: &[u8]) -> Result<KSession, CryptoError>;

    /// Респондер (узел): разбор `msg1` → (`msg2`, `K_session`).
    fn respond(&mut self, msg1: &[u8]) -> Result<(Vec<u8>, KSession), CryptoError>;
}

/// Инициатор гибридного IK (клиент). Статики узла известны заранее — они приходят из
/// манифеста подписки (`02 §3.1`, `§5`), включая статический KEM-ключ узла, нужный
/// пред-сообщению `S` гибридного паттерна.
pub struct IkInitiator {
    session_id: [u8; 16],
    hs: HybridIk,
}

impl IkInitiator {
    /// Создаёт инициатора: свой `client_static` (DH) и свой статический KEM-ключ, статики узла
    /// из манифеста (`node_static`, `node_static_kem`).
    pub fn new(
        session_id: [u8; 16],
        client_static: X25519KeyPair,
        client_static_kem: MlKem768KeyPair,
        node_static: X25519Pub,
        node_static_kem: MlKem768Pub,
    ) -> Result<Self, CryptoError> {
        let params = HybridHandshakeParams::new(noise_hybrid_ik(), true)
            .with_s(client_static)
            .with_s_kem(client_static_kem)
            .with_rs(node_static.0)
            .with_rs_kem(node_static_kem);
        let hs = HybridIk::new(params).map_err(|_| CryptoError::HandshakeFailed)?;
        Ok(Self { session_id, hs })
    }

    /// Идентификатор сессии, вшитый в вывод ключа.
    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    /// Выводит `K_session` из текущего симметричного состояния (см. п. 2 в шапке модуля).
    fn session_key(&self) -> Result<KSession, CryptoError> {
        if !self.hs.is_finished() {
            return Err(CryptoError::HandshakeFailed);
        }
        let hash = self.hs.get_state().get_hash();
        Ok(derive_session(&self.session_id, ByteArray::as_slice(&hash)))
    }
}

impl Handshake for IkInitiator {
    fn initiate(&mut self) -> Result<Vec<u8>, CryptoError> {
        let mut buf = vec![0u8; HANDSHAKE_MSG_BUF];
        let n = self
            .hs
            .write_message(&[], &mut buf)
            .map_err(|_| CryptoError::HandshakeFailed)?;
        buf.truncate(n);
        Ok(buf)
    }

    fn finish_initiator(&mut self, msg2: &[u8]) -> Result<KSession, CryptoError> {
        let mut buf = vec![0u8; HANDSHAKE_MSG_BUF];
        self.hs
            .read_message(msg2, &mut buf)
            .map_err(|_| CryptoError::HandshakeFailed)?;
        self.session_key()
    }

    fn respond(&mut self, _msg1: &[u8]) -> Result<(Vec<u8>, KSession), CryptoError> {
        // Инициатор не отвечает на `msg1`: контракт двусторонний, но роли не взаимозаменяемы.
        Err(CryptoError::HandshakeFailed)
    }
}

/// Респондер гибридного IK (узел). Держит свой `node_static` (DH) и статический KEM-ключ;
/// авторизация клиента — сравнение `get_remote_static()` с авторизованным набором манифеста
/// (`02 §5`, cryptokey routing), это делается вызывающим кодом, а не этим крейтом.
pub struct IkResponder {
    session_id: [u8; 16],
    node_static: X25519Pub,
    node_static_kem: MlKem768Pub,
    hs: HybridIk,
}

impl IkResponder {
    /// Создаёт респондера: свой `node_static` (DH) и статический KEM-ключ узла.
    pub fn new(
        session_id: [u8; 16],
        node_static: X25519KeyPair,
        node_static_kem: MlKem768KeyPair,
    ) -> Result<Self, CryptoError> {
        let node_static_pub = X25519Pub(node_static.public);
        let kem_pub = node_static_kem.public.clone();
        let params = HybridHandshakeParams::new(noise_hybrid_ik(), false)
            .with_s(node_static)
            .with_s_kem(node_static_kem);
        let hs = HybridIk::new(params).map_err(|_| CryptoError::HandshakeFailed)?;
        Ok(Self {
            session_id,
            node_static: node_static_pub,
            node_static_kem: kem_pub,
            hs,
        })
    }

    /// Публичный `node_static` — то, что уезжает клиенту в манифесте.
    pub fn node_static(&self) -> X25519Pub {
        self.node_static
    }

    /// Публичный статический KEM-ключ узла (нужен инициатору для пред-сообщения `S`).
    pub fn node_static_kem(&self) -> MlKem768Pub {
        self.node_static_kem.clone()
    }

    /// Идентификатор сессии, вшитый в вывод ключа.
    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    fn session_key(&self) -> Result<KSession, CryptoError> {
        if !self.hs.is_finished() {
            return Err(CryptoError::HandshakeFailed);
        }
        let hash = self.hs.get_state().get_hash();
        Ok(derive_session(&self.session_id, ByteArray::as_slice(&hash)))
    }
}

impl Handshake for IkResponder {
    fn initiate(&mut self) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::HandshakeFailed)
    }

    fn finish_initiator(&mut self, _msg2: &[u8]) -> Result<KSession, CryptoError> {
        Err(CryptoError::HandshakeFailed)
    }

    fn respond(&mut self, msg1: &[u8]) -> Result<(Vec<u8>, KSession), CryptoError> {
        let mut buf = vec![0u8; HANDSHAKE_MSG_BUF];
        self.hs
            .read_message(msg1, &mut buf)
            .map_err(|_| CryptoError::HandshakeFailed)?;
        let n = self
            .hs
            .write_message(&[], &mut buf)
            .map_err(|_| CryptoError::HandshakeFailed)?;
        buf.truncate(n);
        let key = self.session_key()?;
        Ok((buf, key))
    }
}

/// Запечатывание/вскрытие записей: XChaCha20-Poly1305 под `K_record` (`02 §1`).
pub struct RecordAead;

impl RecordCrypto for RecordAead {
    fn seal(&self, key: &KRecord, nonce: &RecordNonce, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let cipher = XChaCha20Poly1305::new_from_slice(&key.0)
            .expect("K_record is 32 bytes: XChaCha20-Poly1305 key length");
        cipher
            .encrypt(
                &XNonce::from(nonce.0),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("XChaCha20-Poly1305 seal fails only on message size overflow")
    }

    fn open(
        &self,
        key: &KRecord,
        nonce: &RecordNonce,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let cipher =
            XChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| CryptoError::BadLength)?;
        cipher
            .decrypt(
                &XNonce::from(nonce.0),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::OpenFailed)
    }
}

/// Seal/open записей (`Out:` модуля). Отделено от handshake намеренно: записи живут
/// под ratchet-ключом, а не под `K_session` напрямую (`02 §1`).
pub trait RecordCrypto {
    /// Шифрует plaintext под `K_record` с nonce `seq || sid`.
    fn seal(&self, key: &KRecord, nonce: &RecordNonce, aad: &[u8], plaintext: &[u8]) -> Vec<u8>;

    /// Расшифровывает запись; неверный tag — `OpenFailed`, не паника.
    fn open(
        &self,
        key: &KRecord,
        nonce: &RecordNonce,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}

/// Системный RNG (getrandom через clatter) — для `client_nonce` попыток `RESUME` (`02 §3.6`),
/// эфемерных ключей и nonce записей. Экспортируется, чтобы клиентские крейты не тянули
/// собственный источник случайности.
pub fn random_32() -> [u8; 32] {
    let mut out = [0u8; 32];
    DefaultRng::default().fill_bytes(&mut out);
    out
}

/// sha256 — им адресуется ticket в PoP-транскрипте и подписывается транскрипт `RESUME_ACK`
/// (`02 §3.3`). Экспортируется, чтобы клиентские крейты не тянули свою копию `sha2`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// HKDF-SHA256 в 32 байта: `Extract(salt, ikm)` + `Expand(info, 32)` (`02 §1`, `§3.3`, `§5`).
fn hkdf32(salt: Option<&[u8]>, ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// `K_session`: см. п. 2 в шапке модуля — ikm это handshake-hash, а не конкатенация секретов.
pub fn derive_session(session_id: &[u8; 16], handshake_hash: &[u8]) -> KSession {
    KSession(hkdf32(
        Some(session_id),
        handshake_hash,
        LABEL_SESSION,
    ))
}

/// `K_resume` (`02 §3.3`):
/// `HKDF-Expand(HKDF-Extract(salt = session_id, ikm = K_session), "aether v3 resume", 32)`.
pub fn derive_k_resume(session_id: &[u8; 16], k_session: &KSession) -> [u8; 32] {
    hkdf32(Some(session_id), &k_session.0, LABEL_RESUME)
}

/// Пост-ротационный re-key (`02 §3.3`):
/// `ss_rotate = DH(eph_client_priv, eph_node_pub)`,
/// `K_session' = HKDF-Extract(salt = session_id, ikm = ss_rotate ‖ K_session) → Expand(rotate, 32)`.
pub fn derive_rotated_session(
    session_id: &[u8; 16],
    k_session: &KSession,
    ss_rotate: &[u8; 32],
) -> KSession {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(ss_rotate);
    ikm[32..].copy_from_slice(&k_session.0);
    KSession(hkdf32(Some(session_id), &ikm, LABEL_ROTATE))
}

/// Ratchet записей (`02 §1`): `K_record[n] = HKDF(K_record[n-1])`, шаг 0 — от `K_session`.
pub fn ratchet_record(session_id: &[u8; 16], k_session: &KSession, index: u64) -> KRecord {
    let mut key = hkdf32(Some(session_id), &k_session.0, LABEL_RECORD);
    for _ in 0..index {
        key = hkdf32(Some(session_id), &key, LABEL_RECORD);
    }
    KRecord(key)
}

/// Генерирует пару X25519 (`client_static` / `node_static`) через системный RNG clatter.
pub fn x25519_genkey() -> Result<(X25519Pub, [u8; 32]), CryptoError> {
    let kp = X25519::genkey().map_err(|_| CryptoError::HandshakeFailed)?;
    let mut private = [0u8; 32];
    private.copy_from_slice(kp.secret.as_slice());
    Ok((X25519Pub(kp.public), private))
}

/// Собирает пару X25519 из приватного скаляра — форма, которую ждёт clatter.
pub fn x25519_keypair(private: &[u8; 32]) -> X25519KeyPair {
    let secret = <SensitiveByteArray<[u8; 32]> as ByteArray>::from_slice(private);
    KeyPair::new(X25519::pubkey(&secret), secret)
}

/// `DH(X25519)` — для `ss_rotate = DH(eph_client_priv, eph_node_pub)` (`02 §3.3`).
pub fn x25519_dh(private: &[u8; 32], peer: &X25519Pub) -> Result<[u8; 32], CryptoError> {
    let secret = <SensitiveByteArray<[u8; 32]> as ByteArray>::from_slice(private);
    let out = X25519::dh(&secret, &peer.0).map_err(|_| CryptoError::HandshakeFailed)?;
    let mut ss = [0u8; 32];
    ss.copy_from_slice(out.as_slice());
    Ok(ss)
}

/// Генерирует пару ML-KEM-768 (статик клиента или узла) — PQClean-бэкенд clatter.
pub fn mlkem768_genkey() -> Result<MlKem768KeyPair, CryptoError> {
    PqMlKem768::genkey().map_err(|_| CryptoError::HandshakeFailed)
}

/// Генерирует Ed25519-пару личности (`client_identity` / `node_identity`): (pub, priv).
pub fn ed25519_genkey() -> (Ed25519Pub, [u8; 32]) {
    let mut seed = [0u8; 32];
    DefaultRng::default().fill_bytes(&mut seed);
    let signing = SigningKey::from_bytes(&seed);
    (Ed25519Pub(signing.verifying_key().to_bytes()), seed)
}

/// Публичный ключ по приватному (для записей в манифесте подписки).
pub fn ed25519_pubkey(private: &[u8; 32]) -> Ed25519Pub {
    Ed25519Pub(SigningKey::from_bytes(private).verifying_key().to_bytes())
}

/// Подпись Ed25519 — PoP-подпись `sig_client` (`02 §3.3`) и `sig_node` (`§3.3`).
pub fn ed25519_sign(private: &[u8; 32], message: &[u8]) -> Signature {
    Signature(SigningKey::from_bytes(private).sign(message).to_bytes())
}

/// Проверка Ed25519-подписи. Неверные длина/точка ключа — `false`, а не паника.
pub fn ed25519_verify(public: &Ed25519Pub, message: &[u8], signature: &Signature) -> bool {
    let Ok(verifying) = VerifyingKey::from_bytes(&public.0) else {
        return false;
    };
    let Ok(sig) = DalekSignature::try_from(signature.0.as_slice()) else {
        return false;
    };
    verifying.verify(message, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::kem::{Decapsulate, Encapsulate, Kem as RcKem};
    use ml_kem::{EncapsulationKey768, KeyExport, MlKem768 as RcMlKem768, TryKeyInit};

    /// Контракт FIPS 203: ML-KEM-768 (pk = 1184 B, ct = 1088 B, ss = 32 B) + interop
    /// против эталона, потому что clatter именует PQ-примитивы по-своему.
    ///
    /// Что именно проверяется: размеры FIPS 203 Table 3 на обоих бэкендах и **общий секрет на
    /// общих байтах** в обе стороны — эталон RustCrypto `ml-kem 0.3.2` ⇄ PQClean-бэкенд clatter.
    /// ACVP KAT-векторы в дерево не вшиты (объём); residual — `QUESTIONS.md`.
    #[test]
    fn contract_ml_kem_768_kat_and_interop() {
        // (1) Эталон: размеры FIPS 203 и round-trip на RustCrypto ml-kem.
        let (dk, ek) = RcMlKem768::generate_keypair();
        let ek_bytes = ek.to_bytes();
        assert_eq!(ek_bytes.len(), MLKEM768_EK_BYTES, "FIPS 203: ML-KEM-768 pk");
        let (ct, ss_send) = ek.encapsulate();
        assert_eq!(ct.len(), MLKEM768_CT_BYTES, "FIPS 203: ML-KEM-768 ct");
        let ss_recv = dk.decapsulate(&ct);
        assert_eq!(
            ss_send.as_slice(),
            ss_recv.as_slice(),
            "эталон: encaps/decaps дают один секрет"
        );
        assert_eq!(ss_send.len(), MLKEM768_SS_BYTES, "FIPS 203: ML-KEM-768 ss");

        // (2) Interop A: ciphertext эталона → decapsulate PQClean-бэкендом clatter.
        let pq = mlkem768_genkey().expect("PQClean ML-KEM-768 genkey");
        let ek_from_pq = EncapsulationKey768::new_from_slice(pq.public.as_slice())
            .expect("PQClean pk принимается эталоном");
        let (ct_a, ss_rc_a) = ek_from_pq.encapsulate();
        let ss_pq_a = PqMlKem768::decapsulate(ct_a.as_slice(), pq.secret.as_slice())
            .expect("PQClean decapsulate эталонного ct");
        assert_eq!(
            ss_pq_a.as_slice(),
            ss_rc_a.as_slice(),
            "interop: RustCrypto ct → PQClean ss"
        );

        // (3) Interop B: ciphertext PQClean-бэкенда → decapsulate эталоном.
        let (dk_b, ek_b) = RcMlKem768::generate_keypair();
        let ek_b_bytes = ek_b.to_bytes();
        let mut rng = DefaultRng::default();
        let (ct_b, ss_pq_b) = PqMlKem768::encapsulate(&ek_b_bytes[..], &mut rng)
            .expect("PQClean encapsulate на эталонный pk");
        let ss_rc_b = dk_b
            .decapsulate_slice(ct_b.as_slice())
            .expect("эталон decapsulate PQClean ct");
        assert_eq!(
            ss_pq_b.as_slice(),
            ss_rc_b.as_slice(),
            "interop: PQClean ct → RustCrypto ss"
        );
    }

    /// Контракт Noise_IK: два сообщения, один RTT, клиент аутентифицирует узел по
    /// `node_static` из манифеста; порядок токенов фиксируется в Phase 0.5 (`02 §5`).
    ///
    /// Замер раскладки сообщений печатается тестом: `02 §5` даёт бюджеты
    /// (msg1 = 1264 B, msg2 = 1136 B), а фактический encoding библиотеки проверяется как
    /// нижняя граница — расхождение вынесено в `QUESTIONS.md`, спека не правится.
    #[test]
    fn contract_noise_ik_two_messages_one_rtt() {
        let sid = [0x11u8; 16];
        let (_, node_priv) = x25519_genkey().expect("node static");
        let node_kem = mlkem768_genkey().expect("node static kem");
        let mut responder = IkResponder::new(sid, x25519_keypair(&node_priv), node_kem)
            .expect("responder init");
        let node_static = responder.node_static();
        let node_static_kem = responder.node_static_kem();

        let (_, client_priv) = x25519_genkey().expect("client static");
        let client_kem = mlkem768_genkey().expect("client static kem");
        let mut initiator = IkInitiator::new(
            sid,
            x25519_keypair(&client_priv),
            client_kem,
            node_static,
            node_static_kem,
        )
        .expect("initiator init");

        // Ровно два сообщения: K_session у инициатора появляется только после msg2.
        let msg1 = initiator.initiate().expect("msg1");
        let (msg2, ks_node) = responder.respond(&msg1).expect("msg2");
        let ks_client = initiator.finish_initiator(&msg2).expect("k_session клиента");
        assert_eq!(ks_client, ks_node, "обе стороны выводят один K_session");
        assert_ne!(ks_client.0, [0u8; 32], "K_session не пустой");

        let msg1_len = msg1.len();
        let msg2_len = msg2.len();
        // Точная раскладка пинится равенством, а не только бюджетом: `02 §5` задаёт набор полей,
        // но фактический encoding — свойство библиотеки, и его изменение должно ломать тест,
        // а не проходить молча (Phase 0 finding Q12).
        let measured = (msg1_len, msg2_len);
        assert_eq!(
            measured,
            (0, 0),
            "замер раскладки handshake: вписать точные размеры, полученные в этом прогоне"
        );
        assert!(
            msg1_len >= MLKEM768_EK_BYTES + 32 + 48,
            "msg1 {msg1_len} меньше бюджета 02 §5 (e + e_kem + sealed_s)"
        );
        assert!(
            msg2_len >= MLKEM768_CT_BYTES + 32 + 16,
            "msg2 {msg2_len} меньше бюджета 02 §5 (kem_ct + e + tag)"
        );

        // Испорченный msg2 → HandshakeFailed, а не паника.
        let (_, node_priv2) = x25519_genkey().expect("node static");
        let mut responder2 = IkResponder::new(
            sid,
            x25519_keypair(&node_priv2),
            mlkem768_genkey().expect("node static kem"),
        )
        .expect("responder init");
        let (_, client_priv2) = x25519_genkey().expect("client static");
        let mut initiator2 = IkInitiator::new(
            sid,
            x25519_keypair(&client_priv2),
            mlkem768_genkey().expect("client static kem"),
            responder2.node_static(),
            responder2.node_static_kem(),
        )
        .expect("initiator init");
        let msg1_2 = initiator2.initiate().expect("msg1");
        let (mut msg2_2, _) = responder2.respond(&msg1_2).expect("msg2");
        let last = msg2_2.len() - 1;
        msg2_2[last] ^= 0x01;
        assert_eq!(
            initiator2.finish_initiator(&msg2_2),
            Err(CryptoError::HandshakeFailed),
            "испорченный msg2 обязан отвергаться"
        );
    }

    /// Контракт seal/open: nonce ровно 24 B (`seq || sid`), неверный tag → `OpenFailed`.
    #[test]
    fn contract_record_seal_open() {
        let sid = [0x22u8; 16];
        let session = derive_session(&sid, b"handshake-hash-for-test");
        let key = ratchet_record(&sid, &session, 0);
        let key_next = ratchet_record(&sid, &session, 1);
        assert_ne!(key.0, key_next.0, "ratchet двигает K_record");

        let nonce = RecordNonce::new(7, &sid);
        assert_eq!(nonce.0.len(), 24, "nonce XChaCha20-Poly1305 — 24 B");
        assert_eq!(&nonce.0[..8], &7u64.to_be_bytes(), "nonce: seq(8B) впереди");
        assert_eq!(&nonce.0[8..], &sid, "nonce: sid(16B) следом");

        let aead = RecordAead;
        let plaintext = b"record payload";
        let sealed = aead.seal(&key, &nonce, b"aether v3 record", plaintext);
        assert_eq!(
            sealed.len(),
            plaintext.len() + 16,
            "Poly1305 tag — 16 B"
        );
        assert_eq!(
            aead.open(&key, &nonce, b"aether v3 record", &sealed)
                .expect("свой шифротекст открывается"),
            plaintext
        );

        // Другой AAD, другой ключ и испорченный байт — отказ, не паника.
        assert_eq!(
            aead.open(&key, &nonce, b"other aad", &sealed),
            Err(CryptoError::OpenFailed)
        );
        assert_eq!(
            aead.open(&key_next, &nonce, b"aether v3 record", &sealed),
            Err(CryptoError::OpenFailed)
        );
        let mut damaged = sealed.clone();
        damaged[0] ^= 0xff;
        assert_eq!(
            aead.open(&key, &nonce, b"aether v3 record", &damaged),
            Err(CryptoError::OpenFailed)
        );
    }
}
