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
//! 2. **`K_session` выводится из chaining key, а не из конкатенации сырых DH/KEM-секретов**
//!    (Q10 закрыт 2026-09-16, вариант «спека под Clatter»). Поверх clatter формула
//!    `02 §5` (`ss_ee ‖ ss_es ‖ ss_se ‖ ss_ss ‖ ss_mlkem`) неисполнима: библиотека смешивает
//!    секреты внутри симметричного состояния и наружу отдельные `ss_*` не отдаёт — экспорт
//!    ограничен `SymmetricState::get_hash()`, `get_chaining_key()` и `split()`/`finalize()`.
//!    По раскладке токенов (`handshakestate/hybrid.rs`) в handshake-hash (`get_hash`) через
//!    `mix_key_and_hash` попадает только `ss_skem`, поэтому ikm оттуда — не гибрид; гибридный
//!    комбинат — chaining key `c` (`get_chaining_key`): в него `mix_key`-ом сходятся все
//!    DH-секреты (`EE/ES/SS`), `ss_ekem` и `ss_skem`. Итог:
//!    `K_session = HKDF-Extract(salt = session_id, ikm = c) → Expand("aether v3 session", 32)`.
//!    Гибридность «держится, пока держит либо X25519, либо ML-KEM» обеспечивается раскладкой
//!    токенов Clatter (оба класса секретов входят в `c`) и на нашем слое не сверяется —
//!    это внутренность библиотеки; сверка — Phase 0.5 (Q12).
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
//! сверка раскладки токенов гибридного IK (чьи KEM-половины получают инкапсуляцию) — Phase 0.5.

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
use std::fmt;

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
///
/// Debug — ручной redacted, не derive: ключ, который можно напечатать, — утечший ключ.
/// Любой `debug!`/`println!("{:?}")`/паника с этим типом обязана писать `<redacted>`,
/// не байты (аудит F-SEC: derive(Debug) дампил 32 B ключа в любом формате).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KSession(pub [u8; 32]);

impl fmt::Debug for KSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("KSession").field(&"<redacted>").finish()
    }
}

/// Ключ записи на шаге ratchet `K_record[n] = HKDF(K_record[n-1])`.
///
/// Debug — ручной redacted, не derive (см. `KSession`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KRecord(pub [u8; 32]);

impl fmt::Debug for KRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("KRecord").field(&"<redacted>").finish()
    }
}

/// Ключ обложки (`03` §4): выводится из `K_session` с меткой `LABEL_COVER`.
///
/// Debug — ручной redacted, не derive (см. `KSession`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KCover(pub [u8; 32]);

/// Ключ гейта Reality-обложки (`b132-2`, peek-before-decrypt): HMAC-ключ для
/// аутентификации открытого ClientHello **до** терминации TLS. Отдельный слой:
/// компрометация `K_probe` не вскрывает `K_record`/`K_resume`/`K_cover`.
pub struct KProbe(pub [u8; 32]);

impl fmt::Debug for KProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("KProbe").field(&"<redacted>").finish()
    }
}

impl fmt::Debug for KCover {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("KCover").field(&"<redacted>").finish()
    }
}

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
/// Метка KDF ключа обложки (Phase 1, `03` §4): отдельный слой — компрометация обложки
/// не вскрывает session/record ключи.
pub const LABEL_COVER: &[u8] = b"aether v3 cover";
pub const LABEL_PROBE: &[u8] = b"aether v3 reality probe";
/// Метка fleet-ключа гейта Reality (Q24, аудит F-05): выводится из флотского корня
/// (манифеста подписки), а не из `sid`/`K_session` конкретной сессии — bootstrap
/// первого входа (главный сценарий Reality: QUIC заблокирован) и O(1) lookup на сервере.
pub const LABEL_PROBE_FLEET: &[u8] = b"aether v3 reality probe fleet";

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

    /// Выводит `K_session` из текущего симметричного состояния (Q10: ikm — chaining key,
    /// гибридный комбинат Clatter; handshake-hash не годится — в него через
    /// `mix_key_and_hash` попадает только `ss_skem`).
    fn session_key(&self) -> Result<KSession, CryptoError> {
        if !self.hs.is_finished() {
            return Err(CryptoError::HandshakeFailed);
        }
        let ck = self.hs.get_state().get_chaining_key();
        Ok(derive_session(&self.session_id, ByteArray::as_slice(&ck)))
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
        let ck = self.hs.get_state().get_chaining_key();
        Ok(derive_session(&self.session_id, ByteArray::as_slice(&ck)))
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
    DefaultRng.fill_bytes(&mut out);
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

/// HKDF-SHA256 в открытом виде (Phase 1, обложки): salt ‖ ikm ‖ info → 32 B.
/// Публичный, потому что обложки (`cover-*`) выводят свои ключи сами и не должны
/// тянуть внутренние `hkdf32` с семантикой session-слоя.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    hkdf32(Some(salt), ikm, info)
}

/// Ключ обложки из `K_session`: соль — `session_id`, метка — `LABEL_COVER`.
/// Отдельный слой ключей: компрометация ключа обложки не вскрывает `K_record`/`K_resume`.
pub fn derive_cover_key(session_id: &[u8; 16], k_session: &KSession) -> KCover {
    KCover(hkdf32(Some(session_id), &k_session.0, LABEL_COVER))
}

/// Ключ гейта Reality-обложки из `K_session`: соль — `session_id`, метка — `LABEL_PROBE`.
/// Домен отдельен от `K_cover` (`LABEL_PROBE` ≠ `LABEL_COVER`): компрометация/утечка
/// ключа гейта не вскрывает обложку и наоборот.
///
/// Q24 (аудит F-05): сессионный `K_probe` не пригоден для гейта первого входа — у
/// впервые приходящего клиента `K_session` ещё не существует. Гейт Q22 использует
/// `derive_probe_fleet_key`; эта функция остаётся как per-session слой (Phase 2
/// сужение гейта), не используется прод-гейтом.
pub fn derive_probe_key(session_id: &[u8; 16], k_session: &KSession) -> KProbe {
    KProbe(hkdf32(Some(session_id), &k_session.0, LABEL_PROBE))
}

/// Fleet-ключ гейта Reality-обложки (Q24, аудит F-05):
/// `KProbe(HKDF-SHA256(ikm = K_fleet_root, info = LABEL_PROBE_FLEET))`.
///
/// `k_fleet_root` — флотский корневой секрет из манифеста подписки (тот же корень,
/// что выдаёт `client_identity`; отдельный INFO-лейбл — домен отделён от всех
/// существующих слоёв). Клиент и сервер вычисляют ключ **до всякой сессии** из уже
/// доверенного материала — bootstrap первого входа работает, lookup на сервере O(1)
/// (один HMAC × 3 слота окна на ClientHello). Компрометация = компрометация манифеста
/// (существующая threat-модель, не новый класс).
pub fn derive_probe_fleet_key(k_fleet_root: &[u8; 32]) -> KProbe {
    KProbe(hkdf32(None, k_fleet_root, LABEL_PROBE_FLEET))
}

/// HMAC-SHA256-тег `probe_tag`: аутентификация открытого ClientHello гейтом
/// Reality-обложки. Решение peek-before-decrypt принимается **до** ключей TLS,
/// поэтому тег — HMAC (не AEAD): короткий, детерминированный, не требует nonce.
/// `window` — нижняя/верхняя граница допустимого `client_random` (Q21-класс:
/// диапазон, не равенство; анти-replay с окном ~минуты).
pub fn probe_tag(k_probe: &KProbe, client_hello: &[u8], window: (u64, u64)) -> [u8; 24] {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&k_probe.0)
        .expect("HMAC accepts any key length");
    mac.update(client_hello);
    mac.update(&window.0.to_be_bytes());
    mac.update(&window.1.to_be_bytes());
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; 24];
    tag.copy_from_slice(&out[..24]);
    tag
}

/// Constant-time сверка тегов гейта (Q24, аудит F-05): вход — секретный HMAC,
/// сравнение обязано быть постоянным по времени. Реализация — XOR-аккумуляция
/// (24 байта, без ветвлений по данным); crate subtle уже в дереве, но ради
/// трёхстрочной локальной логики отдельная зависимость не нужна.
pub fn tags_equal_ct(a: &[u8; 24], b: &[u8; 24]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// `K_session` (Q10, вариант «спека под Clatter»): ikm — **chaining key** симметричного
/// состояния после msg2 (`SymmetricState::get_chaining_key()`), в который Clatter через
/// `mix_key`/`mix_key_and_hash` сводит все DH- и KEM-секреты; salt — `session_id`
/// (domain separation нашего слоя).
pub fn derive_session(session_id: &[u8; 16], handshake_hash: &[u8]) -> KSession {
    KSession(hkdf32(Some(session_id), handshake_hash, LABEL_SESSION))
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

/// Ключ записи (`02 §1`, аудит F-02 — константный вывод):
/// `K_record[n] = HKDF-SHA256(salt = sid, ikm = K_session, info = LABEL_RECORD ‖ be64(n))`.
///
/// Один шаг HKDF для **произвольного** `n`: приём записи — O(1), а не O(n) итераций
/// (прежняя цепочка давала ~50 мс CPU на запись при seq = 1e5 и жёсткий обрыв на лимите).
/// Свойства: компрометация одного `K_record[n]` не раскрывает ни прошлых, ни будущих
/// членов (цепочки не существует — это строже прежнего ratchet, где утечка текущего
/// члена давала все последующие); компрометация `K_session` раскрывает все члены —
/// периодический re-key и ротация узла остаются средством сужения этого окна.
pub fn derive_record_key(session_id: &[u8; 16], k_session: &KSession, seq: u64) -> KRecord {
    let mut info = Vec::with_capacity(LABEL_RECORD.len() + 8);
    info.extend_from_slice(LABEL_RECORD);
    info.extend_from_slice(&seq.to_be_bytes());
    KRecord(hkdf32(Some(session_id), &k_session.0, &info))
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

/// Сериализация публичного статического KEM-ключа узла для манифеста подписки:
/// `ek` — FIPS 203 encapsulation key, ровно `MLKEM768_EK_BYTES` байт.
pub fn mlkem768_ek_bytes(public: &MlKem768Pub) -> Vec<u8> {
    clatter::bytearray::ByteArray::as_slice(public).to_vec()
}

/// Обратное к `mlkem768_ek_bytes`: сборка `MlKem768Pub` из байтов манифеста.
/// Длина контролируется самим типом; кривой вход — `CryptoError::BadLength`.
pub fn mlkem768_pub_from_bytes(ek: &[u8]) -> Result<MlKem768Pub, CryptoError> {
    if ek.len() != MLKEM768_EK_BYTES {
        return Err(CryptoError::BadLength);
    }
    Ok(clatter::bytearray::ByteArray::from_slice(ek))
}

/// Генерирует Ed25519-пару личности (`client_identity` / `node_identity`): (pub, priv).
pub fn ed25519_genkey() -> (Ed25519Pub, [u8; 32]) {
    let mut seed = [0u8; 32];
    DefaultRng.fill_bytes(&mut seed);
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
        let mut rng = DefaultRng;
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
    /// `node_static` из манифеста; семантика токенов — Phase 0.5 (`02 §5`).
    ///
    /// Замер раскладки сообщений печатается тестом (`println!`) и пинится диапазоном —
    /// бюджеты `§5` снизу, кап 4 КБ/сообщение сверху (Q21), без exact-равенства (аудит Low).
    /// `02 §5` принял замер как ИЗМЕРЕНО
    /// (3568 + 3424 B; Clatter 2.3.0, CI — Q12), раскладка = семантика паттерна `hybridIK`
    #[test]
    fn contract_noise_ik_two_messages_one_rtt() {
        let sid = [0x11u8; 16];
        let (_, node_priv) = x25519_genkey().expect("node static");
        let node_kem = mlkem768_genkey().expect("node static kem");
        let mut responder =
            IkResponder::new(sid, x25519_keypair(&node_priv), node_kem).expect("responder init");
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
        let ks_client = initiator
            .finish_initiator(&msg2)
            .expect("k_session клиента");
        assert_eq!(ks_client, ks_node, "обе стороны выводят один K_session");
        assert_ne!(ks_client.0, [0u8; 32], "K_session не пустой");

        let msg1_len = msg1.len();
        let msg2_len = msg2.len();
        // Замер раскладки (CI, прогон 35064845279): 3568 + 3424 B. Принят в `02 §5` как
        // ИЗМЕРЕНО (Q12): в clatter msg1 несёт `Skem` (статический KEM-ключ, 1184 B) и
        // гибридный `E` (DH + KEM-эфемер), а msg2 — и `Ekem` (ct), и статический KEM-ключ
        // узла. Точное равенство пинить не стали (аудит Low: оно доказывает не больше,
        // чем бюджетные `>=`, и ложнопадает при смене encoding clatter'ом): границы —
        // бюджеты `§5` снизу и кап 4 КБ/сообщение сверху против тихого удвоения размера.
        println!("handshake layout: msg1 = {msg1_len} B, msg2 = {msg2_len} B");
        assert!(
            msg1_len >= MLKEM768_EK_BYTES + 32 + 48,
            "msg1 {msg1_len} меньше бюджета 02 §5 (e + e_kem + sealed_s)"
        );
        assert!(
            msg2_len >= MLKEM768_CT_BYTES + 32 + 16,
            "msg2 {msg2_len} меньше бюджета 02 §5 (kem_ct + e + tag)"
        );
        assert!(
            msg1_len <= 4 * 1024 && msg2_len <= 4 * 1024,
            "сообщение handshake удвоилось: msg1 = {msg1_len}, msg2 = {msg2_len} B \
             (замер 2026-09-16: 3568/3424 — обнови `02 §5` и QUESTIONS Q12)"
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

    /// Точка вывода `K_session` (Q10, вариант «спека под Clatter»): ikm — chaining key
    /// симметричного состояния, не handshake-hash. Свойства: обе стороны выводят один ключ;
    /// ключ зависит от материала (изменение входа меняет вывод); вывод устойчив (зафиксирован
    /// в `QUESTIONS.md` Q10 вместе с формулой). Почему не handshake-hash: по раскладке токенов
    /// Clatter (`handshakestate/hybrid.rs`) в `h` через `mix_key_and_hash` попадает только
    /// `ss_skem` — ikm оттуда не гибридный; в chaining key сходятся все DH- и KEM-секреты.
    /// Вектор не вшивается байтами: ikm — внутреннее состояние библиотеки, наши гарантии —
    /// KDF-обвязка (метки, salt = session_id), она и фиксируется.
    #[test]
    fn contract_k_session_ikm_is_chaining_key() {
        let sid = [0x33u8; 16];
        let (_, node_priv) = x25519_genkey().expect("node static");
        let mut responder = IkResponder::new(
            sid,
            x25519_keypair(&node_priv),
            mlkem768_genkey().expect("node static kem"),
        )
        .expect("responder init");
        let (_, client_priv) = x25519_genkey().expect("client static");
        let mut initiator = IkInitiator::new(
            sid,
            x25519_keypair(&client_priv),
            mlkem768_genkey().expect("client static kem"),
            responder.node_static(),
            responder.node_static_kem(),
        )
        .expect("initiator init");
        let msg1 = initiator.initiate().expect("msg1");
        let (msg2, ks_node) = responder.respond(&msg1).expect("msg2");
        let ks_client = initiator
            .finish_initiator(&msg2)
            .expect("k_session клиента");

        assert_eq!(ks_client, ks_node, "один K_session у обеих сторон");

        // Вывод детерминирован относительно входа KDF: воспроизводим derivation напрямую
        // из отданного clatter секрета (chaining key) той же обвязкой.
        let ck = initiator.hs.get_state().get_chaining_key();
        let replayed = derive_session(&sid, ByteArray::as_slice(&ck));
        assert_eq!(
            replayed, ks_client,
            "K_session воспроизводится из chaining key той же обвязкой"
        );
        assert_ne!(
            derive_session(&[0x35u8; 16], ByteArray::as_slice(&ck)),
            ks_client,
            "salt = session_id входит в вывод (domain separation)"
        );
    }

    /// Контракт гейта Reality (b132-2): `K_probe` — отдельный слой (домен ≠ `LABEL_COVER`,
    /// Debug redacted), `probe_tag` — детерминированный HMAC, чувствительный к любому байту
    /// ClientHello и к окну; верификация — сравнение тегов при тех же входах.
    #[test]
    fn contract_probe_tag_hmac_gate() {
        let sid = [0x5au8; 16];
        let ks = derive_session(&sid, b"probe gate hash");
        let k_probe = derive_probe_key(&sid, &ks);

        // Отдельный слой: K_probe ≠ K_cover при том же входе (domain separation меток).
        let k_cover = derive_cover_key(&sid, &ks);
        assert_ne!(
            k_probe.0, k_cover.0,
            "LABEL_PROBE ≠ LABEL_COVER → разные ключи"
        );
        assert!(
            !format!("{k_probe:?}").contains("90"),
            "Debug KProbe redacted"
        );

        let ch = [0x42u8; 512]; // открытый ClientHello (байты как есть на проводе)
        let window = (1_000u64, 2_000u64);
        let tag = probe_tag(&k_probe, &ch, window);
        assert_eq!(tag, probe_tag(&k_probe, &ch, window), "детерминирован");

        // Чувствительность: любой байт CH, окно или ключ меняют тег целиком.
        let mut ch2 = ch;
        ch2[256] ^= 1;
        assert_ne!(
            tag,
            probe_tag(&k_probe, &ch2, window),
            "байт CH входит в тег"
        );
        assert_ne!(
            tag,
            probe_tag(&k_probe, &ch, (1_001, 2_000)),
            "нижняя граница окна в теге"
        );
        assert_ne!(
            tag,
            probe_tag(&k_probe, &ch, (1_000, 2_001)),
            "верхняя граница окна в теге"
        );
        let other = derive_probe_key(&sid, &derive_session(&sid, b"other"));
        assert_ne!(
            tag,
            probe_tag(&other, &ch, window),
            "чужой ключ → другой тег"
        );

        // Окно: границы входят в тег (см. выше), тег детерминирован — контракт сверки у гейта.
        let ok = |w: (u64, u64)| probe_tag(&k_probe, &ch, w);
        assert_eq!(ok(window), ok(window));
        let (lo, hi) = window;
        assert!(lo < hi, "окно осмысленно");
    }

    /// Q24 (аудит F-05): fleet-ключ гейта выводится из флотского корня ДО всякой сессии.
    /// Детерминированный вектор + домен: fleet-ключ ≠ сессионный `K_probe` ≠ `K_cover`
    /// при том же материале; изменение одного байта корня меняет ключ целиком.
    #[test]
    fn contract_probe_fleet_key_bootstrap_and_domain() {
        let root: [u8; 32] = core::array::from_fn(|i| (i * 3 + 1) as u8);
        let fleet = derive_probe_fleet_key(&root);

        // Детерминированный вектор (фиксация формулы):
        let hex: String = fleet.0.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex, "99738ba50a03b5fa98dc97c3a22591ab3f64a5cacec4eac5d49791a36ef0073b",
            "K_probe_fleet = HKDF-SHA256(ikm=fleet_root, info=LABEL_PROBE_FLEET)"
        );

        // Bootstrap-семантика: ключ не зависит ни от sid, ни от K_session — только от
        // флотского корня, который есть у клиента до первой сессии.
        let sid = [0x11u8; 16];
        let session_probe = derive_probe_key(&sid, &derive_session(&sid, b"any"));
        assert_ne!(
            fleet.0, session_probe.0,
            "fleet-ключ — отдельный слой от сессионного"
        );

        // Домен: тот же корень с другой меткой даёт другой ключ (LABEL_PROBE_FLEET уникален).
        let cover_from_root = hkdf_sha256(&[], &root, LABEL_COVER);
        assert_ne!(fleet.0, cover_from_root);

        // Чувствительность: байт корня — другой ключ.
        let mut root2 = root;
        root2[5] ^= 1;
        assert_ne!(fleet.0, derive_probe_fleet_key(&root2).0);
    }

    /// Q24 (аудит F-05): constant-time сверка тегов гейта — семантика обычного ==
    /// (порог на совпадение/различие), но без memcmp-раннего выхода.
    #[test]
    fn contract_tags_equal_ct_semantics() {
        let a: [u8; 24] = core::array::from_fn(|i| i as u8);
        assert!(tags_equal_ct(&a, &a));
        let mut b = a;
        b[0] ^= 1;
        assert!(!tags_equal_ct(&a, &b));
        let mut c = a;
        c[23] ^= 1; // различие в последнем байте — та же ложь, что и в первом
        assert!(!tags_equal_ct(&a, &c));
        assert!(tags_equal_ct(&[0u8; 24], &[0u8; 24]));
    }

    /// Контракт seal/open: nonce ровно 24 B (`seq || sid`), неверный tag → `OpenFailed`.
    #[test]
    fn contract_record_seal_open() {
        let sid = [0x22u8; 16];
        let session = derive_session(&sid, b"ikm-from-chaining-key");
        let key = derive_record_key(&sid, &session, 0);
        let key_next = derive_record_key(&sid, &session, 1);
        assert_ne!(key.0, key_next.0, "соседние члены K_record различны");
        let key_far = derive_record_key(&sid, &session, 2_000_000);
        assert_ne!(
            key_far.0, key.0,
            "произвольный seq — тот же один шаг HKDF (F-02)"
        );

        let nonce = RecordNonce::new(7, &sid);
        assert_eq!(nonce.0.len(), 24, "nonce XChaCha20-Poly1305 — 24 B");
        assert_eq!(&nonce.0[..8], &7u64.to_be_bytes(), "nonce: seq(8B) впереди");
        assert_eq!(&nonce.0[8..], &sid, "nonce: sid(16B) следом");

        let aead = RecordAead;
        let plaintext = b"record payload";
        let sealed = aead.seal(&key, &nonce, b"aether v3 record", plaintext);
        assert_eq!(sealed.len(), plaintext.len() + 16, "Poly1305 tag — 16 B");
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

    /// Контракт гигиены логов: Debug секретных ключей — ручной redacted, не derive.
    /// Проверяем, что Debug не печатает байты ключа **в любом формате**: ни десятичные
    /// пары (типичный derive для массивов), ни hex — иначе любой `debug!`/паника с
    /// ключом пишут 32 B материала в логи (аудит F-SEC).
    #[test]
    fn contract_secret_keys_debug_is_redacted() {
        const KEY: [u8; 32] = [0xab; 32];
        let session = format!("{:?}", KSession(KEY));
        let record = format!("{:?}", KRecord(KEY));
        let cover = format!("{:?}", KCover(KEY));
        for (printed, name) in [
            (&session, "KSession"),
            (&record, "KRecord"),
            (&cover, "KCover"),
        ] {
            assert!(
                printed.contains("<redacted>"),
                "{name}: Debug помечает ключ как redacted: {printed}"
            );
            assert!(
                !printed.contains("0xab"),
                "{name}: нет hex-дампа: {printed}"
            );
            assert!(
                !printed.contains("171"),
                "{name}: нет десятичного дампа: {printed}"
            );
            assert!(
                !printed.contains("[171"),
                "{name}: нет массивного дампа: {printed}"
            );
            assert!(
                !printed.contains("171, 171"),
                "{name}: нет парного десятичного дампа: {printed}"
            );
        }
    }
}
