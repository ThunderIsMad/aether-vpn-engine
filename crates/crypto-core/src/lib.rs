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
//! Реализации нет: здесь только типы и черновой контракт.

#![deny(unsafe_code)]

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

/// Кейс сессии (`02 §8`): гибрид X25519 + ML-KEM-768.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemChoice {
    /// `X25519MLKEM768`: pk = 1184 B, ct = 1088 B, ss = 32 B (FIPS 203, Table 3).
    X25519MlKem768,
}

/// Тип KEM-ошибки.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// Входные данные неверной длины.
    BadLength,
    /// Вскрытие не прошло аутентификацию (AEAD tag).
    OpenFailed,
    /// Handshake не сошёлся (несовпадение KEM-кейса, испорченный msg).
    HandshakeFailed,
}

/// ЧЕРНОВОЙ контракт: в `03-components.md` трейта нет — форма фиксируется при реализации
/// Phase 0. Гипотеза, которую он выражает: инициатор — клиент, респондер — узел,
/// session-id вшивается в transcript вызывающим (владелец — `frame-session`).
pub trait Handshake {
    /// Инициатор (клиент): `msg1` по Noise_IK с гибридным KEM + `K_session`.
    fn initiate(&mut self, peer_static: &X25519Pub, choice: KemChoice) -> (Vec<u8>, KSession);

    /// Респондер (узел): разбор `msg1`, ответ `msg2` + `K_session`.
    fn respond(&mut self, msg1: &[u8], choice: KemChoice) -> Result<(Vec<u8>, KSession), CryptoError>;
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

#[cfg(test)]
mod tests {
    /// Контракт FIPS 203: ML-KEM-768 (pk = 1184 B, ct = 1088 B, ss = 32 B) + interop
    /// против эталона, потому что clatter именует PQ-примитивы по-своему.
    #[test]
    #[ignore = "контракт Phase 0: тело намеренно todo!() — тест начнёт проходить вместе с реализацией"]
    fn contract_ml_kem_768_kat_and_interop() {
        todo!("Phase 0: KAT-векторы ML-KEM-768 (FIPS 203) + interop с эталоном")
    }

    /// Контракт Noise_IK: два сообщения, один RTT, клиент аутентифицирует узел по
    /// `node_static` из манифеста; порядок токенов фиксируется в Phase 0.5 (`02 §5`).
    #[test]
    #[ignore = "контракт Phase 0: тело намеренно todo!() — тест начнёт проходить вместе с реализацией"]
    fn contract_noise_ik_two_messages_one_rtt() {
        todo!("Phase 0: Noise_IK initiate/respond (02 §5); наличие гибридного IK в clatter — Phase 0.5")
    }

    /// Контракт seal/open: nonce ровно 24 B (`seq || sid`), неверный tag → `OpenFailed`.
    #[test]
    #[ignore = "контракт Phase 0: тело намеренно todo!() — тест начнёт проходить вместе с реализацией"]
    fn contract_record_seal_open() {
        todo!("Phase 0: XChaCha20-Poly1305 seal/open под K_record, nonce = seq || sid")
    }
}
