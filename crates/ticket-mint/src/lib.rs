//! `ticket-mint` — сторона узла: **единственный владелец mint** (`03-components.md`, контракты).
//!
//! **In:** `sid`, `client_auth_pub` из авторизованного набора манифеста, окно дедупа;
//! `ticket_blob` при `RESUME`; `sig_client` и контекст резюма.
//! **Out:** `ticket_blob`; `TicketPlain` для узла; вердикт по PoP.
//! **Deps:** `chacha20poly1305` (AEAD тикета, `02 §3.2`), `ed25519-dalek` (PoP, `§3.3`),
//! `sha2` (ключ consumed-set `epoch_id ‖ sha256(ticket_blob)`, `§3.6`). Ключ флота
//! `TFK_epoch` приходит снаружи (владелец — узел, `02 §3.1`).
//!
//! Почему mint у узла, а не у клиента: если клиент получает `TFK_epoch`, он минтит tickets
//! сам, и containment эпохи вместе с PoP обходятся (`02 §3.1`). Клиентский крейт
//! `key-coordinator` умеет только `request_ticket`.
//!
//! Состояние узла (`02 §3.5`, §3.6): окно дедупа 4096 записей и **in-memory**
//! consumed-ticket set на эпоху. Набор теряется при рестарте узла — принято сознательно;
//! правило вытеснения набора ещё не определено (QUESTIONS.md Q1).
//!
//! ## Что реализовано в Phase 0 и где реализация разошлась со спекой
//!
//! 1. **Nonce тикета — 24 B, а не 12.** `§3.2` пишет `nonce(12 B) ‖ AEAD_XChaCha20Poly1305`,
//!    но XChaCha20-Poly1305 принимает 24-байтовый nonce (12 B — это у ChaCha20-Poly1305), а
//!    крипто-набор проекта — X-вариант (`§8`: записи тоже XChaCha20-Poly1305). Взят X-вариант:
//!    размер blob получается `24 + 121 + 16 = 161 B`, тогда как `§3.2` оценивает «≈165 B».
//!    Оба расхождения — в `QUESTIONS.md` (Phase 0 findings), а не «поправлены в спеке».
//! 2. **Контракт `TicketMint` исправлен дважды.** `mint` в скаффолде принимал только `sid`,
//!    `client_auth_pub` и окно — то есть не имел ни `K_session`, которым наполняется ticket,
//!    ни времени, по которому выставляются `minted_at`/`exp` (`§3.2`), ни способа вернуть
//!    ошибку. Добавлены `k_session` в параметры и явные `mint_at`/`unwrap_at` с временем;
//!    трейт делегирует к ним через инжектированный `now` (`set_now`).
//! 3. **Подпись проверяется вместе с привязкой к blob.** `verify_pop` сам по себе проверяет
//!    подпись над `ctx.ticket_hash`, но не может убедиться, что хеш принадлежит **предъявленному**
//!    билету. Поэтому решение по резюму вынесено в `handle_resume`, который сперва сверяет
//!    `ctx.ticket_hash == sha256(blob)`: иначе подпись, выданная для другого билета, прошла бы
//!    проверку PoP.
//! 4. **`k_session_wrapped: Vec<u8>` → `k_session: [u8; 32]`.** Поле всегда 32 байта
//!    (`§3.1`), `Vec` здесь только добавлял неоднозначность длины; отдельного wrap-слоя нет —
//!    `K_session` защищён AEAD самого тикета, то есть ровно тем `TFK_epoch`, который объявлен
//!    флотским (`§3.2`).
//! 5. **Nonce тикета — случайный, не выводится из открытого текста.** Изначальный
//!    `sha256(plain)[..24]` делал AEAD детерминированным: повторный mint с тем же plain
//!    давал байт-идентичный blob и коллизию в consumed-set. Исправлено на CSPRNG
//!    (`getrandom`) — см. `QUESTIONS.md`, закрытие аудита.

#![deny(unsafe_code)]

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;

/// Идентификатор сессии (`sid`).
///
/// Дублирует `frame_session::SessionId` сознательно: крейт стороны узла не тянет
/// клиентские типы. Свести их в один — решение Phase 0 (см. QUESTIONS.md Q3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; 16]);

/// Публичный ключ Ed25519 клиента (`client_auth_pub` из ticket) — им проверяется PoP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519Pub(pub [u8; 32]);

/// Подпись Ed25519 (64 B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

/// Окно дедупа на момент минта (`window_lo`/`window_hi`); текущее окно клиент присылает
/// в `RESUME` и покрывает своей подписью (`02 §3.3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    /// Нижняя граница на момент минта: `last_seq − 4096`.
    pub lo: u64,
    /// Верхняя граница на момент минта: `last_seq`.
    pub hi: u64,
}

/// Непрозрачный для клиента ticket (~165 B).
#[derive(Clone, PartialEq, Eq)]
pub struct TicketBlob(pub Vec<u8>);

impl fmt::Debug for TicketBlob {
    /// Байты blob — шифротекст под `TFK_epoch`, но печатаем только длину: привычка
    /// дампить содержимое билета в логи недопустима уже на этапе отладки.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TicketBlob")
            .field(&format_args!("{} bytes", self.0.len()))
            .finish()
    }
}

/// Версия формата ticket (`02 §3.2`, поле `version`).
pub const TICKET_VERSION: u8 = 3;
/// Размер nonce тикета: XChaCha20-Poly1305 берёт 24 B (см. п. 1 в шапке модуля).
pub const TICKET_NONCE_BYTES: usize = 24;
/// Размер открытого текста тикета (`§3.2`, сумма полей).
pub const TICKET_PLAINTEXT_BYTES: usize = 1 + 16 + 4 + 4 + 8 + 8 + 32 + 32 + 8 + 8;
/// Размер blob: nonce ‖ AEAD(plaintext) с 16-байтовым тегом (`§3.2`).
pub const TICKET_BLOB_BYTES: usize = TICKET_NONCE_BYTES + TICKET_PLAINTEXT_BYTES + 16;

/// Метка подписи PoP (`02 §3.3`).
pub const LABEL_RESUME: &[u8] = b"aether-resume-v3";

/// Развёрнутый ticket: то, что видит только узел после unwrap флотским ключом.
#[derive(Clone, PartialEq, Eq)]
pub struct TicketPlain {
    /// Идентификатор сессии.
    pub sid: SessionId,
    /// Ключ сессии. Защищён AEAD тикета (`TFK_epoch`), отдельного wrap-слоя нет (`§3.2`).
    pub k_session: [u8; 32],
    /// Ключ клиента для проверки PoP.
    pub client_auth: Ed25519Pub,
    /// Пол окна на момент минта.
    pub window: Window,
    /// Идентификатор эпохи флотского ключа.
    pub epoch_id: u32,
    /// Идентификатор набора узлов (`node_set_id`, из манифеста).
    pub node_set_id: u32,
    /// Момент минта (unix-секунды).
    pub minted_at: u64,
    /// Срок годности ticket.
    pub exp: u64,
}

impl fmt::Debug for TicketPlain {
    /// Ручной Debug вместо derive: `k_session` — секрет и не печатается никогда;
    /// nonce открытого текста (sid/ключи/окно) сводится к идентификаторам.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TicketPlain")
            .field("sid", &self.sid)
            .field("k_session", &"<redacted>")
            .field("client_auth", &self.client_auth)
            .field("window", &self.window)
            .field("epoch_id", &self.epoch_id)
            .field("node_set_id", &self.node_set_id)
            .field("minted_at", &self.minted_at)
            .field("exp", &self.exp)
            .finish()
    }
}

/// Контекст резюма, который клиент подписывает (`02 §3.3`, `sig_client`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeCtx {
    /// Хеш `ticket_blob`.
    pub ticket_hash: [u8; 32],
    /// Последний `seq`, который видел клиент.
    pub last_seq: u64,
    /// Клиентское окно дедупа.
    pub window: Window,
    /// Публичный эфемерный ключ клиента (`eph_client`).
    pub eph_client: [u8; 32],
    /// Одноразовый номер.
    pub client_nonce: [u8; 16],
}

/// Сообщение, которое подписывает клиент (`02 §3.3`):
/// `"aether-resume-v3" ‖ sha256(ticket_blob) ‖ last_seq ‖ window_lo ‖ window_hi ‖ eph_client
/// ‖ client_nonce`.
pub fn resume_signing_payload(ctx: &ResumeCtx) -> Vec<u8> {
    let mut msg = Vec::with_capacity(LABEL_RESUME.len() + 32 + 8 + 8 + 8 + 32 + 16);
    msg.extend_from_slice(LABEL_RESUME);
    msg.extend_from_slice(&ctx.ticket_hash);
    msg.extend_from_slice(&ctx.last_seq.to_be_bytes());
    msg.extend_from_slice(&ctx.window.lo.to_be_bytes());
    msg.extend_from_slice(&ctx.window.hi.to_be_bytes());
    msg.extend_from_slice(&ctx.eph_client);
    msg.extend_from_slice(&ctx.client_nonce);
    msg
}

/// sha256 — им адресуется ticket в PoP-транскрипте и в consumed-set (`§3.3`, `§3.6`).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Ключ consumed-set эпохи: `epoch_id ‖ sha256(ticket_blob)` (`02 §3.6`).
pub fn consumed_key(epoch_id: u32, blob: &TicketBlob) -> Vec<u8> {
    let mut key = Vec::with_capacity(4 + 32);
    key.extend_from_slice(&epoch_id.to_be_bytes());
    key.extend_from_slice(&sha256(&blob.0));
    key
}

/// Ошибка разбора ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketError {
    /// AEAD не вскрылся флотским ключом.
    BadWrap,
    /// `epoch_id` не совпал с текущей эпохой.
    EpochMismatch,
    /// `exp` истёк.
    Expired,
    /// Поля открытого текста не сходятся по длине или версии.
    BadLayout,
}

/// Вердикт узла по `RESUME` (`02 §3.7`) — ровно те ветки, которые называет спека,
/// плюс «не наш/битый blob» как drop, а не NAK (спека предполагает разбираемый ticket).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeVerdict {
    /// Резюм принят: ticket развёрнут, PoP проверен, ticket консумирован.
    Accept {
        /// Развёрнутый ticket.
        ticket: TicketPlain,
        /// `last_seq` ниже пола из ticket — аномалия, но окно принимается от клиента (`§3.7`).
        anomaly: bool,
    },
    /// Подпись клиента неверна: ticket **не** консумируется (`§3.7`).
    NakBadPop,
    /// Повтор ticket на том же узле (`§3.6`, `§3.7`).
    NakReplay,
    /// `epoch_id` не совпал → фолбэк на полный IK-handshake (`§3.7`, `§5`).
    NakEpoch,
    /// `exp` истёк → фолбэк на полный handshake (`§3.7`).
    NakExpired,
    /// Blob не разбирается нашим `TFK_epoch`/версией: это не NAK, а drop.
    Drop,
}

/// Сторона узла (`03-components.md`, контракты; находка #29: единственный владелец mint).
pub trait TicketMint {
    /// Выдаёт ticket по запросу клиента: `sid` + его `client_auth_pub` + пол окна + `K_session`.
    ///
    /// `k_session` добавлен к черновой подписи скаффолда: без ключа сессии ticket
    /// нечем наполнить, и «успешный» mint отдавал бы билет, которым нельзя резюмировать.
    /// Время берётся из инжектированного `now` (`set_now`), а не из параметра: трейт
    /// контракта остаётся без часов, а спека требует `minted_at`/`exp` (`§3.2`).
    fn mint(
        &self,
        sid: SessionId,
        client_auth: Ed25519Pub,
        window: Window,
        k_session: &[u8; 32],
    ) -> TicketBlob;

    /// Разворачивает ticket флотским `TFK_epoch`.
    fn unwrap_ticket(&self, blob: &TicketBlob) -> Result<TicketPlain, TicketError>;

    /// Проверяет PoP-подпись клиента по `client_auth_pub` из ticket.
    fn verify_pop(&self, ticket: &TicketPlain, sig: &Signature, ctx: &ResumeCtx) -> bool;
}

/// Узел-минтер: флотский ключ эпохи, набор узлов, TTL тикета и consumed-set эпохи.
///
/// Часы инжектируются (`now`), потому что в контракте скаффолда их не было, а спека требует
/// и `minted_at`, и проверку `exp`; детерминированный `now` делает тесты воспроизводимыми.
pub struct TicketFactory {
    tfk_epoch: [u8; 32],
    epoch_id: u32,
    node_set_id: u32,
    ttl_seconds: u64,
    now: u64,
    consumed: HashSet<Vec<u8>>,
}

impl TicketFactory {
    /// Новый минтер эпохи: `TFK_epoch`, `epoch_id`, `node_set_id`, TTL тикета.
    pub fn new(tfk_epoch: [u8; 32], epoch_id: u32, node_set_id: u32, ttl_seconds: u64) -> Self {
        Self {
            tfk_epoch,
            epoch_id,
            node_set_id,
            ttl_seconds,
            now: 0,
            consumed: HashSet::new(),
        }
    }

    /// Эпоха минитера.
    pub fn epoch_id(&self) -> u32 {
        self.epoch_id
    }

    /// Устанавливает «текущее время» для трейтовых вызовов без явного `now`.
    pub fn set_now(&mut self, now: u64) {
        self.now = now;
    }

    /// Сколько tickets консумировано в этой эпохе (набор in-memory, `§3.6`).
    pub fn consumed_len(&self) -> usize {
        self.consumed.len()
    }

    /// Mint с явным временем (`§3.2`). Nonce — 24 B из системного CSPRNG (`getrandom`):
    /// AEAD обязан быть probabilistic — детерминированный `sha256(plain)`-nonce давал
    /// байт-идентичный blob при повторном mint (одинаковые входы в одну секунду), что
    /// коллизировало `consumed_key` и сжигало легитимный второй билет как replay
    /// (аудит F-SEC, High). Blob остаётся самодостаточным: nonce лежит в заголовке.
    pub fn mint_at(
        &self,
        sid: SessionId,
        client_auth: Ed25519Pub,
        window: Window,
        k_session: &[u8; 32],
        minted_at: u64,
    ) -> TicketBlob {
        let mut plain = Vec::with_capacity(TICKET_PLAINTEXT_BYTES);
        plain.push(TICKET_VERSION);
        plain.extend_from_slice(&sid.0);
        plain.extend_from_slice(&self.node_set_id.to_be_bytes());
        plain.extend_from_slice(&self.epoch_id.to_be_bytes());
        plain.extend_from_slice(&minted_at.to_be_bytes());
        plain.extend_from_slice(&minted_at.saturating_add(self.ttl_seconds).to_be_bytes());
        plain.extend_from_slice(k_session);
        plain.extend_from_slice(&client_auth.0);
        plain.extend_from_slice(&window.lo.to_be_bytes());
        plain.extend_from_slice(&window.hi.to_be_bytes());
        debug_assert_eq!(plain.len(), TICKET_PLAINTEXT_BYTES);

        // Случайный nonce из системного CSPRNG: XChaCha20-Poly1305 остаётся probabilistic.
        // `expect` допустим: единственная ошибка `getrandom::fill` — системный RNG
        // недоступен, и тогда узлу нет безопасного способа минтить билет вовсе.
        let mut nonce = [0u8; TICKET_NONCE_BYTES];
        getrandom::fill(&mut nonce)
            .expect("system CSPRNG unavailable: cannot mint a ticket securely");
        let cipher = XChaCha20Poly1305::new_from_slice(&self.tfk_epoch)
            .expect("TFK_epoch is 32 bytes: XChaCha20-Poly1305 key length");
        let sealed = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plain,
                    aad: &[],
                },
            )
            .expect("XChaCha20-Poly1305 seal fails only on message size overflow");

        let mut blob = Vec::with_capacity(nonce.len() + sealed.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&sealed);
        TicketBlob(blob)
    }

    /// Unwrap с явным временем: проверяет эпоху и `exp` (`§3.2`, `§3.7`).
    pub fn unwrap_at(&self, blob: &TicketBlob, now: u64) -> Result<TicketPlain, TicketError> {
        if blob.0.len() != TICKET_BLOB_BYTES {
            return Err(TicketError::BadWrap);
        }
        let (nonce, sealed) = blob.0.split_at(TICKET_NONCE_BYTES);
        let cipher =
            XChaCha20Poly1305::new_from_slice(&self.tfk_epoch).map_err(|_| TicketError::BadWrap)?;
        let plain = cipher
            .decrypt(
                &XNonce::from(
                    <[u8; TICKET_NONCE_BYTES]>::try_from(nonce)
                        .map_err(|_| TicketError::BadWrap)?,
                ),
                Payload {
                    msg: sealed,
                    aad: &[],
                },
            )
            .map_err(|_| TicketError::BadWrap)?;
        if plain.len() != TICKET_PLAINTEXT_BYTES || plain[0] != TICKET_VERSION {
            return Err(TicketError::BadLayout);
        }
        let mut cursor = 1usize;
        let sid = SessionId(take_array::<16>(&plain, &mut cursor)?);
        let node_set_id = u32::from_be_bytes(take_array::<4>(&plain, &mut cursor)?);
        let epoch_id = u32::from_be_bytes(take_array::<4>(&plain, &mut cursor)?);
        let minted_at = u64::from_be_bytes(take_array::<8>(&plain, &mut cursor)?);
        let exp = u64::from_be_bytes(take_array::<8>(&plain, &mut cursor)?);
        let k_session = take_array::<32>(&plain, &mut cursor)?;
        let client_auth = Ed25519Pub(take_array::<32>(&plain, &mut cursor)?);
        let lo = u64::from_be_bytes(take_array::<8>(&plain, &mut cursor)?);
        let hi = u64::from_be_bytes(take_array::<8>(&plain, &mut cursor)?);

        if epoch_id != self.epoch_id {
            return Err(TicketError::EpochMismatch);
        }
        if now >= exp {
            return Err(TicketError::Expired);
        }
        Ok(TicketPlain {
            sid,
            k_session,
            client_auth,
            window: Window { lo, hi },
            epoch_id,
            node_set_id,
            minted_at,
            exp,
        })
    }

    /// Полный разбор `RESUME` на стороне узла: unwrap → consumed-set → PoP → консумирование.
    ///
    /// Порядок веток — `§3.7`; ticket консумируется **только** при `Accept`, поэтому неверная
    /// подпись не «съедает» билет и легитимный резюм после неё проходит.
    pub fn handle_resume(
        &mut self,
        blob: &TicketBlob,
        sig: &Signature,
        ctx: &ResumeCtx,
        now: u64,
    ) -> ResumeVerdict {
        let ticket = match self.unwrap_at(blob, now) {
            Ok(ticket) => ticket,
            Err(TicketError::EpochMismatch) => return ResumeVerdict::NakEpoch,
            Err(TicketError::Expired) => return ResumeVerdict::NakExpired,
            Err(TicketError::BadWrap | TicketError::BadLayout) => return ResumeVerdict::Drop,
        };
        let key = consumed_key(self.epoch_id, blob);
        if self.consumed.contains(&key) {
            return ResumeVerdict::NakReplay;
        }
        // Подпись покрывает sha256(ticket_blob): сверяем, что предъявлен именно тот билет,
        // для которого подпись выдана (`§3.3`).
        if ctx.ticket_hash != sha256(&blob.0) || !self.verify_pop(&ticket, sig, ctx) {
            return ResumeVerdict::NakBadPop;
        }
        let anomaly = ctx.last_seq < ticket.window.lo;
        self.consumed.insert(key);
        ResumeVerdict::Accept { ticket, anomaly }
    }
}

fn take_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], TicketError> {
    let end = cursor.checked_add(N).ok_or(TicketError::BadLayout)?;
    let slice = bytes.get(*cursor..end).ok_or(TicketError::BadLayout)?;
    let array = <[u8; N]>::try_from(slice).map_err(|_| TicketError::BadLayout)?;
    *cursor = end;
    Ok(array)
}

impl TicketMint for TicketFactory {
    fn mint(
        &self,
        sid: SessionId,
        client_auth: Ed25519Pub,
        window: Window,
        k_session: &[u8; 32],
    ) -> TicketBlob {
        self.mint_at(sid, client_auth, window, k_session, self.now)
    }

    fn unwrap_ticket(&self, blob: &TicketBlob) -> Result<TicketPlain, TicketError> {
        self.unwrap_at(blob, self.now)
    }

    fn verify_pop(&self, ticket: &TicketPlain, sig: &Signature, ctx: &ResumeCtx) -> bool {
        let Ok(verifying) = VerifyingKey::from_bytes(&ticket.client_auth.0) else {
            return false;
        };
        let Ok(signature) = DalekSignature::try_from(sig.0.as_slice()) else {
            return false;
        };
        verifying
            .verify(&resume_signing_payload(ctx), &signature)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const TFK: [u8; 32] = [0x11; 32];
    const SID: SessionId = SessionId([0x22; 16]);
    const K_SESSION: [u8; 32] = [0x33; 32];

    fn identity(seed: u8) -> (SigningKey, Ed25519Pub) {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let public = Ed25519Pub(signing.verifying_key().to_bytes());
        (signing, public)
    }

    fn context(blob: &TicketBlob, identity: &SigningKey) -> (Signature, ResumeCtx) {
        let ctx = ResumeCtx {
            ticket_hash: sha256(&blob.0),
            last_seq: 41,
            window: Window { lo: 41, hi: 41 },
            eph_client: [0x44; 32],
            client_nonce: [0x55; 16],
        };
        let sig = Signature(identity.sign(&resume_signing_payload(&ctx)).to_bytes());
        (sig, ctx)
    }

    /// Контракт mint: клиент не минтит сам; ticket привязан к `client_auth_pub`
    /// и содержит пол окна на момент минта (`02 §3.1`, §3.3).
    #[test]
    fn contract_mint_binds_client_pub_and_window() {
        let factory = TicketFactory::new(TFK, 7, 3, 3_600);
        let (_, client_pub) = identity(0xaa);
        let window = Window { lo: 100, hi: 4_196 };
        let blob = factory.mint_at(SID, client_pub, window, &K_SESSION, 1_000);

        assert_eq!(
            blob.0.len(),
            TICKET_BLOB_BYTES,
            "blob = nonce(24) + plaintext(121) + tag(16)"
        );
        assert_eq!(TICKET_BLOB_BYTES, 161);
        assert_eq!(TICKET_PLAINTEXT_BYTES, 121);

        let ticket = factory
            .unwrap_at(&blob, 1_100)
            .expect("свой ticket разворачивается");
        assert_eq!(ticket.sid, SID);
        assert_eq!(
            ticket.client_auth, client_pub,
            "ticket привязан к ключу клиента"
        );
        assert_eq!(ticket.window, window, "пол окна — на момент минта");
        assert_eq!(ticket.epoch_id, 7);
        assert_eq!(ticket.node_set_id, 3);
        assert_eq!(ticket.minted_at, 1_000);
        assert_eq!(ticket.exp, 4_600, "TTL применён");
        assert_eq!(&ticket.k_session, &K_SESSION);

        // Чужая эпоха и чужой флотский ключ не разворачивают ticket: mint требует `TFK_epoch`.
        let other_epoch = TicketFactory::new(TFK, 8, 3, 3_600);
        assert_eq!(
            other_epoch.unwrap_at(&blob, 1_100),
            Err(TicketError::EpochMismatch)
        );
        let other_fleet = TicketFactory::new([0x99; 32], 7, 3, 3_600);
        assert_eq!(
            other_fleet.unwrap_at(&blob, 1_100),
            Err(TicketError::BadWrap)
        );

        // `exp` истёк (`§3.7`) и обрезанный blob — отказ, не паника.
        assert_eq!(factory.unwrap_at(&blob, 4_600), Err(TicketError::Expired));
        let short = TicketBlob(blob.0[..20].to_vec());
        assert_eq!(factory.unwrap_at(&short, 1_100), Err(TicketError::BadWrap));
        let mut corrupted = blob.clone();
        let last = corrupted.0.len() - 1;
        corrupted.0[last] ^= 0x01;
        assert_eq!(
            factory.unwrap_at(&corrupted, 1_100),
            Err(TicketError::BadWrap)
        );
    }

    /// AEAD тикета probabilistic: повторный mint с теми же входами (в т.ч. в одну
    /// секунду детерминированных часов) обязан давать другой blob — иначе consumed_key
    /// (`epoch ‖ sha256(blob)`) коллизирует и второй легитимный билет сразу NakReplay
    /// (аудит: детерминированный nonce). Debug-редакция: `k_session` не печатается.
    #[test]
    fn contract_mint_is_probabilistic_and_debug_redacted() {
        let factory = TicketFactory::new(TFK, 7, 3, 3_600);
        let (_, client_pub) = identity(0xaa);
        let window = Window { lo: 0, hi: 0 };

        let a = factory.mint_at(SID, client_pub, window, &K_SESSION, 1_000);
        let b = factory.mint_at(SID, client_pub, window, &K_SESSION, 1_000);
        assert_ne!(
            a, b,
            "два mint с одним plain — разные blob (случайный nonce)"
        );
        // Оба разворачиваются и дают одинаковый plain: случайность — только в nonce.
        let ta = factory.unwrap_at(&a, 1_100).expect("unwrap a");
        let tb = factory.unwrap_at(&b, 1_100).expect("unwrap b");
        assert_eq!(ta.k_session, tb.k_session);
        assert_eq!(ta.sid, tb.sid);

        // Debug не печатает ни байта ключа: ни hex-пар, ни десятичных последовательностей.
        let plain_debug = format!("{:?}", ta);
        assert!(
            plain_debug.contains("<redacted>"),
            "k_session redacted: {plain_debug}"
        );
        assert!(
            !plain_debug.contains("51, 51"),
            "десятичный дамп k_session отсутствует"
        );
        assert!(
            !plain_debug.contains("0x33"),
            "hex-дамп k_session отсутствует"
        );
        let blob_debug = format!("{:?}", a);
        assert!(
            !blob_debug.contains("160"),
            "blob печатает только длину: {blob_debug}"
        );
    }

    /// Контракт PoP: подделка или отсутствие `sig_client` → отказ, ticket не консумируется;
    /// повтор того же ticket на том же узле → `RESUME_NAK replay` (consumed-set эпохи).
    #[test]
    fn contract_pop_and_replay_rejection() {
        let mut factory = TicketFactory::new(TFK, 7, 3, 3_600);
        let (client, client_pub) = identity(0xaa);
        let (attacker, _) = identity(0xbb);
        let window = Window { lo: 0, hi: 0 };
        let blob = factory.mint_at(SID, client_pub, window, &K_SESSION, 1_000);

        // Украденный ticket без приватного ключа личности: подпись чужим ключом.
        let (bad_sig, ctx) = context(&blob, &attacker);
        assert_eq!(
            factory.handle_resume(&blob, &bad_sig, &ctx, 1_100),
            ResumeVerdict::NakBadPop
        );
        assert_eq!(
            factory.consumed_len(),
            0,
            "bad_pop не консумирует ticket (02 §3.7)"
        );

        // Подпись, выданная для другого билета: hash в контексте не сходится с blob.
        let (good_sig, good_ctx) = context(&blob, &client);
        let mut wrong_ctx = good_ctx.clone();
        wrong_ctx.ticket_hash = sha256(b"another ticket");
        assert_eq!(
            factory.handle_resume(&blob, &good_sig, &wrong_ctx, 1_100),
            ResumeVerdict::NakBadPop
        );
        assert_eq!(factory.consumed_len(), 0);

        // Легитимный резюм проходит и консумирует ticket.
        match factory.handle_resume(&blob, &good_sig, &good_ctx, 1_100) {
            ResumeVerdict::Accept { ticket, anomaly } => {
                assert_eq!(ticket.sid, SID);
                assert!(!anomaly, "last_seq не ниже пола из ticket");
            }
            verdict => panic!("ожидался Accept, получено {verdict:?}"),
        }
        assert_eq!(
            factory.consumed_len(),
            1,
            "ticket консумирован ровно один раз"
        );

        // Повтор того же ticket на том же узле → replay, второй сессии нет (`§3.6`).
        assert_eq!(
            factory.handle_resume(&blob, &good_sig, &good_ctx, 1_200),
            ResumeVerdict::NakReplay
        );
        assert_eq!(factory.consumed_len(), 1);

        // `last_seq` ниже пола из ticket — аномалия, но резюм принимается (`§3.7`).
        let (client2, pub2) = identity(0xcc);
        let blob2 = factory.mint_at(SID, pub2, Window { lo: 500, hi: 500 }, &K_SESSION, 1_300);
        // `last_seq` ниже пола из ticket: подпись считается уже по аномальному контексту,
        // иначе узел ответил бы `bad_pop`, а не принял аномалию.
        let ctx2 = ResumeCtx {
            ticket_hash: sha256(&blob2.0),
            last_seq: 10,
            window: Window { lo: 500, hi: 500 },
            eph_client: [0x44; 32],
            client_nonce: [0x55; 16],
        };
        let sig2 = Signature(client2.sign(&resume_signing_payload(&ctx2)).to_bytes());
        match factory.handle_resume(&blob2, &sig2, &ctx2, 1_400) {
            ResumeVerdict::Accept { anomaly, .. } => assert!(anomaly),
            verdict => panic!("ожидался Accept с аномалией, получено {verdict:?}"),
        }

        // Ветки epoch/expired и «не наш blob» (`§3.7`).
        let mut foreign = TicketFactory::new(TFK, 9, 3, 3_600);
        let (sig3, ctx3) = context(&blob2, &client2);
        assert_eq!(
            foreign.handle_resume(&blob2, &sig3, &ctx3, 1_400),
            ResumeVerdict::NakEpoch
        );
        let (sig4, ctx4) = context(&blob2, &client2);
        assert_eq!(
            factory.handle_resume(&blob2, &sig4, &ctx4, 10_000),
            ResumeVerdict::NakExpired
        );
        assert_eq!(
            factory.handle_resume(&TicketBlob(vec![0x00; 8]), &sig4, &ctx4, 1_400),
            ResumeVerdict::Drop
        );
    }

    /// Трейтовый путь (`TicketMint`) делегирует к явным `mint_at`/`unwrap_at`
    /// и использует инжектированное время, поэтому `exp` проверяется по нему.
    #[test]
    fn contract_trait_path_uses_injected_clock() {
        let (_, client_pub) = identity(0xdd);
        let mut factory = TicketFactory::new(TFK, 1, 1, 60);
        factory.set_now(500);
        let blob = TicketMint::mint(
            &factory,
            SID,
            client_pub,
            Window { lo: 0, hi: 0 },
            &K_SESSION,
        );
        assert!(TicketMint::unwrap_ticket(&factory, &blob).is_ok());
        factory.set_now(600);
        assert_eq!(
            TicketMint::unwrap_ticket(&factory, &blob),
            Err(TicketError::Expired),
            "TTL 60 s от minted_at=500 истёк к 600"
        );
    }
}
