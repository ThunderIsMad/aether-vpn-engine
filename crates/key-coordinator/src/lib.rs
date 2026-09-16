//! `key-coordinator` — ticket-обёртка и PoP на **клиенте** (`03-components.md` §3).
//!
//! **In:** манифест подписки (только публичные ключи узлов и свои ключи), запросы mint.
//! **Out:** `RESUME` с PoP-подписью, проверка `RESUME_ACK`, re-key события.
//! **Deps:** `crypto-core` — DH, Ed25519-подпись/проверка и выводы ключей. Примитивы
//! (`sid`/`window`) здесь по-прежнему свои: канонический `Seq`/`SessionId` живёт в
//! `frame-session`, связь крейтов в `03` не зафиксирована (QUESTIONS.md Q3).
//!
//! **Impl:** запрашивает mint **у узла** (сам не минтит и `TFK_epoch` не получает);
//! `sig_client` Ed25519 по `client_identity`; post-rotation re-key со свежим DH
//! `HKDF(HKDF-Extract(DH(eph_client, eph_node)) ‖ K_session)` (`02 §3.3`).
//!
//! **Не владеет:** epoch keys, wrap-ключами, состоянием дедупа. Приватный `client_identity`
//! тоже не хранит: подпись — операция по переданному ключу, владелец — `session-store` (`03` §7).
//!
//! Ключевое свойство, которое реализация сохраняет: `RESUME` несёт `sig_client`
//! по `client_auth_pub` из ticket, поэтому украденный ticket без приватного ключа
//! личности резюма не даёт (`02 §3.3`, §3.9).
//!
//! ## Что реализовано в Phase 0 и чего спека не задаёт
//!
//! 1. **Зависимость на `crypto-core` — правка скаффолда.** Скаффолд объявил «Deps: нет»,
//!    но клиенту нужны DH (`ss_rotate`), Ed25519 (PoP) и те же выводы ключей, что в ядре;
//!    вторая копия `HKDF`/`sha2` в соседнем крейте — это ровно то расхождение, которое
//!    потом ловится аудитом. Примитивы (`Seq`/`SessionId`/`Window`) остались своими, как
//!    и требует `03` («Контракты»), а сшивка примитивов — Q3.
//! 2. **Wire-формат `RESUME`/`RESUME_ACK` — Phase 0 решение.** `§3.3` задаёт поля, но не
//!    кадрирование: реализация пишет `kind(1B) ‖ ticket_blob_len(2B) ‖ ticket_blob ‖
//!    nonce(24B) ‖ AEAD{K_resume}(поля)`, где `ticket_blob` идёт **вне** `K_resume`, как и
//!    требует спека.
//! 3. **Nonce для `RESUME`/`RESUME_ACK` спека не задаёт вовсе** — и это опасное место:
//!    один `K_resume` на два сообщения означает, что повтор nonce вскрывает оба. Nonce
//!    собирается как `client_nonce(16B) ‖ метка направления(8B)` (`"resume\x00\x00"` /
//!    `"resumeak"`), поэтому две стороны никогда не используют один nonce дважды.
//!    Вынесено в `QUESTIONS.md`.
//! 4. **NAK на проводе** — `kind(1B) ‖ код(1B)`: `0x02` + `BadPop|Replay|Epoch|Expired`.
//!    Спека называет ветки, но не их представление (`§3.7`).
//! 5. **Проверка `sig_node` — здесь, а не в `frame-session`:** транскрипт `RESUME_ACK`
//!    принадлежит этому крейту (`ResumeError::BadNodeSignature` в контрактах `03`),
//!    а `frame-session` получает уже принятый ACK (`on_resume_ack`).
//!
//! Открытые остатки (в `QUESTIONS.md`): определение `sha256(transcript_client)` из `§3.3`
//! (`transcript_client` = подписанный клиентом `sig_client`-полезная нагрузка — наше прочтение);
//! `last_seq`/`window` клиент передаёт снаружи (их дом — `frame-session`).

#![deny(unsafe_code)]

use crypto_core::{
    derive_k_resume, derive_rotated_session, ed25519_verify, x25519_dh, RecordAead, RecordCrypto,
    KRecord, RecordNonce,
};

/// Идентификатор узла флота (`node_set_id` — набор допустимых узлов).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub u32);

/// Публичный статический ключ X25519 (DH-половина Noise_IK).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X25519Pub(pub [u8; 32]);

/// Публичный ключ Ed25519 (здесь — `node_identity`, которым подписан `RESUME_ACK`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519Pub(pub [u8; 32]);

/// Подпись Ed25519 (64 B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

/// Узел из манифеста подписки: только публичная часть.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Node {
    /// Идентификатор узла.
    pub id: NodeId,
    /// Ключ, которым узел подписывает `RESUME_ACK` (`node_identity`); клиент аутентифицирует узел по нему.
    pub node_identity: Ed25519Pub,
    /// Статик для Noise_IK (`node_static`); предраспределён в манифесте (`02 §5`).
    pub node_static: X25519Pub,
}

/// Непрозрачный ticket, как его выдал узел (`ticket_blob`, ~165 B).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketBlob(pub Vec<u8>);

/// Обёртка над blob — клиент его не разворачивает (`TFK_epoch` у клиента нет).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    /// Байты ticket как есть.
    pub blob: TicketBlob,
}

/// Continuity point, подтверждённый новым узлом (`02 §3.3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Continuity {
    /// Подтверждённый `continuity_point`.
    pub point: u64,
    /// Нижняя граница окна нового узла.
    pub window_lo: u64,
    /// Верхняя граница окна нового узла.
    pub window_hi: u64,
}

/// Ошибка запроса ticket у узла.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintError {
    /// Узел недоступен.
    NodeUnreachable,
    /// Узел отказал (`RESUME_NAK` не относится к mint, но отказ бывает и здесь).
    Rejected,
}

/// Ошибка резюма на стороне клиента (`02 §3.7`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeError {
    /// `RESUME_ACK` не пришёл за `T_ack` = 2 × SRTT, клип [200 ms, 2 s].
    AckTimeout,
    /// `sig_node` неверна → канал не подтверждён, узел в quarantine.
    BadNodeSignature,
    /// Узел отклонил ticket: `bad_pop`, `replay`, `epoch`, `expired`.
    Nacked,
    /// Ответ узла не разбирается (кадрирование/длина).
    Malformed,
}

/// Ошибка пост-ротационного re-key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekeyError {
    /// `eph_node` отсутствует или неверной длины.
    BadEphemeral,
}

/// Отказ канала до узла.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelError {
    /// Узел недоступен.
    Unreachable,
    /// Ответ не пришёл за `T_ack`.
    Timeout,
}

/// Канал до узла: в Phase 0 — мок, в проде — control-стрим поверх outer QUIC (`02 §2.1`).
pub trait RotationChannel {
    /// Отправляет запрос и возвращает ответ узла.
    fn exchange(&mut self, node: NodeId, request: &[u8]) -> Result<Vec<u8>, ChannelError>;
}

/// Метки подписи и направлений (`02 §3.3`).
pub const LABEL_RESUME: &[u8] = b"aether-resume-v3";
/// Метка `sig_node` над `RESUME_ACK` (`02 §3.3`).
pub const LABEL_RESUME_ACK: &[u8] = b"aether-resume-ack-v3";

const KIND_MINT_REQ: u8 = 0x01;
const KIND_RESUME: u8 = 0x02;
const KIND_ACK: u8 = 0x01;
const KIND_NAK: u8 = 0x02;
const NONCE_LABEL_RESUME: [u8; 8] = *b"resume\x00\x00";
const NONCE_LABEL_ACK: [u8; 8] = *b"resumeak";

/// Максимальный ticket, который клиент согласен принять от узла (защита от флуда памяти).
pub const MAX_TICKET_BYTES: usize = 1024;

/// Контекст, который клиент подписывает в `RESUME` (`02 §3.3`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeCtx {
    /// `sha256(ticket_blob)`.
    pub ticket_hash: [u8; 32],
    /// Последний `seq`, который видел клиент.
    pub last_seq: u64,
    /// Клиентское окно дедупа.
    pub window: (u64, u64),
    /// Публичный эфемерный ключ клиента.
    pub eph_client: [u8; 32],
    /// Одноразовый номер попытки.
    pub client_nonce: [u8; 16],
}

/// Полезная нагрузка `sig_client` (`02 §3.3`).
pub fn resume_signing_payload(ctx: &ResumeCtx) -> Vec<u8> {
    let mut msg = Vec::with_capacity(17 + 32 + 8 + 8 + 8 + 32 + 16);
    msg.extend_from_slice(LABEL_RESUME);
    msg.extend_from_slice(&ctx.ticket_hash);
    msg.extend_from_slice(&ctx.last_seq.to_be_bytes());
    msg.extend_from_slice(&ctx.window.0.to_be_bytes());
    msg.extend_from_slice(&ctx.window.1.to_be_bytes());
    msg.extend_from_slice(&ctx.eph_client);
    msg.extend_from_slice(&ctx.client_nonce);
    msg
}

/// Полезная нагрузка `sig_node` (`02 §3.3`):
/// `"aether-resume-ack-v3" ‖ sha256(transcript_client) ‖ continuity_point ‖ window_lo ‖
/// window_hi ‖ eph_node`.
pub fn ack_signing_payload(
    transcript_client_hash: &[u8; 32],
    continuity_point: u64,
    window: (u64, u64),
    eph_node: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(20 + 32 + 8 + 8 + 8 + 32);
    msg.extend_from_slice(LABEL_RESUME_ACK);
    msg.extend_from_slice(transcript_client_hash);
    msg.extend_from_slice(&continuity_point.to_be_bytes());
    msg.extend_from_slice(&window.0.to_be_bytes());
    msg.extend_from_slice(&window.1.to_be_bytes());
    msg.extend_from_slice(eph_node);
    msg
}

/// Nonce сообщения `RESUME`: `client_nonce ‖ "resume\0\0"`.
pub fn resume_nonce(client_nonce: &[u8; 16]) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..16].copy_from_slice(client_nonce);
    nonce[16..].copy_from_slice(&NONCE_LABEL_RESUME);
    nonce
}

/// Nonce сообщения `RESUME_ACK`: `client_nonce ‖ "resumeak"` — отличается от `RESUME`,
/// чтобы один `K_resume` не давал повтор nonce (`02 §3.3` спека не задаёт nonce).
pub fn ack_nonce(client_nonce: &[u8; 16]) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..16].copy_from_slice(client_nonce);
    nonce[16..].copy_from_slice(&NONCE_LABEL_ACK);
    nonce
}

/// Клиентская сторона ротации (`03-components.md`, контракты). **mint здесь нет** —
/// единственный владелец mint — узел (`ticket-mint`); `request_ticket` лишь отправляет
/// запрос и получает blob.
pub trait Rotation {
    /// Запрашивает ticket у узла (сам не минтит, `TFK_epoch` не получает).
    fn request_ticket(&mut self, node: &Node) -> Result<Ticket, MintError>;

    /// Резюмирует сессию на новом узле: `RESUME` с PoP-подписью и свежим `eph_client`.
    fn resume(
        &mut self,
        node: &Node,
        ticket: &Ticket,
        eph: X25519Pub,
    ) -> Result<Continuity, ResumeError>;

    /// Считает `K_session'` из `DH(eph_client, eph_node)` и перезапускает ratchet.
    fn post_rotation_rekey(&mut self, eph_node: &X25519Pub) -> Result<(), RekeyError>;
}

/// Клиентский координатор ротации: `K_resume`, PoP-подпись, проверка `ACK` и re-key.
///
/// Материал, которым подписывается `RESUME` (`client_identity`, `eph_client`, `last_seq`,
/// окно), **инжектируется вызывающим** — иначе трейт `Rotation` из `03` неисполним: в его
/// подписи нет ни приватного ключа личности, ни эфемерной пары, ни состояния дедупа,
/// а PoP без приватного ключа и re-key без приватной половины `eph_client` невозможны.
pub struct ClientRotation<C: RotationChannel> {
    session_id: [u8; 16],
    k_session: [u8; 32],
    client_identity: Option<[u8; 32]>,
    eph_client: Option<([u8; 32], X25519Pub)>,
    last_seq: u64,
    window: (u64, u64),
    k_session_prime: Option<[u8; 32]>,
    confirmed_eph_node: Option<X25519Pub>,
    attempts: u8,
    channel: C,
}

impl<C: RotationChannel> ClientRotation<C> {
    /// Новый координатор поверх канала до узла.
    pub fn new(session_id: [u8; 16], k_session: [u8; 32], channel: C) -> Self {
        Self {
            session_id,
            k_session,
            client_identity: None,
            eph_client: None,
            last_seq: 0,
            window: (0, 0),
            k_session_prime: None,
            confirmed_eph_node: None,
            attempts: 0,
            channel,
        }
    }

    /// Публичная эфемерная половина текущей попытки — её вызывающий передаёт в `resume`.
    pub fn eph_public(&self) -> Option<X25519Pub> {
        self.eph_client.map(|(_, public)| public)
    }

    /// Приватный `client_identity` для PoP-подписи. Владелец ключа — `session-store` (`03` §7):
    /// координатор получает его на время резюма, а не хранит как собственность.
    pub fn set_client_identity(&mut self, identity: [u8; 32]) {
        self.client_identity = Some(identity);
    }

    /// Эфемерная пара попытки: public нужен узлу, private — для `ss_rotate` (`02 §3.3`).
    pub fn set_eph_client(&mut self, private: [u8; 32], public: X25519Pub) {
        self.eph_client = Some((private, public));
    }

    /// Состояние дедупа клиента, попадающее в подпись (`02 §3.3`, `§3.5`);
    /// его дом — `frame-session`, поэтому оно передаётся сюда, а не берётся извне сама собой.
    pub fn set_resume_state(&mut self, last_seq: u64, window: (u64, u64)) {
        self.last_seq = last_seq;
        self.window = window;
    }

    /// `K_resume = HKDF-Expand(HKDF-Extract(salt = session_id, ikm = K_session),
    /// "aether v3 resume", 32)` (`02 §3.3`).
    pub fn k_resume(&self) -> [u8; 32] {
        derive_k_resume(&self.session_id, &crypto_core::KSession(self.k_session))
    }

    /// Сколько попыток `RESUME` сделано (потолок — `02 §3.7`: не более двух ретраев).
    pub fn attempts(&self) -> u8 {
        self.attempts
    }

    /// Пост-ротационный `K_session'`, если re-key состоялся (`02 §3.3`).
    pub fn k_session_prime(&self) -> Option<[u8; 32]> {
        self.k_session_prime
    }

    /// `eph_node`, подтверждённый валидным `RESUME_ACK` — вход re-key.
    pub fn confirmed_eph_node(&self) -> Option<X25519Pub> {
        self.confirmed_eph_node
    }

    /// Собирает `RESUME` (`02 §3.3`): `kind(1B) ‖ len(2B) ‖ ticket_blob ‖ nonce(24B) ‖
    /// AEAD{K_resume}(last_seq ‖ window_lo ‖ window_hi ‖ eph_client ‖ client_nonce ‖ sig_client)`.
    ///
    /// `ticket_blob` летит **вне** `K_resume`, как и требует спека.
    pub fn build_resume(
        &mut self,
        ticket: &Ticket,
        client_nonce: [u8; 16],
    ) -> Result<(Vec<u8>, ResumeCtx), ResumeError> {
        if ticket.blob.0.len() > MAX_TICKET_BYTES {
            return Err(ResumeError::Malformed);
        }
        let identity = self.client_identity.ok_or(ResumeError::Malformed)?;
        let (_, eph_public) = self.eph_client.ok_or(ResumeError::Malformed)?;
        let ctx = ResumeCtx {
            ticket_hash: crypto_core::sha256(&ticket.blob.0),
            last_seq: self.last_seq,
            window: self.window,
            eph_client: eph_public.0,
            client_nonce,
        };
        let signature = crypto_core::ed25519_sign(&identity, &resume_signing_payload(&ctx));

        let mut plain = Vec::with_capacity(72 + 64);
        plain.extend_from_slice(&ctx.last_seq.to_be_bytes());
        plain.extend_from_slice(&ctx.window.0.to_be_bytes());
        plain.extend_from_slice(&ctx.window.1.to_be_bytes());
        plain.extend_from_slice(&ctx.eph_client);
        plain.extend_from_slice(&ctx.client_nonce);
        plain.extend_from_slice(&signature.0);

        let sealed = RecordAead.seal(
            &KRecord(self.k_resume()),
            &RecordNonce(resume_nonce(&client_nonce)),
            &ticket.blob.0,
            &plain,
        );

        let mut request = Vec::with_capacity(3 + ticket.blob.0.len() + sealed.len());
        request.push(KIND_RESUME);
        request.extend_from_slice(&(ticket.blob.0.len() as u16).to_be_bytes());
        request.extend_from_slice(&ticket.blob.0);
        request.extend_from_slice(&sealed);
        Ok((request, ctx))
    }

    /// Разбирает ответ узла: `NAK` → `Nacked`, `ACK` → расшифровка под `K_resume` и проверка
    /// `sig_node` (`02 §3.3`, `§3.7`). Проверка подписи обязательна: без неё скомпрометированный
    /// старый узел подсунул бы свой `eph_node` и сохранил чтение.
    pub fn accept_response(
        &mut self,
        node: &Node,
        request: &[u8],
        response: &[u8],
        ctx: &ResumeCtx,
    ) -> Result<Continuity, ResumeError> {
        let kind = *response.first().ok_or(ResumeError::Malformed)?;
        if kind == KIND_NAK {
            return Err(ResumeError::Nacked);
        }
        let body = response.get(1..).ok_or(ResumeError::Malformed)?;
        let (nonce, sealed) = body.split_at_checked(24).ok_or(ResumeError::Malformed)?;
        let nonce: [u8; 24] = nonce.try_into().map_err(|_| ResumeError::Malformed)?;

        // AAD ответа — сам `RESUME`: спека этого не требует, но без привязки к запросу
        // валидный `ACK` другого резюма был бы неотличим от ответа на этот.
        let plain = RecordAead
            .open(
                &KRecord(self.k_resume()),
                &RecordNonce(nonce),
                request,
                sealed,
            )
            .map_err(|_| ResumeError::BadNodeSignature)?;
        if plain.len() != 8 + 8 + 8 + 32 + 64 {
            return Err(ResumeError::Malformed);
        }
        let continuity_point =
            u64::from_be_bytes(plain[..8].try_into().map_err(|_| ResumeError::Malformed)?);
        let window_lo =
            u64::from_be_bytes(plain[8..16].try_into().map_err(|_| ResumeError::Malformed)?);
        let window_hi =
            u64::from_be_bytes(plain[16..24].try_into().map_err(|_| ResumeError::Malformed)?);
        let eph_node: [u8; 32] = plain[24..56]
            .try_into()
            .map_err(|_| ResumeError::Malformed)?;
        let sig_node = Signature(plain[56..120].try_into().map_err(|_| ResumeError::Malformed)?);

        let transcript_client_hash = crypto_core::sha256(&resume_signing_payload(ctx));
        let payload = ack_signing_payload(
            &transcript_client_hash,
            continuity_point,
            (window_lo, window_hi),
            &eph_node,
        );
        let verified = ed25519_verify(
            &crypto_core::Ed25519Pub(node.node_identity.0),
            &payload,
            &crypto_core::Signature(sig_node.0),
        );
        if !verified {
            return Err(ResumeError::BadNodeSignature);
        }
        self.confirmed_eph_node = Some(X25519Pub(eph_node));
        Ok(Continuity {
            point: continuity_point,
            window_lo,
            window_hi,
        })
    }
}

impl<C: RotationChannel> Rotation for ClientRotation<C> {
    fn request_ticket(&mut self, node: &Node) -> Result<Ticket, MintError> {
        let mut request = Vec::with_capacity(5);
        request.push(KIND_MINT_REQ);
        request.extend_from_slice(&node.id.0.to_be_bytes());
        let response = self
            .channel
            .exchange(node.id, &request)
            .map_err(|_| MintError::NodeUnreachable)?;
        if response.is_empty() || response.len() > MAX_TICKET_BYTES || response[0] == KIND_NAK {
            return Err(MintError::Rejected);
        }
        Ok(Ticket {
            blob: TicketBlob(response),
        })
    }

    fn resume(
        &mut self,
        node: &Node,
        ticket: &Ticket,
        eph: X25519Pub,
    ) -> Result<Continuity, ResumeError> {
        if self.attempts >= 2 {
            // Спека: не более двух ретраев, затем откат на старый канал (`02 §3.7`).
            return Err(ResumeError::AckTimeout);
        }
        match self.eph_client {
            Some((_, public)) if public == eph => {}
            _ => return Err(ResumeError::Malformed),
        }
        self.attempts += 1;
        // Новый `client_nonce` на каждую попытку, ticket тот же (`02 §3.6`).
        let nonce_bytes = crypto_core::random_32();
        let mut client_nonce = [0u8; 16];
        client_nonce.copy_from_slice(&nonce_bytes[..16]);
        let (request, ctx) = self.build_resume(ticket, client_nonce)?;
        let response = self
            .channel
            .exchange(node.id, &request)
            .map_err(|_| ResumeError::AckTimeout)?;
        self.accept_response(node, &request, &response, &ctx)
    }

    fn post_rotation_rekey(&mut self, eph_node: &X25519Pub) -> Result<(), RekeyError> {
        let (private, _) = self.eph_client.ok_or(RekeyError::BadEphemeral)?;
        let shared = x25519_dh(&private, &crypto_core::X25519Pub(eph_node.0))
            .map_err(|_| RekeyError::BadEphemeral)?;
        // Нулевой общий секрет = точка малого порядка: DH не состоялся, re-key запрещён.
        if shared == [0u8; 32] {
            return Err(RekeyError::BadEphemeral);
        }
        self.k_session_prime = Some(
            derive_rotated_session(
                &self.session_id,
                &crypto_core::KSession(self.k_session),
                &shared,
            )
            .0,
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: [u8; 16] = [0x11; 16];
    const K_SESSION: [u8; 32] = [0x22; 32];
    const CLIENT_NONCE: [u8; 16] = [0x33; 16];
    const EPH_NODE: [u8; 32] = [0x77; 32];

    /// Мок-канал: узел, который вскрывает `RESUME` своим `K_resume` и строит `ACK`/`NAK`.
    struct MockNode {
        k_resume: [u8; 32],
        node_identity_priv: [u8; 32],
        corrupt_signature: bool,
        replies: u8,
    }

    impl MockNode {
        fn new(k_resume: [u8; 32], node_identity_priv: [u8; 32], corrupt_signature: bool) -> Self {
            Self {
                k_resume,
                node_identity_priv,
                corrupt_signature,
                replies: 0,
            }
        }
    }

    impl RotationChannel for MockNode {
        fn exchange(&mut self, _node: NodeId, request: &[u8]) -> Result<Vec<u8>, ChannelError> {
            if request[0] == KIND_MINT_REQ {
                return Ok(vec![0xab; 161]);
            }
            self.replies += 1;
            // Разбор RESUME: `kind ‖ len ‖ ticket ‖ nonce ‖ sealed`.
            let len = u16::from_be_bytes([request[1], request[2]]) as usize;
            let ticket = &request[3..3 + len];
            let sealed = &request[3 + len..];
            let mut nonce = [0u8; 24];
            nonce.copy_from_slice(&sealed[..24]);
            let plain = RecordAead
                .open(
                    &KRecord(self.k_resume),
                    &RecordNonce(nonce),
                    ticket,
                    &sealed[24..],
                )
                .map_err(|_| ChannelError::Unreachable)?;

            // Транскрипт клиента = `resume_signing_payload` (`02 §3.3`).
            let mut client_payload = Vec::with_capacity(16 + 32 + 72);
            client_payload.extend_from_slice(LABEL_RESUME);
            client_payload.extend_from_slice(&crypto_core::sha256(ticket));
            client_payload.extend_from_slice(&plain[..72]);
            let transcript_hash = crypto_core::sha256(&client_payload);

            let mut ack_payload = Vec::with_capacity(20 + 32 + 8 + 8 + 8 + 32);
            ack_payload.extend_from_slice(LABEL_RESUME_ACK);
            ack_payload.extend_from_slice(&transcript_hash);
            ack_payload.extend_from_slice(&42u64.to_be_bytes());
            ack_payload.extend_from_slice(&0u64.to_be_bytes());
            ack_payload.extend_from_slice(&42u64.to_be_bytes());
            ack_payload.extend_from_slice(&EPH_NODE);
            let mut signature = crypto_core::ed25519_sign(&self.node_identity_priv, &ack_payload).0;
            if self.corrupt_signature {
                signature[0] ^= 0xff;
            }

            let mut ack_plain = Vec::with_capacity(120);
            ack_plain.extend_from_slice(&42u64.to_be_bytes());
            ack_plain.extend_from_slice(&0u64.to_be_bytes());
            ack_plain.extend_from_slice(&42u64.to_be_bytes());
            ack_plain.extend_from_slice(&EPH_NODE);
            ack_plain.extend_from_slice(&signature);
            let sealed_ack = RecordAead.seal(
                &KRecord(self.k_resume),
                &RecordNonce(ack_nonce(&CLIENT_NONCE)),
                request,
                &ack_plain,
            );
            let mut response = vec![KIND_ACK];
            response.extend_from_slice(&sealed_ack);
            Ok(response)
        }
    }

    fn node(node_pub: crypto_core::Ed25519Pub) -> Node {
        Node {
            id: NodeId(1),
            node_identity: Ed25519Pub(node_pub.0),
            node_static: X25519Pub([0x44; 32]),
        }
    }

    /// Вытаскивает `sig_client` из собранного `RESUME`, чтобы проверить его отдельно.
    fn signature_of(request: &[u8], k_resume: &[u8; 32]) -> crypto_core::Signature {
        let len = u16::from_be_bytes([request[1], request[2]]) as usize;
        let ticket = &request[3..3 + len];
        let sealed = &request[3 + len..];
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&sealed[..24]);
        let plain = RecordAead
            .open(
                &KRecord(*k_resume),
                &RecordNonce(nonce),
                ticket,
                &sealed[24..],
            )
            .expect("RESUME вскрывается под K_resume");
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&plain[72..136]);
        crypto_core::Signature(signature)
    }

    fn coordinator(
        corrupt_signature: bool,
    ) -> (ClientRotation<MockNode>, crypto_core::Ed25519Pub, [u8; 32], crypto_core::Ed25519Pub) {
        let k_resume = derive_k_resume(&SID, &crypto_core::KSession(K_SESSION));
        let (client_pub, client_priv) = crypto_core::ed25519_genkey();
        let (node_pub, node_priv) = crypto_core::ed25519_genkey();
        let (eph_priv, eph_pub) = crypto_core::x25519_genkey().expect("eph_client");
        let mut rotation = ClientRotation::new(
            SID,
            K_SESSION,
            MockNode::new(k_resume, node_priv, corrupt_signature),
        );
        rotation.set_client_identity(client_priv);
        rotation.set_eph_client(eph_priv, X25519Pub(eph_pub));
        rotation.set_resume_state(42, (0, 42));
        (rotation, client_pub, client_priv, node_pub)
    }

    /// Контракт PoP: `RESUME` без валидной `sig_client` не даёт сессии, а сам ticket
    /// не даёт её без приватного `client_identity` (`02 §3.3`, §3.9).
    #[test]
    fn contract_resume_requires_proof_of_possession() {
        let (mut rotation, client_pub, _, node_pub) = coordinator(false);
        let k_resume = rotation.k_resume();
        let target = node(node_pub);
        let ticket = rotation.request_ticket(&target).expect("узел выдал ticket");
        assert_eq!(ticket.blob.0.len(), 161, "blob тот же, что выдал узел");

        let (request, ctx) = rotation
            .build_resume(&ticket, CLIENT_NONCE)
            .expect("RESUME собран");
        assert!(
            request
                .windows(ticket.blob.0.len())
                .any(|w| w == ticket.blob.0),
            "ticket_blob идёт вне K_resume (02 §3.3)"
        );
        assert!(
            crypto_core::ed25519_verify(
                &client_pub,
                &resume_signing_payload(&ctx),
                &signature_of(&request, &k_resume)
            ),
            "sig_client валидна по client_identity"
        );

        // Украденный ticket без приватного ключа личности: та же полезная нагрузка,
        // но подпись чужим ключом — PoP не проходит.
        let (_, attacker_priv) = crypto_core::ed25519_genkey();
        let mut thief = ClientRotation::new(
            SID,
            K_SESSION,
            MockNode::new(k_resume, [0u8; 32], false),
        );
        thief.set_client_identity(attacker_priv);
        thief.set_eph_client([0x55; 32], X25519Pub([0x66; 32]));
        let (thief_request, thief_ctx) = thief
            .build_resume(&ticket, CLIENT_NONCE)
            .expect("RESUME собран");
        assert!(
            !crypto_core::ed25519_verify(
                &client_pub,
                &resume_signing_payload(&thief_ctx),
                &signature_of(&thief_request, &k_resume)
            ),
            "подпись чужого ключа не подтверждается ключом из ticket"
        );
        assert_ne!(thief_ctx.eph_client, ctx.eph_client);

        // Полный путь с корректной парой: ACK принимается, `eph_node` — из проверенного ответа.
        let (mut rotation, _, _, node_pub) = coordinator(false);
        let target = node(node_pub);
        let ticket = rotation.request_ticket(&target).expect("ticket");
        let eph = rotation.eph_public().expect("eph_client установлен");
        let continuity = rotation.resume(&target, &ticket, eph).expect("валидный ACK");
        assert_eq!(continuity.point, 42);
        assert_eq!(continuity.window_hi, 42);
        assert_eq!(rotation.attempts(), 1);
        assert_eq!(rotation.confirmed_eph_node(), Some(X25519Pub(EPH_NODE)));

        // Битый `sig_node` → `BadNodeSignature`, а не `Nacked` (`02 §3.7`).
        let (mut hostile, _, _, node_pub) = coordinator(true);
        let target = node(node_pub);
        let ticket = hostile.request_ticket(&target).expect("ticket");
        let eph = hostile.eph_public().expect("eph_client установлен");
        assert_eq!(
            hostile.resume(&target, &ticket, eph),
            Err(ResumeError::BadNodeSignature)
        );
        assert_eq!(hostile.confirmed_eph_node(), None);

        // Потолок ретраев: третья попытка не делается (`02 §3.7`).
        let (mut capped, _, _, node_pub) = coordinator(false);
        let target = node(node_pub);
        let ticket = capped.request_ticket(&target).expect("ticket");
        let eph = capped.eph_public().expect("eph_client установлен");
        assert!(capped.resume(&target, &ticket, eph).is_ok());
        assert!(capped.resume(&target, &ticket, eph).is_ok());
        assert_eq!(capped.attempts(), 2);
        assert_eq!(
            capped.resume(&target, &ticket, eph),
            Err(ResumeError::AckTimeout)
        );
    }

    /// Контракт re-key: `K_session'` выводится из `DH(eph_client, eph_node)`, поэтому
    /// узел N1 с одним `K_session` пост-ротационный трафик не читает (`02 §3.3`).
    #[test]
    fn contract_post_rotation_rekey_is_fresh_dh() {
        let (mut rotation, _, _, _) = coordinator(false);
        assert!(rotation.k_session_prime().is_none(), "до re-key ключа нет");

        rotation
            .post_rotation_rekey(&X25519Pub(EPH_NODE))
            .expect("DH состоялся");
        let first = rotation.k_session_prime().expect("K_session' посчитан");
        assert_ne!(first, K_SESSION, "K_session' ≠ K_session");

        // Другой `eph_node` даёт другой ключ: значит вывод зависит от ss_rotate.
        rotation
            .post_rotation_rekey(&X25519Pub([0x78; 32]))
            .expect("DH состоялся");
        let second = rotation.k_session_prime().expect("K_session' посчитан");
        assert_ne!(first, second, "re-key — именно свежий DH");

        // Нулевой общий секрет (точка малого порядка) — отказ.
        assert_eq!(
            rotation.post_rotation_rekey(&X25519Pub([0u8; 32])),
            Err(RekeyError::BadEphemeral)
        );

        // Без установленной эфемерной пары re-key невозможен.
        let mut bare = ClientRotation::new(SID, K_SESSION, MockNode::new([0u8; 32], [0u8; 32], false));
        assert_eq!(
            bare.post_rotation_rekey(&X25519Pub(EPH_NODE)),
            Err(RekeyError::BadEphemeral)
        );

        // N1, знающий только `K_session`, того же ключа не выведет: без ss значение другое.
        let without_dh = crypto_core::derive_rotated_session(
            &SID,
            &crypto_core::KSession(K_SESSION),
            &[0u8; 32],
        );
        assert_ne!(without_dh.0, first);
    }
}

