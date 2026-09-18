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
//!    требует спека. Nonce стоит в открытом виде — иначе он оказался бы *внутри* того
//!    шифротекста, который им же и вскрывается (спека перечисляет `client_nonce` среди
//!    запечатанных полей и про nonce AEAD не говорит ничего).
//! 3. **Nonce для `RESUME`/`RESUME_ACK` спека не задаёт вовсе** — и это опасное место:
//!    один `K_resume` на два сообщения означает, что повтор nonce вскрывает оба. Nonce
//!    собирается как `client_nonce(16B) ‖ метка направления(8B)` (`"resume\x00\x00"` /
//!    `"resumeak"`), поэтому две стороны никогда не используют один nonce дважды.
//!    Вынесено в `QUESTIONS.md`. Клиент при этом не берёт nonce ACK с провода на веру:
//!    принимается только `nonce == ack_nonce(&ctx.client_nonce)`, иначе `Malformed` —
//!    nonce с провода не доверенный вход (закрытие аудита F-CORR).
//! 4. **NAK на проводе** — `kind(1B) ‖ код(1B)`: `0x02` + `BadPop|Replay|Epoch|Expired`.
//!    Спека называет ветки, но не их представление (`§3.7`). Детекция — по фрейму целиком
//!    (`len == 2` **и** `kind == 0x02`), не по первому байту сырого ответа: первый байт
//!    легитимного ticket/blob — данные, а не маркер отказа (аудит F-CORR: heuristic давал
//!    ложные отказы с p ≈ 1/256 на mint-пути).
//! 5. **Проверка `sig_node` — здесь, а не в `frame-session`:** транскрипт `RESUME_ACK`
//!    принадлежит этому крейту (`ResumeError::BadNodeSignature` в контрактах `03`),
//!    а `frame-session` получает уже принятый ACK (`on_resume_ack`).
//! 6. **Классификация отказов ACK:** AEAD-open failure — `Malformed` (битый шифротекст /
//!    не тот ключ — это corruption, а не доказательство подделки); `BadNodeSignature` —
//!    только вердикт `ed25519_verify` при вскрывшемся AEAD. Иначе честный узел уходил бы
//!    в quarantine из-за случайной порчи кадра (аудит F-CORR).
//!
//! Открытые остатки (в `QUESTIONS.md`): определение `sha256(transcript_client)` из `§3.3`
//! (`transcript_client` = подписанный клиентом `sig_client`-полезная нагрузка — наше прочтение);
//! `last_seq`/`window` клиент передаёт снаружи (их дом — `frame-session`).

#![deny(unsafe_code)]

use crypto_core::{
    derive_k_resume, derive_rotated_session, ed25519_sign, ed25519_verify, x25519_dh, KRecord,
    RecordAead, RecordCrypto, RecordNonce,
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

/// Полный принятый `RESUME_ACK` (`02 §3.3`) — все поля, которые клиент проверил.
///
/// Выделен из `Continuity` сознательно: `Continuity` — это «продолжение сессии»
/// (граница окна), а `AcceptedAck` — доказательство, на котором оно построено.
/// Frame-слою нужны оба (`on_resume_ack`), и брать их надо из одного типа, а не из двух
/// половин, одну из которых (`sig_node`) до Q17 вообще никто не отдавал.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedAck {
    /// Подтверждённый `continuity_point`.
    pub continuity_point: u64,
    /// Нижняя граница окна нового узла.
    pub window_lo: u64,
    /// Верхняя граница окна нового узла.
    pub window_hi: u64,
    /// `eph_node` из `RESUME_ACK` — вход пост-ротационного re-key (`02 §3.3`).
    pub eph_node: X25519Pub,
    /// `sig_node`, которой узел подписал ACK (проверена здесь, хранится для полноты).
    pub sig_node: Signature,
}

/// Continuity point, подтверждённый новым узлом (`02 §3.3`).
///
/// Несёт **все поля `RESUME_ACK`** (`eph_node`, `sig_node` добавлены по Q17): раньше
/// здесь была только граница окна, и вызывающему коду пришлось бы вскрывать AEAD ответа
/// самому, чтобы дотащить `sig_node`/`eph_node` до `frame-session::on_resume_ack`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Continuity {
    /// Подтверждённый `continuity_point`.
    pub point: u64,
    /// Нижняя граница окна нового узла.
    pub window_lo: u64,
    /// Верхняя граница окна нового узла.
    pub window_hi: u64,
    /// `eph_node` из принятого ACK — вход `post_rotation_rekey` (`02 §3.3`).
    pub eph_node: X25519Pub,
    /// `sig_node`, которой узел подписал ACK (проверена, хранится для полноты записи).
    pub sig_node: Signature,
}

impl From<AcceptedAck> for Continuity {
    fn from(ack: AcceptedAck) -> Self {
        Self {
            point: ack.continuity_point,
            window_lo: ack.window_lo,
            window_hi: ack.window_hi,
            eph_node: ack.eph_node,
            sig_node: ack.sig_node,
        }
    }
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
    /// Узел отклонил ticket с причиной (`F-06`): код-байт NAK-кадра разбирается, а не
    /// отбрасывается — клиент обязан различать `Epoch`/`Expired` (фолбэк на полный
    /// IK-handshake) и `Replay`/`BadPop` (rollback на старый канал / телеметрия).
    Nacked(ResumeNak),
    /// Ответ узла не разбирается (кадрирование/длина/неизвестный код NAK).
    Malformed,
}

/// Причина `RESUME_NAK` на проводе (`02 §3.7`, F-06). Коды зафиксированы в спеке §3.7;
/// прод-эмиттер — `build_resume_nak`, прод-парсер — `accept_response` (единые, как и
/// для ACK — прецедент BLOCKER-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeNak {
    /// `sig_client` неверна: ticket не консумируется, инцидент в телеметрию узла.
    BadPop,
    /// Повтор ticket на том же узле (`consumed-set` эпохи, `02 §3.6`).
    Replay,
    /// `epoch_id` не совпал → фолбэк: полный IK-handshake (`02 §5`).
    Epoch,
    /// `exp` истёк → фолбэк: полный handshake.
    Expired,
}

impl ResumeNak {
    /// Код-байт NAK-кадра (`02 §3.7`).
    pub fn code(self) -> u8 {
        match self {
            ResumeNak::BadPop => NAK_BAD_POP,
            ResumeNak::Replay => NAK_REPLAY,
            ResumeNak::Epoch => NAK_EPOCH,
            ResumeNak::Expired => NAK_EXPIRED,
        }
    }

    /// Обратное к `code`; неизвестный код — `None` (парсер → `Malformed`).
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            NAK_BAD_POP => Some(ResumeNak::BadPop),
            NAK_REPLAY => Some(ResumeNak::Replay),
            NAK_EPOCH => Some(ResumeNak::Epoch),
            NAK_EXPIRED => Some(ResumeNak::Expired),
            _ => None,
        }
    }

    /// Требует ли ветка фолбэка на полный IK-handshake (`02 §3.7`).
    pub fn requires_full_handshake(self) -> bool {
        matches!(self, ResumeNak::Epoch | ResumeNak::Expired)
    }
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

/// Коды причин `RESUME_NAK` (`02 §3.7`, F-06). Единственный источник правды —
/// `ResumeNak::code`/`from_code` здесь; эмиттеры обязаны звать `build_resume_nak`.
pub const NAK_BAD_POP: u8 = 0x01;
pub const NAK_REPLAY: u8 = 0x02;
pub const NAK_EPOCH: u8 = 0x03;
pub const NAK_EXPIRED: u8 = 0x04;

const NONCE_LABEL_RESUME: [u8; 8] = *b"resume\x00\x00";
const NONCE_LABEL_ACK: [u8; 8] = *b"resumeak";

/// Максимальный ticket, который клиент согласен принять от узла (защита от флуда памяти).
pub const MAX_TICKET_BYTES: usize = 1024;

/// Всего попыток `RESUME` на один ticket: первая + одна повторная (`02 §3.7`, Q18).
pub const MAX_RESUME_ATTEMPTS: u8 = 2;

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

/// Собирает `RESUME_NAK` на узловой стороне (`02 §3.7`, F-06) — единственный прод-эмиттер
/// NAK-кадра. Раньше ветки отказов дублировались литералами `vec![0x02, 0xFF]` в
/// `e2e-harness` и спектральными кодами в моке `rotation-tests` (три источника правды,
/// код-байт терялся). Парсер зеркальной стороны — `ClientRotation::accept_response`.
///
/// Провод: `kind(0x02) ‖ код причины(1B)` (`§3.7`: BadPop=1, Replay=2, Epoch=3, Expired=4).
/// AAD/шифрования нет — NAK не несёт секрета, только причину отказа (как и раньше).
pub fn build_resume_nak(reason: ResumeNak) -> Vec<u8> {
    vec![KIND_NAK, reason.code()]
}

/// Собирает `RESUME_ACK` на узловой стороне (`02 §3.3`) — единственный прод-эмиттер ACK-кадра
/// (BLOCKER-2, `QUESTIONS.md`); раньше этот layout дублировался в моках `rotation-tests`
/// и в `e2e-harness`. Парсер зеркальной стороны — `ClientRotation::accept_response`.
///
/// Провод: `kind(0x01) ‖ nonce(24B, открытый) ‖ AEAD{K_resume}(ack_plain)`, AAD — сам `RESUME`;
/// **`len`-поля нет** — решение по BLOCKER-2 в `QUESTIONS.md` (вариант A). `ack_plain =
/// continuity_point(8) ‖ window_lo(8) ‖ window_hi(8) ‖ eph_node(32) ‖ sig_node(64)`;
/// `sig_node` — Ed25519 `node_identity` над `"aether-resume-ack-v3" ‖ sha256(transcript_client)
/// ‖ continuity_point ‖ window_lo ‖ window_hi ‖ eph_node`.
///
/// Аргументы: `k_resume` — из ticket (узел получил при unwrap), `request` — байты `RESUME`
/// (AAD), `client_resume_ctx` — контекст клиента из RESUME (нужен для транскрипта подписи),
/// `node_window` — окно дедупа, посчитанное узлом (`02 §3.5`), `eph_node` — публичный
/// эфемерный ключ узла этой попытки, `node_identity_priv` — ключ подписи `sig_node`.
#[allow(clippy::too_many_arguments)]
pub fn build_resume_ack(
    k_resume: [u8; 32],
    request: &[u8],
    client_nonce: &[u8; 16],
    client_resume_ctx: &ResumeCtx,
    node_window: (u64, u64),
    eph_node: &X25519Pub,
    node_identity_priv: &[u8; 32],
) -> Vec<u8> {
    let transcript = crypto_core::sha256(&resume_signing_payload(client_resume_ctx));
    let payload = ack_signing_payload(
        &transcript,
        client_resume_ctx.last_seq,
        node_window,
        &eph_node.0,
    );
    let sig_node = ed25519_sign(node_identity_priv, &payload);

    let mut ack_plain = Vec::with_capacity(8 + 8 + 8 + 32 + 64);
    ack_plain.extend_from_slice(&client_resume_ctx.last_seq.to_be_bytes());
    ack_plain.extend_from_slice(&node_window.0.to_be_bytes());
    ack_plain.extend_from_slice(&node_window.1.to_be_bytes());
    ack_plain.extend_from_slice(&eph_node.0);
    ack_plain.extend_from_slice(&sig_node.0);

    let nonce = ack_nonce(client_nonce);
    let sealed = RecordAead.seal(&KRecord(k_resume), &RecordNonce(nonce), request, &ack_plain);
    let mut out = Vec::with_capacity(1 + 24 + sealed.len());
    out.push(KIND_ACK);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    out
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
    accepted_ack: Option<AcceptedAck>,
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
            accepted_ack: None,
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

    /// Сколько попыток `RESUME` **дошло до сети** (потолок — `02 §3.7`, Q18: первая плюс
    /// одна повторная). Локальные `Malformed` (нет identity/eph, пустой/битый ticket)
    /// бюджет не расходуют (аудит F-CORR).
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

    /// Полный принятый `RESUME_ACK` — все поля `02 §3.3` из одного типа (Q17).
    pub fn confirmed_ack(&self) -> Option<AcceptedAck> {
        self.accepted_ack
    }

    /// Собирает `RESUME` (`02 §3.3`): `kind(1B) ‖ len(2B) ‖ ticket_blob ‖ nonce(24B) ‖
    /// AEAD{K_resume}(last_seq ‖ window_lo ‖ window_hi ‖ eph_client ‖ client_nonce ‖ sig_client)`.
    ///
    /// `ticket_blob` летит **вне** `K_resume`, как и требует спека. Пустой blob — тоже
    /// `Malformed`: узел такой RESUME всё равно отбросит, тратить попытку и запрос
    /// нерационально (аудит F-CORR: раньше отклонялся только `len > 1024`).
    pub fn build_resume(
        &mut self,
        ticket: &Ticket,
        client_nonce: [u8; 16],
    ) -> Result<(Vec<u8>, ResumeCtx), ResumeError> {
        if ticket.blob.0.is_empty() || ticket.blob.0.len() > MAX_TICKET_BYTES {
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

        let mut request = Vec::with_capacity(3 + ticket.blob.0.len() + 24 + sealed.len());
        request.push(KIND_RESUME);
        request.extend_from_slice(&(ticket.blob.0.len() as u16).to_be_bytes());
        request.extend_from_slice(&ticket.blob.0);
        request.extend_from_slice(&resume_nonce(&client_nonce));
        request.extend_from_slice(&sealed);
        Ok((request, ctx))
    }

    /// Разбирает ответ узла: NAK-фрейм (`len == 2` и `kind == 0x02`) → `Nacked`; иначе
    /// `ACK` (`kind == 0x01`) — расшифровка под `K_resume` и проверка `sig_node`
    /// (`02 §3.3`, `§3.7`). Проверка подписи обязательна: без неё скомпрометированный
    /// старый узел подсунул бы свой `eph_node` и сохранил чтение.
    ///
    /// Классификация отказов (закрытие аудита F-CORR):
    /// * nonce ответа обязан равняться `ack_nonce(&ctx.client_nonce)` — nonce с провода
    ///   не доверенный вход, mismatch → `Malformed`;
    /// * AEAD-open failure → `Malformed` (corruption, не доказательство подделки);
    ///   `BadNodeSignature` — только вердикт `ed25519_verify` при вскрывшемся AEAD;
    /// * всё, что не NAK-фрейм и не ACK (в т. ч. одинокий байт `0x02`), — `Malformed`.
    pub fn accept_response(
        &mut self,
        node: &Node,
        request: &[u8],
        response: &[u8],
        ctx: &ResumeCtx,
    ) -> Result<Continuity, ResumeError> {
        let kind = *response.first().ok_or(ResumeError::Malformed)?;
        // NAK детектируется фреймом целиком (`len == 2 && kind == 0x02`): первый байт
        // длинного ответа — данные, а не маркер отказа (аудит F-CORR). Код-байт разбирается
        // (F-06): причина нужна клиенту для ветки `§3.7`; неизвестный код — `Malformed`.
        if response.len() == 2 && kind == KIND_NAK {
            let reason = ResumeNak::from_code(response[1]).ok_or(ResumeError::Malformed)?;
            return Err(ResumeError::Nacked(reason));
        }
        if kind != KIND_ACK {
            return Err(ResumeError::Malformed);
        }
        let body = response.get(1..).ok_or(ResumeError::Malformed)?;
        let (nonce, sealed) = body.split_at_checked(24).ok_or(ResumeError::Malformed)?;
        let nonce: [u8; 24] = nonce.try_into().map_err(|_| ResumeError::Malformed)?;
        // Nonce ACK — не с провода, а выведенный из собственной попытки: AAD уже привязывает
        // ответ к запросу, а повтор nonce под одним `K_resume` вскрывал бы и RESUME, и ACK —
        // поэтому допускается ровно `ack_nonce(client_nonce)` (аудит F-CORR).
        if nonce != ack_nonce(&ctx.client_nonce) {
            return Err(ResumeError::Malformed);
        }

        // AAD ответа — сам `RESUME`: спека этого не требует, но без привязки к запросу
        // валидный `ACK` другого резюма был бы неотличим от ответа на этот.
        // AEAD-open failure — corruption (битый шифротекст, не тот ключ), а не подделка:
        // честный узел не должен уходить в quarantine из-за порчи кадра — `Malformed`.
        // `BadNodeSignature` — только вердикт `ed25519_verify` ниже (аудит F-CORR).
        let plain = RecordAead
            .open(
                &KRecord(self.k_resume()),
                &RecordNonce(nonce),
                request,
                sealed,
            )
            .map_err(|_| ResumeError::Malformed)?;
        if plain.len() != 8 + 8 + 8 + 32 + 64 {
            return Err(ResumeError::Malformed);
        }
        let continuity_point =
            u64::from_be_bytes(plain[..8].try_into().map_err(|_| ResumeError::Malformed)?);
        let window_lo = u64::from_be_bytes(
            plain[8..16]
                .try_into()
                .map_err(|_| ResumeError::Malformed)?,
        );
        let window_hi = u64::from_be_bytes(
            plain[16..24]
                .try_into()
                .map_err(|_| ResumeError::Malformed)?,
        );
        let eph_node: [u8; 32] = plain[24..56]
            .try_into()
            .map_err(|_| ResumeError::Malformed)?;
        let sig_node = Signature(
            plain[56..120]
                .try_into()
                .map_err(|_| ResumeError::Malformed)?,
        );

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
        let accepted = AcceptedAck {
            continuity_point,
            window_lo,
            window_hi,
            eph_node: X25519Pub(eph_node),
            sig_node,
        };
        self.confirmed_eph_node = Some(accepted.eph_node);
        self.accepted_ack = Some(accepted);
        Ok(Continuity::from(accepted))
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
        // NAK фреймится distinctly (`len == 2 && kind == 0x02`): легитимный ticket начинается
        // со случайного nonce AEAD, и heuristic «первый байт == 0x02» давал ложный `Rejected`
        // с p ≈ 1/256 (аудит F-CORR).
        if response.len() == 2 && response.first() == Some(&KIND_NAK) {
            return Err(MintError::Rejected);
        }
        if response.is_empty() || response.len() > MAX_TICKET_BYTES {
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
        if self.attempts >= MAX_RESUME_ATTEMPTS {
            // Спека: не более двух попыток RESUME (первая + одна повторная), затем откат
            // на старый канал (`02 §3.7`, Q18: формулировка выровнена со спекой).
            return Err(ResumeError::AckTimeout);
        }
        match self.eph_client {
            Some((_, public)) if public == eph => {}
            _ => return Err(ResumeError::Malformed),
        }
        // Новый `client_nonce` на каждую попытку, ticket тот же (`02 §3.6`).
        let nonce_bytes = crypto_core::random_32();
        let mut client_nonce = [0u8; 16];
        client_nonce.copy_from_slice(&nonce_bytes[..16]);
        let (request, ctx) = self.build_resume(ticket, client_nonce)?;
        // Бюджет тратят только попытки, дошедшие до сети (включая таймаут канала):
        // локальный `Malformed` до `build_resume`/на нём самом не съедает ретрай — иначе
        // третий валидный вызов получал `AckTimeout` вместо попытки (аудит F-CORR).
        self.attempts += 1;
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
    }

    impl MockNode {
        fn new(k_resume: [u8; 32], node_identity_priv: [u8; 32], corrupt_signature: bool) -> Self {
            Self {
                k_resume,
                node_identity_priv,
                corrupt_signature,
            }
        }
    }

    impl RotationChannel for MockNode {
        fn exchange(&mut self, _node: NodeId, request: &[u8]) -> Result<Vec<u8>, ChannelError> {
            if request[0] == KIND_MINT_REQ {
                return Ok(vec![0xab; 161]);
            }
            // Разбор RESUME: `kind ‖ len ‖ ticket ‖ nonce(24) ‖ sealed`.
            let len = u16::from_be_bytes([request[1], request[2]]) as usize;
            let ticket = &request[3..3 + len];
            let nonce_and_sealed = &request[3 + len..];
            let mut nonce = [0u8; 24];
            nonce.copy_from_slice(&nonce_and_sealed[..24]);
            let plain = RecordAead
                .open(
                    &KRecord(self.k_resume),
                    &RecordNonce(nonce),
                    ticket,
                    &nonce_and_sealed[24..],
                )
                .map_err(|_| ChannelError::Unreachable)?;
            // Узел знает `client_nonce` только отсюда — и выбирает свой nonce для ACK.
            let mut client_nonce = [0u8; 16];
            client_nonce.copy_from_slice(&plain[56..72]);

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
                &RecordNonce(ack_nonce(&client_nonce)),
                request,
                &ack_plain,
            );
            let mut response = vec![KIND_ACK];
            response.extend_from_slice(&ack_nonce(&client_nonce));
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
        let nonce_and_sealed = &request[3 + len..];
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&nonce_and_sealed[..24]);
        let plain = RecordAead
            .open(
                &KRecord(*k_resume),
                &RecordNonce(nonce),
                ticket,
                &nonce_and_sealed[24..],
            )
            .expect("RESUME вскрывается под K_resume");
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&plain[72..136]);
        crypto_core::Signature(signature)
    }

    fn coordinator(
        corrupt_signature: bool,
    ) -> (
        ClientRotation<MockNode>,
        crypto_core::Ed25519Pub,
        [u8; 32],
        crypto_core::Ed25519Pub,
    ) {
        let k_resume = derive_k_resume(&SID, &crypto_core::KSession(K_SESSION));
        let (client_pub, client_priv) = crypto_core::ed25519_genkey();
        let (node_pub, node_priv) = crypto_core::ed25519_genkey();
        // `x25519_genkey` отдаёт (публичный, приватный).
        let (eph_pub, eph_priv) = crypto_core::x25519_genkey().expect("eph_client");
        let mut rotation = ClientRotation::new(
            SID,
            K_SESSION,
            MockNode::new(k_resume, node_priv, corrupt_signature),
        );
        rotation.set_client_identity(client_priv);
        rotation.set_eph_client(eph_priv, X25519Pub(eph_pub.0));
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
        let mut thief =
            ClientRotation::new(SID, K_SESSION, MockNode::new(k_resume, [0u8; 32], false));
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
        let continuity = rotation
            .resume(&target, &ticket, eph)
            .expect("валидный ACK");
        assert_eq!(continuity.point, 42);
        assert_eq!(continuity.window_hi, 42);
        assert_eq!(
            continuity.eph_node,
            X25519Pub(EPH_NODE),
            "Q17: eph_node в типе"
        );
        assert_ne!(continuity.sig_node.0, [0u8; 64], "Q17: sig_node в типе");
        assert_eq!(rotation.attempts(), 1);
        assert_eq!(rotation.confirmed_eph_node(), Some(X25519Pub(EPH_NODE)));
        let ack = rotation.confirmed_ack().expect("полный ACK сохранён");
        assert_eq!(ack.continuity_point, 42);
        assert_eq!(ack.eph_node, X25519Pub(EPH_NODE));

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

        // Потолок попыток: третья не делается (`02 §3.7`, Q18 — попыток не более двух).
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

    /// Прод-эмиттер `build_resume_ack` даёт кадр, который прод-парсер `accept_response`
    /// принимает: подпись, AEAD-поля и транскрипт совпадают (BLOCKER-2: один источник
    /// кодирования ACK вместо моков). Подпись чужим ключом узла отвергается.
    #[test]
    fn contract_resume_ack_emitter_matches_parser() {
        let k_resume = derive_k_resume(&SID, &crypto_core::KSession(K_SESSION));
        let (node_pub, node_priv) = crypto_core::ed25519_genkey();
        let (eph_pub, _) = crypto_core::x25519_genkey().expect("eph_node");
        let (eph_client_pub, _) = crypto_core::x25519_genkey().expect("eph_client");
        let ctx = ResumeCtx {
            ticket_hash: crypto_core::sha256(b"ticket-blob"),
            last_seq: 42,
            window: (0, 42),
            eph_client: eph_client_pub.0,
            client_nonce: CLIENT_NONCE,
        };
        // AAD парсера — байты `RESUME`; для roundtrip достаточно любого согласованного
        // запроса: эмиттер и парсер берут одни и те же байты.
        let request = vec![KIND_RESUME, 0x00, 0x00];

        let ack = build_resume_ack(
            k_resume,
            &request,
            &CLIENT_NONCE,
            &ctx,
            (0, 42),
            &X25519Pub(eph_pub.0),
            &node_priv,
        );

        // Кадр len-less: kind(0x01), дальше nonce, без len-поля (решение BLOCKER-2, A).
        assert_eq!(ack[0], KIND_ACK);

        // Прод-парсер принимает кадр прод-эмиттера: все поля на месте.
        let target = Node {
            id: NodeId(1),
            node_identity: Ed25519Pub(node_pub.0),
            node_static: X25519Pub([0x44; 32]),
        };
        let mut rotation =
            ClientRotation::new(SID, K_SESSION, MockNode::new(k_resume, [0u8; 32], false));
        rotation.set_resume_state(ctx.last_seq, ctx.window);
        let continuity = rotation
            .accept_response(&target, &request, &ack, &ctx)
            .expect("ACK прод-эмиттера принят прод-парсером");
        assert_eq!(continuity.point, 42);
        assert_eq!(continuity.window_lo, 0);
        assert_eq!(continuity.window_hi, 42);
        assert_eq!(continuity.eph_node, X25519Pub(eph_pub.0));
        assert_eq!(
            rotation.confirmed_ack().map(|a| a.eph_node),
            Some(X25519Pub(eph_pub.0))
        );

        // Чужой ключ подписи узла → BadNodeSignature (`02 §3.7`).
        let forged = build_resume_ack(
            k_resume,
            &request,
            &CLIENT_NONCE,
            &ctx,
            (0, 42),
            &X25519Pub(eph_pub.0),
            &[0xEE; 32],
        );
        assert_eq!(
            rotation.accept_response(&target, &request, &forged, &ctx),
            Err(ResumeError::BadNodeSignature)
        );
    }

    /// Ручной стенд для парсера ACK без мок-узла: полный контроль над байтами ответа
    /// (nonce, подпись, шифротекст) — прод-эмиттер `build_resume_ack` строит кадры.
    fn ack_stand() -> (ClientRotation<MockNode>, Node, [u8; 32], ResumeCtx, Vec<u8>) {
        let k_resume = derive_k_resume(&SID, &crypto_core::KSession(K_SESSION));
        let (node_pub, node_priv) = crypto_core::ed25519_genkey();
        // `eph_node` в кадрах стенда — константа EPH_NODE: парсер берёт его из plain
        // и сверяет только подписью, отдельная пара ключей здесь не нужна.
        let (eph_client_pub, _) = crypto_core::x25519_genkey().expect("eph_client");
        let ctx = ResumeCtx {
            ticket_hash: crypto_core::sha256(b"ticket-blob"),
            last_seq: 42,
            window: (0, 42),
            eph_client: eph_client_pub.0,
            client_nonce: CLIENT_NONCE,
        };
        // AAD парсера — байты `RESUME`; прод-эмиттеру достаточно тех же байтов.
        let request = vec![KIND_RESUME, 0x00, 0x00];
        let node = Node {
            id: NodeId(1),
            node_identity: Ed25519Pub(node_pub.0),
            node_static: X25519Pub([0x44; 32]),
        };
        let mut rotation =
            ClientRotation::new(SID, K_SESSION, MockNode::new(k_resume, [0u8; 32], false));
        rotation.set_resume_state(ctx.last_seq, ctx.window);
        (rotation, node, node_priv, ctx, request)
    }

    /// Nonce ACK — производная от собственной попытки, а не доверенный вход с провода:
    /// кадр под чужим nonce → `Malformed` до open (аудит F-CORR), под своим — принимается.
    #[test]
    fn contract_ack_nonce_is_derived_from_client_nonce() {
        let (mut rotation, node, node_priv, ctx, request) = ack_stand();
        let k_resume = derive_k_resume(&SID, &crypto_core::KSession(K_SESSION));
        let eph = X25519Pub([0x77; 32]);

        // Валидный ACK другой попытки: тот же AEAD-ключ и AAD, но nonce и транскрипт —
        // от чужого `client_nonce`. Раньше клиент молча принимал такой nonce с провода.
        let other_nonce = [0x99u8; 16];
        let mut other_ctx = ctx.clone();
        other_ctx.client_nonce = other_nonce;
        let stale = build_resume_ack(
            k_resume,
            &request,
            &other_nonce,
            &other_ctx,
            (0, 42),
            &eph,
            &node_priv,
        );
        assert_eq!(
            rotation.accept_response(&node, &request, &stale, &ctx),
            Err(ResumeError::Malformed),
            "nonce ACK обязан равняться ack_nonce(client_nonce)"
        );
        assert!(
            rotation.confirmed_ack().is_none(),
            "отказ ничего не подтверждает"
        );

        // Тот же кадр под nonce этой попытки принимается — различие ровно в nonce.
        let fresh = build_resume_ack(
            k_resume,
            &request,
            &ctx.client_nonce,
            &ctx,
            (0, 42),
            &eph,
            &node_priv,
        );
        assert!(rotation
            .accept_response(&node, &request, &fresh, &ctx)
            .is_ok());
    }

    /// AEAD-open failure — corruption (`Malformed`), а не доказательство подделки;
    /// `BadNodeSignature` — только вердикт `ed25519_verify` при вскрывшемся AEAD.
    /// Это разные классы отказа (аудит F-CORR): карантинить честный узел из-за
    /// испорченного байта — quarantine poisoning.
    #[test]
    fn contract_aead_failure_is_malformed_not_bad_signature() {
        let (mut rotation, node, node_priv, ctx, request) = ack_stand();
        let k_resume = derive_k_resume(&SID, &crypto_core::KSession(K_SESSION));
        let eph = X25519Pub([0x77; 32]);

        let mut corrupted = build_resume_ack(
            k_resume,
            &request,
            &ctx.client_nonce,
            &ctx,
            (0, 42),
            &eph,
            &node_priv,
        );
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0xff; // испорчен шифротекст — AEAD open не пройдёт
        assert_eq!(
            rotation.accept_response(&node, &request, &corrupted, &ctx),
            Err(ResumeError::Malformed),
            "битый AEAD — Malformed, не BadNodeSignature"
        );

        // Подпись чужим ключом при целом AEAD — по-прежнему BadNodeSignature.
        let forged = build_resume_ack(
            k_resume,
            &request,
            &ctx.client_nonce,
            &ctx,
            (0, 42),
            &eph,
            &[0xEE; 32],
        );
        assert_eq!(
            rotation.accept_response(&node, &request, &forged, &ctx),
            Err(ResumeError::BadNodeSignature)
        );

        // Обрезанные/чужие кадры — Malformed: одинокий NAK-байт, ACK без тела, пустой ответ.
        assert_eq!(
            rotation.accept_response(&node, &request, &[KIND_NAK], &ctx),
            Err(ResumeError::Malformed)
        );
        assert_eq!(
            rotation.accept_response(&node, &request, &[KIND_ACK], &ctx),
            Err(ResumeError::Malformed)
        );
        assert_eq!(
            rotation.accept_response(&node, &request, &[], &ctx),
            Err(ResumeError::Malformed)
        );
    }

    /// NAK детектируется фреймом (`len == 2 && kind == 0x02`), а не первым байтом
    /// сырого ответа (аудит F-CORR): первый байт легитимного ticket — случайный nonce
    /// AEAD, и heuristic «первый байт == 0x02» давал ложный `Rejected` с p ≈ 1/256.
    #[test]
    fn contract_nak_detection_is_framed_not_heuristic() {
        let (mut rotation, node, _node_priv, ctx, request) = ack_stand();

        // RESUME-ответ: NAK-фрейм → Nacked с причиной (F-06); всё прочее с kind=NAK → Malformed.
        assert_eq!(
            rotation.accept_response(&node, &request, &[KIND_NAK, NAK_BAD_POP], &ctx),
            Err(ResumeError::Nacked(ResumeNak::BadPop))
        );
        assert_eq!(
            rotation.accept_response(&node, &request, &[KIND_NAK, NAK_REPLAY], &ctx),
            Err(ResumeError::Nacked(ResumeNak::Replay))
        );
        assert_eq!(
            rotation.accept_response(&node, &request, &[KIND_NAK, NAK_EPOCH], &ctx),
            Err(ResumeError::Nacked(ResumeNak::Epoch))
        );
        assert_eq!(
            rotation.accept_response(&node, &request, &[KIND_NAK, NAK_EXPIRED], &ctx),
            Err(ResumeError::Nacked(ResumeNak::Expired))
        );
        assert_eq!(
            rotation.accept_response(&node, &request, &[KIND_NAK, 0xFF], &ctx),
            Err(ResumeError::Malformed),
            "неизвестный код NAK — Malformed (код-байт больше не отбрасывается, F-06)"
        );
        assert_eq!(
            rotation.accept_response(&node, &request, &[KIND_NAK, 0x01, 0x02], &ctx),
            Err(ResumeError::Malformed),
            "3 байта с kind=NAK — не NAK-фрейм"
        );
        assert_eq!(
            rotation.accept_response(&node, &request, &[KIND_NAK], &ctx),
            Err(ResumeError::Malformed)
        );

        // Mint-ответ: NAK-фрейм отклоняется, но blob, начинающийся с байта 0x02, — данные.
        struct FixedNode(Vec<u8>);
        impl RotationChannel for FixedNode {
            fn exchange(
                &mut self,
                _node: NodeId,
                _request: &[u8],
            ) -> Result<Vec<u8>, ChannelError> {
                Ok(self.0.clone())
            }
        }
        let target = Node {
            id: NodeId(1),
            node_identity: Ed25519Pub([0x00; 32]),
            node_static: X25519Pub([0x44; 32]),
        };
        let mut nak_mint = ClientRotation::new(SID, K_SESSION, FixedNode(vec![KIND_NAK, 0x01]));
        assert_eq!(nak_mint.request_ticket(&target), Err(MintError::Rejected));

        // Регрессия heuristic: ticket с первым байтом 0x02 больше не ложный Rejected.
        let mut blob_02 = ClientRotation::new(SID, K_SESSION, FixedNode(vec![0x02, 0x33, 0x44]));
        let ticket = blob_02
            .request_ticket(&target)
            .expect("0x02 в первом байте blob — данные, а не отказ");
        assert_eq!(ticket.blob.0, vec![0x02, 0x33, 0x44]);
    }

    /// Бюджет попыток тратят только попытки, дошедшие до сети (аудит F-CORR):
    /// локальные `Malformed` (eph-мismatch, пустой ticket) не съедают ретрай — иначе
    /// третий валидный вызов получал `AckTimeout` вместо попытки.
    #[test]
    fn contract_local_malformed_does_not_burn_retry_budget() {
        let (mut rotation, _client_pub, _client_priv, node_pub) = coordinator(false);
        let target = node(node_pub);
        let ticket = rotation.request_ticket(&target).expect("ticket");
        let eph = rotation.eph_public().expect("eph_client установлен");

        // Локальный Malformed №1: чужой eph — отказ до сети.
        assert_eq!(
            rotation.resume(&target, &ticket, X25519Pub([0x66; 32])),
            Err(ResumeError::Malformed)
        );
        assert_eq!(rotation.attempts(), 0, "eph-мismatch не тратит попытку");

        // Локальный Malformed №2: пустой blob отклоняется до сборки
        // (аудит F-CORR: раньше отклонялся только len > 1024).
        let empty = Ticket {
            blob: TicketBlob(Vec::new()),
        };
        assert_eq!(
            rotation.build_resume(&empty, CLIENT_NONCE),
            Err(ResumeError::Malformed),
            "len == 0 — Malformed, не только len > 1024"
        );
        assert_eq!(
            rotation.resume(&target, &empty, eph),
            Err(ResumeError::Malformed)
        );
        assert_eq!(rotation.attempts(), 0, "пустой ticket не тратит попытку");

        // Валидная попытка после двух локальных отказов проходит: бюджет не съеден.
        let continuity = rotation
            .resume(&target, &ticket, eph)
            .expect("валидный ACK");
        assert_eq!(continuity.point, 42);
        assert_eq!(rotation.attempts(), 1, "сеть увидела ровно одну попытку");
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
        let mut bare =
            ClientRotation::new(SID, K_SESSION, MockNode::new([0u8; 32], [0u8; 32], false));
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
