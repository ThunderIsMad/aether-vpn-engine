//! Общий harness интеграционных тестов ротации и морфа.
//!
//! Здесь только то, что обязано быть одинаковым во всех прогонах: адаптер крипто-ядра к
//! `frame-session`, мок узла (mint + полный разбор `RESUME`), мок канала и драйвер ротации
//! с окном перекрытия. Ни одного критерия приёмки в harness'е нет — критерии живут
//! в assert'ах тестов, чтобы тест нельзя было «поправить» правкой мока.
//!
//! Моки байндингов — `transport_mux::MemBinding` (тот же тип, что в юнит-тестах
//! `transport-mux`), а не локальный дубль: контракт `CoverBinding` проверяется один раз.
#![allow(dead_code, unused_imports)]

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

pub use crypto_core::{
    derive_k_resume, derive_rotated_session, ed25519_genkey, ed25519_pubkey, ed25519_sign,
    ed25519_verify, mlkem768_genkey, ratchet_record, sha256, x25519_dh, x25519_genkey,
    x25519_keypair, Handshake, IkInitiator, IkResponder, Ed25519Pub, KSession, KRecord,
    MlKem768Pub, RecordAead, RecordCrypto, RecordNonce, Signature, X25519Pub as CoreX25519Pub,
    MLKEM768_EK_BYTES,
};
pub use frame_session::{
    record_nonce, t_ack_ms, t_morph_ms, DedupWindow, DedupOutcome, DuplicateStep, DuplicateWindow,
    FlowId, Record,
    RecordError, RecordType, ResumeNak, Seq, Session, SessionCrypto, SessionId,
    Signature as FrameSignature, StreamId, X25519Pub as FrameX25519Pub,
    DUPLICATE_WINDOW_RECORDS, MAX_RESUME_RETRIES, T_QUARANTINE_MS,
};
pub use key_coordinator::{ack_nonce, ack_signing_payload, resume_signing_payload};
pub use key_coordinator::{
    ChannelError, ClientRotation, Continuity, Ed25519Pub as KcEd25519Pub, Node, NodeId, ResumeCtx,
    ResumeError, Rotation, RotationChannel, Signature as KcSignature, Ticket, TicketBlob,
    X25519Pub as KcX25519Pub,
};
pub use ticket_mint::{
    Ed25519Pub as MintEd25519Pub, ResumeCtx as MintResumeCtx, ResumeVerdict,
    Signature as MintSignature, TicketBlob as MintBlob, TicketError, TicketFactory,
    Window as MintWindow,
};
pub use transport_mux::{
    BindingCaps, BindingError, BindingFailure, CoverBinding, MemBinding,
};

/// `sid` всех прогонов.
pub const SID: [u8; 16] = [0x5a; 16];
/// `K_session` клиента до ротации.
pub const K_SESSION: [u8; 32] = [0x41; 32];
/// Флотский ключ эпохи; он один у всех узлов набора (`02 §3.2`).
pub const TFK_EPOCH: [u8; 32] = [0x11; 32];
/// Идентификатор эпохи флота.
pub const EPOCH_ID: u32 = 7;
/// Идентификатор набора узлов (`node_set_id`).
pub const NODE_SET_ID: u32 = 3;
/// «Сейчас» тестов: детерминированное время вместо часов.
pub const T0: u64 = 1_700_000_000;
/// SRTT прогонов, мс: `T_morph` = 2 × SRTT внутри клипа `[200 ms, 2 s]`.
pub const SRTT_MS: u64 = 150;
/// Клиентский nonce, когда тест собирает `RESUME` руками.
pub const CLIENT_NONCE: [u8; 16] = [0x77; 16];

/// Тип кадра `RESUME` на проводе (`key-coordinator`).
pub const WIRE_RESUME: u8 = 0x02;
/// Тип ответа `ACK` (`key-coordinator`).
pub const WIRE_ACK: u8 = 0x01;
/// Тип ответа `NAK` (`key-coordinator`).
pub const WIRE_NAK: u8 = 0x02;
/// Неизвестный тип — то, что узел отдаёт на неразбираемый вход.
pub const WIRE_UNKNOWN: u8 = 0x03;

/// Код ветки `bad_pop` (`02 §3.7`).
pub const NAK_BAD_POP: u8 = 0x01;
/// Код ветки `replay`.
pub const NAK_REPLAY: u8 = 0x02;
/// Код ветки `epoch`.
pub const NAK_EPOCH: u8 = 0x03;
/// Код ветки `expired`.
pub const NAK_EXPIRED: u8 = 0x04;

/// Адаптер `crypto-core` → `frame-session::SessionCrypto`.
///
/// Один шаг ratchet здесь — `HKDF(sid, K_record, "aether v3 record")`, то есть ровно
/// `02 §1`; `seal`/`open` — `XChaCha20-Poly1305` с nonce `seq ‖ sid` и AAD заголовка.
pub struct CoreCrypto;

impl SessionCrypto for CoreCrypto {
    fn ratchet(&self, session_id: &[u8; 16], k_record: &[u8; 32]) -> [u8; 32] {
        ratchet_record(session_id, &KSession(*k_record), 0).0
    }

    fn seal(&self, k_record: &[u8; 32], nonce: [u8; 24], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        RecordAead.seal(&KRecord(*k_record), &RecordNonce(nonce), aad, plaintext)
    }

    fn open(
        &self,
        k_record: &[u8; 32],
        nonce: [u8; 24],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, RecordError> {
        RecordAead
            .open(&KRecord(*k_record), &RecordNonce(nonce), aad, ciphertext)
            .map_err(|_| RecordError::OpenFailed)
    }
}

/// Новая сессия frame-слоя на заданном `K_session`.
pub fn session(k_session: [u8; 32]) -> Session {
    Session::new(SessionId(SID), k_session, Box::new(CoreCrypto))
}

/// Зеркало сессии на принимающей стороне: те же потоки в том же порядке,
/// потому что `stream_id` выдаётся по порядку открытия (`02 §1`).
pub fn mirror(k_session: [u8; 32], flows: &[u64]) -> Session {
    let mut session = session(k_session);
    for flow in flows {
        session.open_stream(FlowId(*flow));
    }
    session
}

/// `K_resume` для сессии (`02 §3.3`) — нужен и клиенту, и узлу.
pub fn k_resume_for(k_session: &[u8; 32]) -> [u8; 32] {
    derive_k_resume(&SID, &KSession(*k_session))
}

/// Мок узла: свой `node_identity`, свой `eph_node`, флотский `TFK_epoch` и consumed-set.
pub struct NodeSim {
    /// Идентификатор узла (он же — `node_set_id` элемента набора).
    pub id: NodeId,
    /// Публичный `node_identity` — то, что клиент знает из манифеста.
    pub identity: Ed25519Pub,
    identity_priv: [u8; 32],
    /// Публичный эфемерный ключ узла этой попытки ротации (`eph_node` из `RESUME_ACK`).
    pub eph_node: KcX25519Pub,
    eph_node_priv: [u8; 32],
    /// Минтер и consumed-set эпохи — состояние **узла**, не сессии (`02 §3.5`, §3.6).
    pub factory: TicketFactory,
    /// Сколько `RESUME` принято этим узлом.
    pub accepted: u32,
    /// Сколько `RESUME` отклонено.
    pub nacked: u32,
    /// Подписать `ACK` чужим ключом (NodeSim → «скомпрометированный узел»).
    pub corrupt_sig_node: bool,
    /// Подсунуть другой `eph_node` (попытка сохранить чтение старого узла).
    pub eph_override: Option<KcX25519Pub>,
    /// «Сейчас» узла: проверка `exp` идёт по нему.
    pub now: u64,
}

impl NodeSim {
    /// Узел с детерминированными ключами: identity из `seed`, `eph_node` из `eph_seed`.
    pub fn new(id: u32, seed: u8, eph_seed: u8, epoch_id: u32) -> Self {
        let identity_priv = [seed; 32];
        let eph_node_priv = [eph_seed; 32];
        Self {
            id: NodeId(id),
            identity: ed25519_pubkey(&identity_priv),
            identity_priv,
            eph_node: KcX25519Pub(x25519_keypair(&eph_node_priv).public),
            eph_node_priv,
            factory: TicketFactory::new(TFK_EPOCH, epoch_id, NODE_SET_ID, 3_600),
            accepted: 0,
            nacked: 0,
            corrupt_sig_node: false,
            eph_override: None,
            now: T0,
        }
    }

    /// Узел со «своей» эпохой флота (`02 §3.7`: ветка `epoch`).
    pub fn with_epoch(id: u32, seed: u8, eph_seed: u8, epoch_id: u32) -> Self {
        Self::new(id, seed, eph_seed, epoch_id)
    }

    /// Запись узла в манифесте подписки: только публичное.
    pub fn manifest(&self) -> Node {
        Node {
            id: self.id,
            node_identity: KcEd25519Pub(self.identity.0),
            node_static: KcX25519Pub([0x99; 32]),
        }
    }

    /// Приватная половина `eph_node` — нужна тесту, чтобы посчитать `ss_rotate` за узла.
    pub fn eph_node_private(&self) -> [u8; 32] {
        self.eph_node_priv
    }

    /// Минт ticket: `sid`, `client_auth_pub` клиента, пол окна и `K_session` (`02 §3.2`).
    pub fn mint(&self, client_auth: Ed25519Pub, k_session: &[u8; 32], last_seq: u64) -> Ticket {
        let window = MintWindow {
            lo: last_seq.saturating_sub(u64::from(frame_session::DUPLICATE_WINDOW_RECORDS)),
            hi: last_seq,
        };
        let blob = self.factory.mint_at(
            ticket_mint::SessionId(SID),
            ticket_mint::Ed25519Pub(client_auth.0),
            window,
            k_session,
            self.now,
        );
        Ticket {
            blob: TicketBlob(blob.0),
        }
    }

    /// Сколько tickets узел принял (consumed-set эпохи, `02 §3.6`).
    pub fn consumed_tickets(&self) -> usize {
        self.factory.consumed_len()
    }

    /// Пробное разворачивание ticket'а — то, что узел может сделать только своим `TFK_epoch`.
    pub fn unwrap_probe(&self, ticket: &Ticket) -> Result<ticket_mint::TicketPlain, TicketError> {
        self.factory
            .unwrap_at(&MintBlob(ticket.blob.0.clone()), self.now)
    }

    /// Полный разбор `RESUME` на стороне узла: unwrap флотским ключом → `K_resume` →
    /// AEAD → PoP/consumed-set → `ACK`/`NAK` (`02 §3.3`, §3.7).
    pub fn handle(&mut self, request: &[u8]) -> Vec<u8> {
        if request.first() != Some(&WIRE_RESUME) {
            return vec![WIRE_UNKNOWN];
        }
        let Some(len_bytes) = request.get(1..3) else {
            return vec![WIRE_UNKNOWN];
        };
        let len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
        let Some(blob) = request.get(3..3 + len) else {
            return vec![WIRE_UNKNOWN];
        };
        let Some(rest) = request.get(3 + len..) else {
            return vec![WIRE_UNKNOWN];
        };
        let Some((nonce, sealed)) = rest.split_at_checked(24) else {
            return vec![WIRE_UNKNOWN];
        };
        let mut nonce_array = [0u8; 24];
        nonce_array.copy_from_slice(nonce);

        // Эпоха/срок проверяются до PoP: своих ключей для этого blоба у узла может не быть.
        let ticket = match self.factory.unwrap_at(&MintBlob(blob.to_vec()), self.now) {
            Ok(ticket) => ticket,
            Err(TicketError::EpochMismatch) => return self.nak(NAK_EPOCH),
            Err(TicketError::Expired) => return self.nak(NAK_EXPIRED),
            Err(TicketError::BadWrap | TicketError::BadLayout) => return vec![WIRE_UNKNOWN],
        };
        // `K_resume` выводится из `K_session` внутри ticket: снаружи его не знает никто,
        // кроме того, кто уже прочитал ticket флотским ключом (`02 §3.3`).
        let k_resume = k_resume_for(&ticket.k_session);
        let Ok(plain) = RecordAead.open(
            &KRecord(k_resume),
            &RecordNonce(nonce_array),
            blob,
            sealed,
        ) else {
            return vec![WIRE_UNKNOWN];
        };
        if plain.len() != 136 {
            return vec![WIRE_UNKNOWN];
        }
        let ctx = MintResumeCtx {
            ticket_hash: sha256(blob),
            last_seq: u64::from_be_bytes(plain[0..8].try_into().unwrap_or_default()),
            window: MintWindow {
                lo: u64::from_be_bytes(plain[8..16].try_into().unwrap_or_default()),
                hi: u64::from_be_bytes(plain[16..24].try_into().unwrap_or_default()),
            },
            eph_client: plain[24..56].try_into().unwrap_or_default(),
            client_nonce: plain[56..72].try_into().unwrap_or_default(),
        };
        let signature = MintSignature(plain[72..136].try_into().unwrap());

        match self
            .factory
            .handle_resume(&MintBlob(blob.to_vec()), &signature, &ctx, self.now)
        {
            ResumeVerdict::Accept { .. } => {
                self.accepted += 1;
                self.build_ack(request, &ctx, &k_resume)
            }
            ResumeVerdict::NakReplay => {
                self.nacked += 1;
                self.nak(NAK_REPLAY)
            }
            ResumeVerdict::NakBadPop => {
                self.nacked += 1;
                self.nak(NAK_BAD_POP)
            }
            ResumeVerdict::NakEpoch => {
                self.nacked += 1;
                self.nak(NAK_EPOCH)
            }
            ResumeVerdict::NakExpired => {
                self.nacked += 1;
                self.nak(NAK_EXPIRED)
            }
            ResumeVerdict::Drop => vec![WIRE_UNKNOWN],
        }
    }

    fn nak(&self, code: u8) -> Vec<u8> {
        vec![WIRE_NAK, code]
    }

    /// `RESUME_ACK`: окно узла считается тем же кодом, что и у клиента (`02 §3.5`),
    /// подпись — по `node_identity` узла над транскриптом клиента (`02 §3.3`).
    fn build_ack(&self, request: &[u8], ctx: &MintResumeCtx, k_resume: &[u8; 32]) -> Vec<u8> {
        let node_window = DedupWindow::new(Seq(ctx.window.lo), Seq(ctx.last_seq)).window();
        let eph_node = self.eph_override.unwrap_or(self.eph_node);
        let transcript = sha256(&resume_signing_payload(&ResumeCtx {
            ticket_hash: ctx.ticket_hash,
            last_seq: ctx.last_seq,
            window: (ctx.window.lo, ctx.window.hi),
            eph_client: ctx.eph_client,
            client_nonce: ctx.client_nonce,
        }));
        let payload = ack_signing_payload(
            &transcript,
            ctx.last_seq,
            (node_window.lo.0, node_window.hi.0),
            &eph_node.0,
        );
        let signer = if self.corrupt_sig_node {
            [0xee; 32]
        } else {
            self.identity_priv
        };
        let sig_node = ed25519_sign(&signer, &payload);

        let mut ack_plain = Vec::with_capacity(120);
        ack_plain.extend_from_slice(&ctx.last_seq.to_be_bytes());
        ack_plain.extend_from_slice(&node_window.lo.0.to_be_bytes());
        ack_plain.extend_from_slice(&node_window.hi.0.to_be_bytes());
        ack_plain.extend_from_slice(&eph_node.0);
        ack_plain.extend_from_slice(&sig_node.0);

        let nonce = ack_nonce(&ctx.client_nonce);
        let sealed = RecordAead.seal(&KRecord(*k_resume), &RecordNonce(nonce), request, &ack_plain);
        let mut out = vec![WIRE_ACK];
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        out
    }
}

/// Креды клиента, которые нужны узлу при mint (в проде приходят в запросе mint).
#[derive(Debug, Clone, Copy)]
pub struct ClientCreds {
    /// Публичный `client_identity`.
    pub auth: Ed25519Pub,
    /// `K_session` клиента (кладётся в ticket).
    pub k_session: [u8; 32],
    /// `last_seq`, который клиент подтверждает.
    pub last_seq: u64,
}

/// Сеть из мок-узлов: канал клиента до узла + журнал запросов.
pub struct MockNetwork {
    /// Узлы набора по их `NodeId`.
    pub nodes: BTreeMap<u32, NodeSim>,
    /// Креды клиента — для ответа на mint.
    pub client: ClientCreds,
    /// Все `RESUME`, ушедшие в сеть.
    pub requests: Vec<Vec<u8>>,
    /// Ответы узлов (включая `NAK`) — в порядке запросов.
    pub responses: Vec<Vec<u8>>,
    /// Потерять следующий `ACK` (он «ушёл в никуда», узел его уже обработал).
    pub drop_next_ack: bool,
    /// Потерять все `ACK` — узел недостижим на обратном пути.
    pub drop_all_acks: bool,
    /// Узлы, до которых канала нет вовсе.
    pub unreachable: BTreeSet<u32>,
}

/// Разделяемая сеть: тот же объект видит драйвер теста и клиентский координатор.
///
/// Обёртка нужна не «для красоты»: `impl RotationChannel for Rc<RefCell<MockNetwork>>`
/// невозможно (чужой тип нарушает orphan rule), а координатор владеет каналом по значению.
#[derive(Clone)]
pub struct SharedNetwork(Rc<RefCell<MockNetwork>>);

impl SharedNetwork {
    /// Пустая сеть с кредами клиента (единственный конструктор сети).
    pub fn new(client: ClientCreds) -> Self {
        Self(Rc::new(RefCell::new(MockNetwork {
            nodes: BTreeMap::new(),
            client,
            requests: Vec::new(),
            responses: Vec::new(),
            drop_next_ack: false,
            drop_all_acks: false,
            unreachable: BTreeSet::new(),
        })))
    }

    /// Сеть на чтение.
    pub fn borrow(&self) -> std::cell::Ref<'_, MockNetwork> {
        self.0.borrow()
    }

    /// Сеть на запись.
    pub fn borrow_mut(&self) -> std::cell::RefMut<'_, MockNetwork> {
        self.0.borrow_mut()
    }
}

impl MockNetwork {
    /// Добавляет узел в набор.
    pub fn add_node(&mut self, node: NodeSim) {
        self.nodes.insert(node.id.0, node);
    }

    /// Отвечает на запрос клиента: mint (тип `0x01`, 5 байт) — от узла, `RESUME` — от узла.
    pub fn exchange(&mut self, node: NodeId, request: &[u8]) -> Result<Vec<u8>, ChannelError> {
        if self.unreachable.contains(&node.0) {
            return Err(ChannelError::Unreachable);
        }
        let Some(target) = self.nodes.get_mut(&node.0) else {
            return Err(ChannelError::Unreachable);
        };
        // Mint-запрос: `kind(1B) ‖ node_id(4B)` — клиент сам tickets не минтит (`02 §3.1`).
        if request.first() == Some(&0x01) && request.len() == 5 {
            let creds = self.client;
            let ticket = target.mint(creds.auth, &creds.k_session, creds.last_seq);
            return Ok(ticket.blob.0);
        }
        self.requests.push(request.to_vec());
        let response = target.handle(request);
        self.responses.push(response.clone());
        if response.first() == Some(&WIRE_ACK)
            && (self.drop_all_acks || std::mem::take(&mut self.drop_next_ack))
        {
            return Err(ChannelError::Timeout);
        }
        Ok(response)
    }
}

impl RotationChannel for SharedNetwork {
    fn exchange(&mut self, node: NodeId, request: &[u8]) -> Result<Vec<u8>, ChannelError> {
        self.0.borrow_mut().exchange(node, request)
    }
}

/// Разобранный `RESUME_ACK` — то, что нужно frame-слою (`02 §3.3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckParts {
    /// Подтверждённый continuity point.
    pub continuity_point: u64,
    /// Окно узла.
    pub window: (u64, u64),
    /// `eph_node` — вход re-key.
    pub eph_node: [u8; 32],
    /// `sig_node` — то, что клиент проверил до применения.
    pub sig_node: [u8; 64],
}

/// Вскрывает `RESUME_ACK` тем же `K_resume`, что и клиент: тестам нужны `eph_node`/`sig_node`
/// в форме `frame-session`.
pub fn parse_ack(request: &[u8], response: &[u8], k_resume: &[u8; 32]) -> AckParts {
    assert_eq!(response.first(), Some(&WIRE_ACK), "ожидался ACK");
    let body = &response[1..];
    let (nonce, sealed) = body.split_at(24);
    let mut nonce_array = [0u8; 24];
    nonce_array.copy_from_slice(nonce);
    let plain = RecordAead
        .open(&KRecord(*k_resume), &RecordNonce(nonce_array), request, sealed)
        .expect("ACK вскрывается под K_resume");
    assert_eq!(plain.len(), 120);
    AckParts {
        continuity_point: u64::from_be_bytes(plain[0..8].try_into().unwrap()),
        window: (
            u64::from_be_bytes(plain[8..16].try_into().unwrap()),
            u64::from_be_bytes(plain[16..24].try_into().unwrap()),
        ),
        eph_node: plain[24..56].try_into().unwrap(),
        sig_node: plain[56..120].try_into().unwrap(),
    }
}

/// Достаёт `sig_client` из собранного `RESUME` (для проверки покрытия подписи).
pub fn resume_signature(request: &[u8], k_resume: &[u8; 32]) -> Signature {
    let len = u16::from_be_bytes([request[1], request[2]]) as usize;
    let blob = &request[3..3 + len];
    let rest = &request[3 + len..];
    let (nonce, sealed) = rest.split_at(24);
    let mut nonce_array = [0u8; 24];
    nonce_array.copy_from_slice(nonce);
    let plain = RecordAead
        .open(&KRecord(*k_resume), &RecordNonce(nonce_array), blob, sealed)
        .expect("RESUME вскрывается под K_resume");
    Signature(plain[72..136].try_into().unwrap())
}

/// Восстанавливает `ResumeCtx` и `sig_client` из собранного `RESUME`: тестам нужно
/// проверить покрытие подписи побайтово, а не «подпись где-то в шифротексте».
pub fn resume_ctx(request: &[u8], k_resume: &[u8; 32]) -> (ResumeCtx, Signature) {
    let len = u16::from_be_bytes([request[1], request[2]]) as usize;
    let blob = &request[3..3 + len];
    let rest = &request[3 + len..];
    let (nonce, sealed) = rest.split_at(24);
    let mut nonce_array = [0u8; 24];
    nonce_array.copy_from_slice(nonce);
    let plain = RecordAead
        .open(&KRecord(*k_resume), &RecordNonce(nonce_array), blob, sealed)
        .expect("RESUME вскрывается под K_resume");
    let ctx = ResumeCtx {
        ticket_hash: sha256(blob),
        last_seq: u64::from_be_bytes(plain[0..8].try_into().unwrap()),
        window: (
            u64::from_be_bytes(plain[8..16].try_into().unwrap()),
            u64::from_be_bytes(plain[16..24].try_into().unwrap()),
        ),
        eph_client: plain[24..56].try_into().unwrap(),
        client_nonce: plain[56..72].try_into().unwrap(),
    };
    (ctx, Signature(plain[72..136].try_into().unwrap()))
}

/// `RESUME`, собранный клиентом, — последний ушедший в сеть.
pub fn last_request(network: &SharedNetwork) -> Vec<u8> {
    network
        .borrow()
        .requests
        .last()
        .cloned()
        .expect("в сети есть RESUME")
}

/// Драйвер ротации: сессия, старый канал, новый канал и окно перекрытия.
///
/// Ровно то, что делает `FrameSession` при ротации (`02 §3.3` шаг 5, `§4`): пока новый
/// канал не подтверждён валидным `ACK`, записи идут **на оба** канала, а старый гасится
/// только после подтверждения (make-before-break).
pub struct RotationDriver {
    /// Сессия frame-слоя.
    pub session: Session,
    /// Старый канал (N1).
    pub old: MemBinding,
    /// Новый канал (N2), включается в окне перекрытия.
    pub new: Option<MemBinding>,
    /// Открыто ли окно перекрытия.
    pub overlap: bool,
    /// Сколько записей продублировано.
    pub duplicated: u32,
    /// Сколько раз драйвер упёрся в бюджет окна.
    pub exhausted: u32,
    /// Сколько записей старый канал уже не смог принять (узел снят до ACK).
    pub old_failures: u32,
}

impl RotationDriver {
    /// Новый прогон: сессия и активный (старый) канал.
    pub fn new(session: Session, old: MemBinding) -> Self {
        Self {
            session,
            old,
            new: None,
            overlap: false,
            duplicated: 0,
            exhausted: 0,
            old_failures: 0,
        }
    }

    /// Открывает окно перекрытия и подключает новый канал (`02 §4`).
    pub fn start_overlap(&mut self, incoming: MemBinding, srtt_ms: u64) -> u64 {
        let timeout = t_morph_ms(srtt_ms);
        self.session.begin_overlap(srtt_ms);
        self.new = Some(incoming);
        self.overlap = true;
        self.duplicated = 0;
        timeout
    }

    /// Запечатывает запись, отправляет её на старый канал и — в окне — дублирует на новый.
    pub fn emit(&mut self, stream: StreamId, payload: &[u8], elapsed_ms: u64) -> Record {
        let record = self.session.seal_record(stream, payload);
        self.old
            .send(&record)
            .expect("старый канал обязан принять запись");
        if self.overlap {
            match self.session.duplicate(elapsed_ms) {
                DuplicateStep::Duplicated => {
                    self.duplicated += 1;
                    if let Some(incoming) = self.new.as_mut() {
                        incoming
                            .send(&record)
                            .expect("новый канал обязан принять дубль");
                    }
                }
                DuplicateStep::Exhausted => self.exhausted += 1,
            }
        }
        record
    }

    /// То же, но отказ старого канала не паника, а счётчик: это кейс «узел снят до ACK»
    /// (`02 §3.7`), когда доставка обязана продолжиться новым каналом.
    pub fn emit_tolerant(&mut self, stream: StreamId, payload: &[u8], elapsed_ms: u64) -> Record {
        let record = self.session.seal_record(stream, payload);
        if self.old.send(&record).is_err() {
            self.old_failures += 1;
        }
        if self.overlap {
            match self.session.duplicate(elapsed_ms) {
                DuplicateStep::Duplicated => {
                    self.duplicated += 1;
                    if let Some(incoming) = self.new.as_mut() {
                        let _ = incoming.send(&record);
                    }
                }
                DuplicateStep::Exhausted => self.exhausted += 1,
            }
        }
        record
    }

    /// Закрывает окно валидным `ACK` и гасит старый канал (make-before-break завершён).
    ///
    /// Невалидный `ACK` окно не закрывает — тогда откат идёт ребром `Rollback` FSM (`02 §4`).
    pub fn promote_on_ack(&mut self, ack_valid: bool) -> bool {
        let closed = self.session.close_overlap_on_ack(ack_valid);
        if closed {
            self.overlap = false;
        }
        closed
    }

    /// Продолжение работы после ротации: записи идут только по новому каналу.
    pub fn emit_after_rotation(&mut self, stream: StreamId, payload: &[u8]) -> Record {
        let record = self.session.seal_record(stream, payload);
        match self.new.as_mut() {
            Some(incoming) => incoming
                .send(&record)
                .expect("новый канал обязан принять запись"),
            None => self
                .old
                .send(&record)
                .expect("старого канала хватает без ротации"),
        }
        record
    }
}

/// Журнал байндинга как множество `(stream_id, seq)` — база для проверок «ничего не потеряно».
pub fn delivered(binding: &MemBinding) -> BTreeSet<(u32, u64)> {
    binding
        .journal()
        .iter()
        .map(|(stream, seq)| (stream.0, *seq))
        .collect()
}

/// Множество `(stream_id, seq)` для набора записей.
pub fn records_set(records: &[Record]) -> BTreeSet<(u32, u64)> {
    records
        .iter()
        .map(|record| (record.stream_id.0, record.seq.0))
        .collect()
}

/// Проверка подписи узла так, как её делает клиент (`02 §3.3`): по `node_identity`
/// из манифеста над транскриптом клиента, `continuity_point`, окном и `eph_node`.
pub fn node_signature_verifies(
    node_identity: &Ed25519Pub,
    parts: &AckParts,
    client_ctx: &ResumeCtx,
) -> bool {
    let transcript = sha256(&resume_signing_payload(client_ctx));
    let payload = ack_signing_payload(
        &transcript,
        parts.continuity_point,
        parts.window,
        &parts.eph_node,
    );
    ed25519_verify(node_identity, &payload, &Signature(parts.sig_node))
}

/// Последний ответ узла (включая `NAK`) — для проверки ветки по коду, а не по классу ошибки.
pub fn last_response(network: &SharedNetwork) -> Vec<u8> {
    network
        .borrow()
        .responses
        .last()
        .cloned()
        .expect("у узла есть ответ")
}

/// Клиентский координатор ротации с заданными кредами (identity, eph, окно).
pub fn coordinator(
    network: SharedNetwork,
    identity: &[u8; 32],
    eph_public: KcX25519Pub,
    eph_private: [u8; 32],
    last_seq: u64,
    window: (u64, u64),
) -> ClientRotation<SharedNetwork> {
    let mut rotation = ClientRotation::new(SID, K_SESSION, network);
    rotation.set_client_identity(*identity);
    rotation.set_eph_client(eph_private, eph_public);
    rotation.set_resume_state(last_seq, window);
    rotation
}

/// Свежая эфемерная пара клиента.
pub fn fresh_eph() -> (KcX25519Pub, [u8; 32]) {
    let (public, private) = crypto_core::x25519_genkey().expect("eph_client");
    (KcX25519Pub(public.0), private)
}

/// `ss_rotate = DH(eph_client_priv, eph_node_pub)` — то, что обязан посчитать клиент
/// и не может посчитать узел, знающий только `K_session` (`02 §3.3`).
pub fn ss_rotate(eph_private: &[u8; 32], eph_node: &KcX25519Pub) -> [u8; 32] {
    x25519_dh(eph_private, &CoreX25519Pub(eph_node.0)).expect("DH состоялся")
}

/// Проверка, что `DedupWindow` окна узла принимает дубль и не двигает `continuity_point`.
pub fn dedup_probe(floor: u64, last_seq: u64, seq: u64) -> (DedupOutcome, u64) {
    let mut window = DedupWindow::new(Seq(floor), Seq(last_seq));
    let outcome = window.accept(Seq(seq));
    (outcome, window.continuity_point().0)
}
