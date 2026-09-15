//! `ticket-mint` — сторона узла: **единственный владелец mint** (`03-components.md`, контракты).
//!
//! **In:** `sid`, `client_auth_pub` из авторизованного набора манифеста, окно дедупа;
//! `ticket_blob` при `RESUME`; `sig_client` и контекст резюма.
//! **Out:** `ticket_blob`; `TicketPlain` для узла; вердикт по PoP.
//! **Deps:** нет; ключ флота `TFK_epoch` приходит снаружи (владелец — узел, `02 §3.1`).
//!
//! Почему mint у узла, а не у клиента: если клиент получает `TFK_epoch`, он минтит tickets
//! сам, и containment эпохи вместе с PoP обходятся (`02 §3.1`). Клиентский крейт
//! `key-coordinator` умеет только `request_ticket`.
//!
//! Состояние узла (`02 §3.5`, §3.6): окно дедупа 4096 записей и **in-memory**
//! consumed-ticket set на эпоху. Набор теряется при рестарте узла — принято сознательно;
//! правило вытеснения набора ещё не определено (QUESTIONS.md Q1).
//!
//! Реализации нет: здесь только контракт.

#![deny(unsafe_code)]

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketBlob(pub Vec<u8>);

/// Развёрнутый ticket: то, что видит только узел после unwrap флотским ключом.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketPlain {
    /// Идентификатор сессии.
    pub sid: SessionId,
    /// Ключ сессии, обёрнутый в ticket.
    pub k_session_wrapped: Vec<u8>,
    /// Ключ клиента для проверки PoP.
    pub client_auth: Ed25519Pub,
    /// Пол окна на момент минта.
    pub window: Window,
    /// Идентификатор эпохи флотского ключа.
    pub epoch_id: u32,
    /// Срок годности ticket.
    pub exp: u64,
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

/// Ошибка разбора ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketError {
    /// AEAD не вскрылся флотским ключом.
    BadWrap,
    /// `epoch_id` не совпал с текущей эпохой.
    EpochMismatch,
    /// `exp` истёк.
    Expired,
}

/// Сторона узла (`03-components.md`, контракты; находка #29: единственный владелец mint).
pub trait TicketMint {
    /// Выдаёт ticket по запросу клиента: `sid` + его `client_auth_pub` + пол окна.
    fn mint(&self, sid: SessionId, client_auth: Ed25519Pub, window: Window) -> TicketBlob;

    /// Разворачивает ticket флотским `TFK_epoch`.
    fn unwrap_ticket(&self, blob: &TicketBlob) -> Result<TicketPlain, TicketError>;

    /// Проверяет PoP-подпись клиента по `client_auth_pub` из ticket.
    fn verify_pop(&self, ticket: &TicketPlain, sig: &Signature, ctx: &ResumeCtx) -> bool;
}

#[cfg(test)]
mod tests {
    /// Контракт mint: клиент не минтит сам; ticket привязан к `client_auth_pub`
    /// и содержит пол окна на момент минта (`02 §3.1`, §3.3).
    #[test]
    #[ignore = "контракт Phase 0: тело намеренно todo!() — тест начнёт проходить вместе с реализацией"]
    fn contract_mint_binds_client_pub_and_window() {
        todo!("Phase 0: mint → AEAD(TFK_epoch, {{sid, K_session_wrapped, client_auth, window, epoch_id, exp}})")
    }

    /// Контракт PoP: подделка или отсутствие `sig_client` → отказ, ticket не консумируется;
    /// повтор того же ticket на том же узле → `RESUME_NAK replay` (consumed-set эпохи).
    #[test]
    #[ignore = "контракт Phase 0: тело намеренно todo!() — тест начнёт проходить вместе с реализацией"]
    fn contract_pop_and_replay_rejection() {
        todo!("Phase 0: verify_pop + consumed-ticket set эпохи (02 §3.6)")
    }
}
