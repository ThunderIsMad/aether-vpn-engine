//! `key-coordinator` — ticket-обёртка и PoP на **клиенте** (`03-components.md` §3).
//!
//! **In:** манифест подписки (только публичные ключи узлов и свои ключи), запросы mint.
//! **Out:** `RESUME` с PoP-подписью, проверка `RESUME_ACK`, re-key события.
//! **Deps:** нет. `sid`/`window` здесь — примитивы; канонический `Seq`/`SessionId` живёт
//! в `frame-session`, связь крейтов в `03` не зафиксирована и не изобретается здесь.
//!
//! **Impl:** запрашивает mint **у узла** (сам не минтит и `TFK_epoch` не получает);
//! `sig_client` Ed25519 по `client_identity`; post-rotation re-key со свежим DH
//! `HKDF(HKDF-Extract(DH(eph_client, eph_node)) ‖ K_session)` (`02 §3.3`).
//!
//! **Не владеет:** epoch keys, wrap-ключами, состоянием дедупа.
//!
//! Ключевое свойство, которое реализация обязана сохранить: `RESUME` несёт `sig_client`
//! по `client_auth_pub` из ticket, поэтому украденный ticket без приватного ключа
//! личности резюма не даёт (`02 §3.3`, §3.9).

#![deny(unsafe_code)]

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
///
/// Поля-примитивы: `Seq` принадлежит `frame-session`; типовая связь фиксируется
/// при реализации Phase 0.
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
}

/// Ошибка пост-ротационного re-key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekeyError {
    /// `eph_node` отсутствует или неверной длины.
    BadEphemeral,
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

#[cfg(test)]
mod tests {
    /// Контракт PoP: `RESUME` без валидной `sig_client` не даёт сессии, а сам ticket
    /// не даёт её без приватного `client_identity` (`02 §3.3`, §3.9).
    #[test]
    #[ignore = "контракт Phase 0: тело намеренно todo!() — тест начнёт проходить вместе с реализацией"]
    fn contract_resume_requires_proof_of_possession() {
        todo!("Phase 0: RESUME + sig_client по client_auth_pub из ticket (02 §3.3)")
    }

    /// Контракт re-key: `K_session'` выводится из `DH(eph_client, eph_node)`, поэтому
    /// узел N1 с одним `K_session` пост-ротационный трафик не читает (`02 §3.3`).
    #[test]
    #[ignore = "контракт Phase 0: тело намеренно todo!() — тест начнёт проходить вместе с реализацией"]
    fn contract_post_rotation_rekey_is_fresh_dh() {
        todo!("Phase 0: K_session' = HKDF(DH(eph_client, eph_node) ‖ K_session); проверка подписи узла")
    }
}
