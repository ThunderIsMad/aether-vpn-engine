//! `session-store` — клиентское хранилище состояния сессии (`03-components.md` §7)
//! и **владелец клиентских ключей личности**.
//!
//! **In/State:** `(subscription_id, uuid, session_id)`, `K_session`, tickets, chain descriptor,
//! `client_identity` (Ed25519 priv — подпись `RESUME`), `client_static` (X25519 priv —
//! статик инициатора в Noise_IK).
//! **Out:** сессия, готовая к резюму; ticket для `key-coordinator`.
//! **Deps:** нет (OS secure store подключается на платформенном уровне).
//!
//! **At-rest:** `client_identity`, `client_static` и `K_session` — в OS secure store
//! (keyring / DPAPI / Keychain / libsecret); tickets — только in-memory. У сервера
//! состояния, переживающего ротацию, нет (на время сессии узел держит in-memory окно
//! дедупликации).
//!
//! Типы приватных ключей здесь намеренно не объявлены: их форма — вместе с `zeroize`
//! и opaque-доступом — фиксируется при реализации Phase 0, а не в скаффолде.

#![deny(unsafe_code)]

/// Идентификатор подписки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionId(pub String);

/// Состояние сессии на клиенте (`03-components.md` §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionState {
    /// Подписка, в рамках которой живёт сессия.
    pub subscription_id: SubscriptionId,
    /// UUID устройства/клиента в подписке.
    pub uuid: [u8; 16],
    /// Идентификатор сессии (`sid`).
    pub session_id: [u8; 16],
    /// Мастер-ключ сессии (в at-rest — только через OS secure store).
    pub k_session: [u8; 32],
    /// Tickets, выданные узлами (только in-memory).
    pub tickets: Vec<Vec<u8>>,
    /// Chain descriptor для Federated Egress Mesh (Phase 3, `02 §3.4`).
    pub chain: Vec<[u8; 16]>,
}

/// Ошибка хранилища.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// OS secure store недоступен (нет keyring/DPAPI и т. п.).
    Unavailable,
    /// Запись повреждена или расшифровка не прошла.
    Corrupt,
    /// Доступ запрещён пользователем/политикой ОС.
    Denied,
}

/// ЧЕРНОВОЙ контракт: в `03-components.md` трейта нет — форма фиксируется при реализации
/// Phase 0. Гипотеза: хранилище одно на клиента, сессия — одна активная.
pub trait SessionStore {
    /// Загружает сохранённую сессию, если она есть.
    fn load(&self) -> Result<Option<SessionState>, StoreError>;
    /// Сохраняет состояние сессии.
    fn save(&mut self, state: &SessionState) -> Result<(), StoreError>;
    /// Стирает состояние (logout / отзыв клиента через манифест).
    fn wipe(&mut self) -> Result<(), StoreError>;
}

#[cfg(test)]
mod tests {
    /// Контракт хранилища: `K_session` и обе приватные пары личности лежат в OS secure
    /// store, tickets — только в памяти; после `wipe` не остаётся ни одного секрета.
    #[test]
    #[ignore = "контракт Phase 0: тело намеренно todo!() — тест начнёт проходить вместе с реализацией"]
    fn contract_secrets_at_rest_and_wipe() {
        todo!("Phase 0: at-rest через OS secure store; tickets in-memory; wipe без остатка")
    }

    /// Контракт владельца: `client_identity` priv доступен только этому модулю —
    /// им подписывается `RESUME`, а не хранится где-либо ещё (`03` §7).
    #[test]
    #[ignore = "контракт Phase 0: тело намеренно todo!() — тест начнёт проходить вместе с реализацией"]
    fn contract_client_identity_is_owned_here() {
        todo!("Phase 0: client_identity/client_static priv — единственный владелец session-store")
    }
}
