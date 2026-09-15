//! `policy-engine` — маршрутизация прикладных потоков (`03-components.md` §8).
//!
//! **In:** прикладной поток (адрес, порт, процесс/приложение по возможности).
//! **Out:** решение о маршрутизации: в туннель, напрямую или отклонить.
//! **Deps:** нет.
//!
//! **Impl:** rule matcher + fake-ip DNS (198.18.0.0/16), Clash-стиль, split-tunnel.
//! Fake-ip здесь важен не только для удобства: он даёт стабильный ключ потока для
//! `frame-session::FlowId`, пока DNS-ответ ещё не разрешён в реальный адрес.

#![deny(unsafe_code)]

use std::net::IpAddr;

/// Диапазон fake-ip DNS (`03-components.md` §8).
pub const FAKE_IP_RANGE: &str = "198.18.0.0/16";

/// Ключ потока, по которому принимается решение.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowKey {
    /// Адрес назначения (может быть fake-ip).
    pub dst: IpAddr,
    /// Порт назначения.
    pub dst_port: u16,
    /// SNI/хост, если известен на момент классификации.
    pub host: Option<String>,
}

/// Решение по потоку.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteAction {
    /// Напрямую, минуя туннель (split-tunnel).
    Direct,
    /// В туннель (обычный путь через frame-session).
    Tunnel,
    /// Отклонить (blocklist).
    Reject,
}

/// Правило, выбранное для потока.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Действие.
    pub action: RouteAction,
    /// Имя правила, по которому принято решение (для телеметрии и отладки).
    pub name: String,
}

/// ЧЕРНОВОЙ контракт: в `03-components.md` трейта нет — форма фиксируется при реализации
/// Phase 0.
pub trait PolicyEngine {
    /// Решает судьбу потока.
    fn route(&self, flow: &FlowKey) -> Rule;

    /// Регистрирует fake-ip для хоста и возвращает адрес из `FAKE_IP_RANGE`.
    fn assign_fake_ip(&mut self, host: &str) -> IpAddr;
}

#[cfg(test)]
mod tests {
    /// Контракт fake-ip: адреса выдаются только из `FAKE_IP_RANGE`, один хост —
    /// один стабильный адрес, и по нему поток позже узнаётся как тот же самый.
    #[test]
    #[ignore = "контракт Phase 0: тело намеренно todo!() — тест начнёт проходить вместе с реализацией"]
    fn contract_fake_ip_is_stable_and_in_range() {
        todo!("Phase 0: fake-ip DNS 198.18.0.0/16, стабильный ключ потока")
    }

    /// Контракт split-tunnel: `Direct` не попадает в туннель, `Reject` не создаёт
    /// соединения вообще, `Tunnel` даёт ровно один `FlowId`.
    #[test]
    #[ignore = "контракт Phase 0: тело намеренно todo!() — тест начнёт проходить вместе с реализацией"]
    fn contract_route_actions() {
        todo!("Phase 0: route() → Direct/Tunnel/Reject; один FlowId на поток")
    }
}
