//! `transport-mux` — байндинги frame-слоя к транспортам (`03-components.md` §4).
//!
//! **In:** `Record` из `frame-session`; выбранный байндинг от `morph-controller`.
//! **Out:** байты в транспорт; `BindingError` (синхронно) и `BindingFailure` (асинхронно).
//! **Deps:** `frame-session` (тип `Record`), `quinn` (QUIC-байндинг).
//!
//! Phase 0: **только QUIC-байндинг** (quinn, дефолт cubic — BBR в quinn экспериментальный
//! и не сопровождается, issue #2156). Остальные байндинги — Phase 1: MASQUE CONNECT-UDP
//! на quinn+h3, Reality/TCP с задокументированным HOL-tradeoff, SS-2022/padded.
//!
//! Оба пути отказа обязаны доходить до FSM морфинга и приводить к rollback с quarantine
//! обложки: синхронный — через `Result` из `send`, асинхронный — через `on_failure`
//! (`02 §4`, таблица окна морфа).

#![deny(unsafe_code)]

use frame_session::Record;

/// Флаги возможностей байндинга (`03-components.md`, контракты).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingCaps {
    /// Нет head-of-line блокировки на этом байндинге (QUIC — да, Reality/TCP — нет).
    pub no_hol: bool,
    /// Сохраняет ли датаграммную семантику (для QUIC-байндинга — да).
    pub datagram: bool,
    /// Профиль DPI-поведения байндинга (для классификатора морфа).
    pub dpi_profile: u8,
}

/// Синхронный отказ отправки: возвращается вызывающему сразу.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingError {
    /// Транспорт недоступен.
    TransportDown,
    /// Очередь отправки переполнена (backpressure).
    WouldBlock,
    /// Байндинг не поддерживает такую запись.
    Unsupported,
}

/// Асинхронный отказ: приходит между вызовами `send`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingFailure {
    /// Соединение разорвано без `send` со стороны приложения.
    Closed,
    /// Пир перестал отвечать.
    PeerUnresponsive,
    /// Транспорт снят цензором (RST/spike) — повод для морфа.
    Probed,
}

/// Контракт байндинга (`03-components.md`, контракты) — скопирован дословно.
pub trait CoverBinding {
    /// Отправляет запись; синхронный отказ — `Err`.
    fn send(&mut self, rec: &Record) -> Result<(), BindingError>;
    /// Что умеет этот байндинг.
    fn supports(&self) -> BindingCaps;
    /// Асинхронный отказ, накопившийся с прошлого вызова.
    fn on_failure(&mut self) -> Option<BindingFailure>;
}

#[cfg(test)]
mod tests {
    /// Контракт отказа: `send` возвращает `BindingError` без паники, а `on_failure`
    /// отдаёт асинхронный отказ ровно один раз — оба пути обязаны дойти до FSM (`02 §4`).
    #[test]
    #[ignore = "контракт Phase 0: тело намеренно todo!() — тест начнёт проходить вместе с реализацией"]
    fn contract_sync_and_async_failure_paths() {
        todo!("Phase 0: CoverBinding::send → BindingError и on_failure() → BindingFailure → FSM")
    }

    /// Контракт caps: QUIC-байндинг обязан заявлять `no_hol = true` и `datagram = true`,
    /// иначе выбор байндинга в FSM противоречит `02 §2`.
    #[test]
    #[ignore = "контракт Phase 0: тело намеренно todo!() — тест начнёт проходить вместе с реализацией"]
    fn contract_quic_binding_caps() {
        todo!("Phase 0: QUIC-байндинг на quinn — caps {{ NO_HOL, DATAGRAM }}; дефолт cubic")
    }
}
