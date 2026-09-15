//! `device-adapter` — доступ к TUN-устройству (`03-components.md` §9).
//!
//! **In:** пакеты от сетевого стека ОС; конфигурация адресов от `policy-engine`.
//! **Out:** пакеты в `frame-session`; записанные обратно пакеты из туннеля.
//! **Deps:** нет (платформенные крейты подключаются вместе с платформой).
//!
//! Платформы (`03-components.md` §9): utun (macOS/iOS), TUN (Linux/Android),
//! WFP/WinDivert (Windows). Порядок платформ: **Linux → Windows → macOS**.
//!
//! Phase 0: **только Linux TUN stub** — контракт и заглушка интерфейса, без реального
//! открытия устройства. Windows-путь (WFP/WinDivert: драйвер, права, реакция антивируса)
//! и macOS — Phase 1; для Windows это ещё и открытый вопрос, а не только работа
//! (см. QUESTIONS.md, раздел «не в Phase 0»).

#![deny(unsafe_code)]

use std::net::IpAddr;

/// Платформа исполнения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Linux/Android: TUN.
    LinuxTun,
    /// Windows: WFP/WinDivert.
    WindowsWfp,
    /// macOS/iOS: utun.
    MacOsUtun,
}

/// Текущая платформа сборки (Phase 0 собирает и проверяет только Linux-путь).
pub const PHASE0_PLATFORM: Platform = Platform::LinuxTun;

/// Конфигурация адресов tun-интерфейса.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunConfig {
    /// Адрес интерфейса.
    pub address: IpAddr,
    /// Префикс сети.
    pub prefix_len: u8,
    /// MTU.
    pub mtu: u16,
}

/// Дескриптор открытого устройства.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceHandle(pub u32);

/// Ошибка работы с устройством.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceError {
    /// Нет прав на создание/открытие устройства (для Windows — установка драйвера).
    PermissionDenied,
    /// Платформа не поддерживается в этой сборке.
    UnsupportedPlatform,
    /// Устройство недоступно.
    Unavailable,
}

/// ЧЕРНОВОЙ контракт: в `03-components.md` трейта нет — форма фиксируется при реализации
/// Phase 0. Гипотеза: устройство одно на процесс, пакеты не аллоцируются в горячем пути.
pub trait DeviceAdapter {
    /// Открывает устройство с заданной конфигурацией.
    fn open(&mut self, config: &TunConfig) -> Result<DeviceHandle, DeviceError>;
    /// Читает один пакет; возвращает его длину.
    fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, DeviceError>;
    /// Пишет один пакет.
    fn write_packet(&mut self, packet: &[u8]) -> Result<(), DeviceError>;
    /// Закрывает устройство, возвращая маршруты в исходное состояние.
    fn close(&mut self);
}

#[cfg(test)]
mod tests {
    /// Контракт Phase 0: Linux TUN stub открывается, читает и пишет пакеты, а `close`
    /// не оставляет за собой изменённых маршрутов (иначе прогон теста ломает сеть хоста).
    #[test]
    #[ignore = "контракт Phase 0: тело намеренно todo!() — тест начнёт проходить вместе с реализацией"]
    fn contract_linux_tun_stub_roundtrip() {
        todo!("Phase 0: Linux TUN stub — open → read_packet/write_packet → close без следов")
    }

    /// Контракт платформенного отказа: не-Linux сборка возвращает `UnsupportedPlatform`,
    /// а не паникует (Linux → Windows → macOS — `03` §9).
    #[test]
    #[ignore = "контракт Phase 0: тело намеренно todo!() — тест начнёт проходить вместе с реализацией"]
    fn contract_unsupported_platform_is_result_not_panic() {
        todo!("Phase 0: DeviceError::UnsupportedPlatform вместо паники на не-Linux")
    }
}
