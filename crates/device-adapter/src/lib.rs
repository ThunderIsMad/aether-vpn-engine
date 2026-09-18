//! `device-adapter` — доступ к TUN-устройству (`03-components.md` §9).
//!
//! **In:** пакеты от сетевого стека ОС; конфигурация адресов от `policy-engine`.
//! **Out:** пакеты в `frame-session`; записанные обратно пакеты из туннеля.
//! **Deps:** нет (платформенные крейты подключаются вместе с платформой).
//!
//! Платформы (`03-components.md` §9): utun (macOS/iOS), TUN (Linux/Android),
//! WFP/WinDivert (Windows). Порядок платформ: **Linux → Windows → macOS**.
//!
//! ## Реализация Phase 0
//!
//! - `LinuxTunStub` — **in-memory** устройство, реализующее контракт `DeviceAdapter`
//!   целиком: `open → read_packet / write_packet → close`. Реального открытия
//!   `/dev/net/tun` здесь нет: конфигурация интерфейса требует `ioctl(TUNSETIFF)`
//!   (libc/unsafe в отдельном модуле) — это Phase 1 вместе с правами и ручной
//!   интеграцией (команда — `docs/phase-reports/phase-0.md` → «remainder»).
//!   Поэтому в CI устройство **не поднимается** — и не обязано: unit-тесты гоняются
//!   на стабе, зелёный job не зависит от `/dev/net/tun`.
//! - Платформенный отказ — через `ensure_supported`: на **не-Linux сборке**
//!   `open` возвращает `Err(DeviceError::UnsupportedPlatform)`, не паникуя
//!   (контракт скаффолда). Решение вынесено в чистую функцию, чтобы контракт
//!   проверялся юнит-тестом на любой платформе, а не только на не-Linux раннере.
//! - Пакеты, «приходящие от ОС», инжектируются тестом через `inject_inbound` —
//!   это единственная точка, где стаб отличается от реального устройства.

#![deny(unsafe_code)]

use std::collections::VecDeque;
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
    /// Устройство недоступно (нет `/dev/net/tun`, устройство не открыто).
    Unavailable,
    /// Пакет длиннее MTU интерфейса.
    PacketTooLarge,
}

/// ЧЕРНОВОЙ контракт, форма зафиксирована при реализации Phase 0 (скаффолд).
/// Гипотеза «устройство одно на процесс» выражена в `LinuxTunStub::open`:
/// повторное открытие того же стаба возвращает `PermissionDenied`.
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

/// Платформенный гейт: Linux-путь разрешён, остальные — `UnsupportedPlatform`.
///
/// Чистая функция, а не проверка внутри `open`, чтобы контракт «Result, а не паника»
/// проверялся юнит-тестом на любой платформе (CI — Linux).
pub fn ensure_supported(platform: Platform) -> Result<(), DeviceError> {
    match platform {
        Platform::LinuxTun => Ok(()),
        Platform::WindowsWfp | Platform::MacOsUtun => Err(DeviceError::UnsupportedPlatform),
    }
}

/// Проверяет, что префикс допустим для семейства адреса (`03` §9 — конфиг от policy).
fn validate_config(config: &TunConfig) -> Result<(), DeviceError> {
    let max = match config.address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if config.prefix_len > max {
        return Err(DeviceError::Unavailable);
    }
    Ok(())
}

/// In-memory Linux TUN: контракт устройства без реального `/dev/net/tun`.
///
/// Жизненный цикл: `open` (ровно один раз) → `read_packet` (пакеты, инжектированные
/// `inject_inbound`, как будто их прислал сетевой стек) → `write_packet` (журнал
/// записанных пакетов) → `close` (стаб не трогает маршруты — сбрасывать нечего,
/// устройство перестаёт отвечать до следующего `open`).
#[derive(Debug, Default)]
pub struct LinuxTunStub {
    inner: Option<Opened>,
    /// Пакеты «от сетевого стека ОС», ожидающие `read_packet`.
    inbound: VecDeque<Vec<u8>>,
    /// Пакеты, записанные в устройство (порядок сохранён).
    written: Vec<Vec<u8>>,
    next_handle: u32,
}

/// Состояние открытого устройства.
#[derive(Debug)]
struct Opened {
    handle: DeviceHandle,
    config: TunConfig,
}

impl LinuxTunStub {
    /// Пустой стаб (устройство закрыто, очередь входящих пуста).
    pub fn new() -> Self {
        Self::default()
    }

    /// Инжектирует пакет «от сетевого стека ОС» (тестовая точка стаба).
    pub fn inject_inbound(&mut self, packet: &[u8]) {
        self.inbound.push_back(packet.to_vec());
    }

    /// Журнал пакетов, записанных через `write_packet` (порядок сохранён).
    pub fn written(&self) -> &[Vec<u8>] {
        &self.written
    }

    /// Открыто ли устройство и с какой конфигурацией.
    pub fn opened_config(&self) -> Option<&TunConfig> {
        self.inner.as_ref().map(|opened| &opened.config)
    }

    /// Открыт ли дескриптор (не `Option`, чтобы тест мог сравнить значения).
    pub fn handle(&self) -> Option<DeviceHandle> {
        self.inner.as_ref().map(|opened| opened.handle)
    }
}

impl DeviceAdapter for LinuxTunStub {
    fn open(&mut self, config: &TunConfig) -> Result<DeviceHandle, DeviceError> {
        // Платформенный гейт: на не-Linux сборке — UnsupportedPlatform, не паника.
        ensure_supported(PHASE0_PLATFORM)?;
        // «Устройство одно на процесс» (гипотеза контракта): повторное открытие
        // существующего устройства — отказ, а не тихая замена дескриптора.
        if self.inner.is_some() {
            return Err(DeviceError::PermissionDenied);
        }
        validate_config(config)?;
        let handle = DeviceHandle(self.next_handle);
        self.next_handle += 1;
        self.inner = Some(Opened {
            handle,
            config: config.clone(),
        });
        Ok(handle)
    }

    fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, DeviceError> {
        if self.inner.is_none() {
            return Err(DeviceError::Unavailable);
        }
        let packet = self.inbound.pop_front().ok_or(DeviceError::Unavailable)?;
        let n = packet.len();
        if buf.len() < n {
            // Не помещается в буфер вызывающего: вернуть пакет в очередь, чтобы
            // ретрай с большим буфером был возможен.
            self.inbound.push_front(packet);
            return Err(DeviceError::PacketTooLarge);
        }
        buf[..n].copy_from_slice(&packet);
        Ok(n)
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), DeviceError> {
        let opened = self.inner.as_ref().ok_or(DeviceError::Unavailable)?;
        if packet.len() > usize::from(opened.config.mtu) {
            return Err(DeviceError::PacketTooLarge);
        }
        self.written.push(packet.to_vec());
        Ok(())
    }

    fn close(&mut self) {
        // Стаб не изменяет маршруты хоста (в отличие от реального TUN в Phase 1,
        // где close обязан откатить `ip route`): сбрасывать нечего.
        self.inner = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn config() -> TunConfig {
        TunConfig {
            address: IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)),
            prefix_len: 16,
            mtu: 1400,
        }
    }

    /// Контракт Phase 0: Linux TUN stub открывается, читает и пишет пакеты, а `close`
    /// не оставляет за собой изменённых маршрутов (иначе прогон теста ломает сеть хоста).
    #[test]
    fn contract_linux_tun_stub_roundtrip() {
        let mut tun = LinuxTunStub::new();

        // До open: чтение/запись — Unavailable, устройство недоступно.
        let mut buf = [0u8; 1500];
        assert_eq!(tun.read_packet(&mut buf), Err(DeviceError::Unavailable));
        assert_eq!(tun.write_packet(&[1, 2, 3]), Err(DeviceError::Unavailable));

        let handle = tun.open(&config()).expect("Linux-сборка открывает стаб");
        assert_eq!(tun.handle(), Some(handle), "дескриптор выдан и возвращён");
        assert_eq!(
            tun.opened_config(),
            Some(&config()),
            "конфигурация записана"
        );

        // Повторное открытие того же устройства — PermissionDenied («одно на процесс»).
        assert_eq!(tun.open(&config()), Err(DeviceError::PermissionDenied));

        // Roundtrip: пакет от ОС читается; пакет приложения пишется в журнал по порядку.
        tun.inject_inbound(&[0x45, 0, 0, 4, 1, 2, 3, 4]);
        let n = tun.read_packet(&mut buf).expect("пакет в очереди");
        assert_eq!(n, 8);
        assert_eq!(&buf[..n], &[0x45, 0, 0, 4, 1, 2, 3, 4]);
        tun.write_packet(&[9, 9, 9]).expect("пакет в пределах MTU");
        tun.write_packet(&[8, 8]).expect("пакет в пределах MTU");
        assert_eq!(tun.written(), &[vec![9, 9, 9], vec![8, 8]]);

        // close: устройство перестаёт отвечать; маршруты стаб не трогал —
        // отдельного отката нет, повторный open выдает новый дескриптор.
        tun.close();
        assert_eq!(tun.read_packet(&mut buf), Err(DeviceError::Unavailable));
        assert_eq!(tun.write_packet(&[1]), Err(DeviceError::Unavailable));
        assert_eq!(tun.open(&config()), Ok(DeviceHandle(1)));
    }

    /// Контракт платформенного отказа: не-Linux сборка возвращает `UnsupportedPlatform`,
    /// а не паникует (Linux → Windows → macOS — `03` §9). Решение — чистая функция,
    /// поэтому контракт проверяется и на Linux-раннере CI.
    #[test]
    fn contract_unsupported_platform_is_result_not_panic() {
        assert_eq!(ensure_supported(Platform::LinuxTun), Ok(()));
        assert_eq!(
            ensure_supported(Platform::WindowsWfp),
            Err(DeviceError::UnsupportedPlatform)
        );
        assert_eq!(
            ensure_supported(Platform::MacOsUtun),
            Err(DeviceError::UnsupportedPlatform)
        );
    }

    /// Границы конфигурации и MTU: битый префикс отклоняется на `open`,
    /// пакет длиннее MTU не пишется, короткий буфер читается повторно.
    #[test]
    fn config_and_mtu_boundaries() {
        let mut tun = LinuxTunStub::new();
        let bad_prefix = TunConfig {
            prefix_len: 33,
            ..config()
        };
        assert_eq!(tun.open(&bad_prefix), Err(DeviceError::Unavailable));

        let mut tun = LinuxTunStub::new();
        tun.open(&config()).expect("валидный конфиг");

        // MTU 1400: 1401 байт — PacketTooLarge, журнал не растёт.
        let oversized = vec![0u8; 1401];
        assert_eq!(
            tun.write_packet(&oversized),
            Err(DeviceError::PacketTooLarge)
        );
        assert!(tun.written().is_empty());
        tun.write_packet(&vec![0u8; 1400])
            .expect("ровно MTU проходит");

        // Короткий буфер: пакет возвращается в очередь, ретрай с большим читает его.
        tun.inject_inbound(&[1, 2, 3]);
        let mut tiny = [0u8; 2];
        assert_eq!(tun.read_packet(&mut tiny), Err(DeviceError::PacketTooLarge));
        let mut big = [0u8; 1500];
        let n = tun.read_packet(&mut big).expect("ретрай с большим буфером");
        assert_eq!(n, 3);
        assert_eq!(&big[..n], &[1, 2, 3]);
    }
}
