//! `policy-engine` — маршрутизация прикладных потоков (`03-components.md` §8).
//!
//! **In:** прикладной поток (адрес, порт, процесс/приложение по возможности).
//! **Out:** решение о маршрутизации: в туннель, напрямую или отклонить.
//! **Deps:** нет.
//!
//! **Impl (`03` §8):** rule matcher + fake-ip DNS (198.18.0.0/16), Clash-стиль, split-tunnel.
//! Fake-ip здесь важен не только для удобства: он даёт стабильный ключ потока для
//! `frame-session::FlowId`, пока DNS-ответ ещё не разрешён в реальный адрес.
//!
//! ## Реализация Phase 0
//!
//! - `RouteAction` — три вердикта: `Route` (в туннель), `Direct` (мимо туннеля),
//!   `Block` (отклонить). Fake-ip **не** вердикт маршрута: это механизм DNS-слоя
//!   (`assign_fake_ip`), поток с fake-ip затем маршрутизируется правилами как любой
//!   другой — поэтому в `RouteAction` его нет (в ТЗ он перечислен среди «действий»
//!   как возможность движка, не как исход `route()`).
//! - Matcher — минимум по ТЗ: **exact domain** (без учёта регистра) + **CIDR**.
//!   Clash-провайдеры, geoip-базы и wildcards — не в Phase 0.
//! - Черновой трейт из скаффолда заменён конкретным `Engine` («форма фиксируется при
//!   реализации Phase 0» — скаффолд); если появится второй бэкенд политики, трейт вернётся.
//! - Пул fake-ip исчерпывается паникой с ясным сообщением: 65 534 адресов на процесс —
//!   для Phase 0 достаточно; вытеснение старых привязок — Phase 1/2.

#![deny(unsafe_code)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

/// Диапазон fake-ip DNS (`03-components.md` §8).
pub const FAKE_IP_RANGE: &str = "198.18.0.0/16";

/// Первый выдаваемый fake-ip: `.0` — адрес сети, `.1` традиционно шлюз.
const FAKE_IP_FIRST: u32 = 0xC612_0002; // 198.18.0.2
/// Последний выдаваемый fake-ip (вещательный адрес `198.18.255.255` не выдаётся).
const FAKE_IP_LAST: u32 = 0xC612_FFFE; // 198.18.255.254

/// Решение по потоку.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteAction {
    /// В туннель (обычный путь через frame-session; в Clash-терминах — PROXY).
    Route,
    /// Напрямую, минуя туннель (split-tunnel; Clash DIRECT).
    Direct,
    /// Отклонить (blocklist; Clash REJECT): соединение не создаётся вообще.
    Block,
}

/// CIDR-префикс назначения. Парсится из строк вида `192.168.0.0/16`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix_len: u8,
}

impl Cidr {
    /// Разбор `a.b.c.d/prefix`; невалидный вход — `None`.
    pub fn parse(s: &str) -> Option<Self> {
        let (addr, prefix) = s.split_once('/')?;
        let addr = IpAddr::from_str(addr.trim()).ok()?;
        let prefix = u8::from_str(prefix.trim()).ok()?;
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return None;
        }
        Some(Self { addr, prefix_len: prefix })
    }

    /// Содержит ли префикс адрес. Сравнение только внутри одного семейства.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.addr, *ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = v4_mask(self.prefix_len);
                net.to_bits() & mask == ip.to_bits() & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = v6_mask(self.prefix_len);
                net.to_bits() & mask == ip.to_bits() & mask
            }
            _ => false,
        }
    }
}

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    }
}

/// Правило маршрутизации: действие + имя (для телеметрии) + необязательные матчеры.
///
/// Матчеры соединяются по И: правило срабатывает, когда **все** заданные матчеры совпали.
/// Правило без матчеров соответствует любому потоку (годится как дефолт).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Действие.
    pub action: RouteAction,
    /// Имя правила, по которому принято решение (для телеметрии и отладки).
    pub name: String,
    /// Exact domain: совпадение `flow.host` без учёта регистра.
    pub host: Option<String>,
    /// CIDR назначения.
    pub cidr: Option<Cidr>,
}

impl Rule {
    /// Правило по имени и действию, без матчеров.
    pub fn new(name: &str, action: RouteAction) -> Self {
        Self {
            action,
            name: name.to_owned(),
            host: None,
            cidr: None,
        }
    }

    /// Задаёт exact-domain матчер.
    pub fn with_host(mut self, host: &str) -> Self {
        self.host = Some(host.to_owned());
        self
    }

    /// Задаёт CIDR-матчер назначения.
    pub fn with_cidr(mut self, cidr: Cidr) -> Self {
        self.cidr = Some(cidr);
        self
    }

    fn matches(&self, flow: &FlowKey) -> bool {
        if let Some(host) = &self.host {
            match &flow.host {
                Some(flow_host) if flow_host.eq_ignore_ascii_case(host) => {}
                _ => return false,
            }
        }
        if let Some(cidr) = &self.cidr {
            if !cidr.contains(&flow.dst) {
                return false;
            }
        }
        true
    }
}

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

/// Пул fake-ip из `FAKE_IP_RANGE`: один хост — один стабильный адрес.
///
/// Стабильность — контракт (`03` §8): по fake-ip поток позже узнаётся как тот же самый,
/// поэтому привязки не вытесняются (вытеснение — Phase 1/2, вместе с TTL DNS).
#[derive(Debug, Clone, Default)]
pub struct FakeIpPool {
    by_host: HashMap<String, IpAddr>,
    next: Option<u32>,
}

impl FakeIpPool {
    fn assign(&mut self, host: &str) -> IpAddr {
        if let Some(addr) = self.by_host.get(host) {
            return *addr;
        }
        let next = match self.next {
            Some(prev) => prev
                .checked_add(1)
                .filter(|n| *n <= FAKE_IP_LAST),
            None => Some(FAKE_IP_FIRST),
        }
        .expect("fake-ip pool exhausted (Phase 0 stub): вытеснение привязок — Phase 1/2");
        self.next = Some(next);
        let addr = IpAddr::V4(Ipv4Addr::from(next));
        self.by_host.insert(host.to_owned(), addr);
        addr
    }

    fn len(&self) -> usize {
        self.by_host.len()
    }
}

/// Движок политики: упорядоченный список правил (первое совпавшее побеждает) + дефолт.
#[derive(Debug, Clone)]
pub struct Engine {
    rules: Vec<Rule>,
    default: RouteAction,
    fakeip: FakeIpPool,
}

impl Engine {
    /// Движок с правилами в порядке приоритета и действием по умолчанию.
    pub fn new(default: RouteAction, rules: Vec<Rule>) -> Self {
        Self {
            rules,
            default,
            fakeip: FakeIpPool::default(),
        }
    }

    /// Решает судьбу потока: первое совпавшее правило или дефолт.
    pub fn route(&self, flow: &FlowKey) -> Rule {
        self.rules
            .iter()
            .find(|rule| rule.matches(flow))
            .cloned()
            .unwrap_or_else(|| Rule::new("default", self.default))
    }

    /// Регистрирует fake-ip для хоста и возвращает адрес из `FAKE_IP_RANGE`.
    ///
    /// Повторный вызов для того же хоста возвращает тот же адрес (стабильный ключ
    /// потока, `03` §8).
    pub fn assign_fake_ip(&mut self, host: &str) -> IpAddr {
        self.fakeip.assign(host)
    }

    /// Сколько хостов сейчас держит fake-ip (телеметрия).
    pub fn fake_ip_entries(&self) -> usize {
        self.fakeip.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).expect("валидный адрес")
    }

    /// Контракт fake-ip: адреса выдаются только из `FAKE_IP_RANGE`, один хост —
    /// один стабильный адрес, и по нему поток позже узнаётся как тот же самый.
    #[test]
    fn contract_fake_ip_is_stable_and_in_range() {
        let mut engine = Engine::new(RouteAction::Route, Vec::new());
        let first = engine.assign_fake_ip("example.com");
        let again = engine.assign_fake_ip("example.com");
        assert_eq!(first, again, "один хост — один стабильный адрес");

        let range = Cidr::parse(FAKE_IP_RANGE).expect("константа FAKE_IP_RANGE парсится");
        assert!(range.contains(&first), "адрес внутри {FAKE_IP_RANGE}");

        let other = engine.assign_fake_ip("other.example");
        assert_ne!(first, other, "разные хосты — разные адреса");
        assert!(range.contains(&other));
        assert_eq!(engine.fake_ip_entries(), 2);
    }

    /// Контракт split-tunnel: `Block` отклоняет по домену, `Direct` — по CIDR,
    /// непокрытый поток уходит в дефолт `Route`. («Один FlowId на поток» — контракт
    /// `frame-session::open_stream`, здесь проверяется вердикт политики.)
    #[test]
    fn contract_route_actions() {
        let engine = Engine::new(
            RouteAction::Route,
            vec![
                Rule::new("block-tracker", RouteAction::Block)
                    .with_host("tracker.example"),
                Rule::new("lan-direct", RouteAction::Direct)
                    .with_cidr(Cidr::parse("192.168.0.0/16").expect("валидный CIDR")),
            ],
        );
        let key = |dst: IpAddr, host: Option<&str>| FlowKey {
            dst,
            dst_port: 443,
            host: host.map(str::to_owned),
        };

        let blocked = engine.route(&key(ip("203.0.113.5"), Some("tracker.example")));
        assert_eq!(blocked.action, RouteAction::Block);
        assert_eq!(blocked.name, "block-tracker");

        // Хост-матчер нечувствителен к регистру.
        let blocked_upper = engine.route(&key(ip("203.0.113.5"), Some("TRACKER.example")));
        assert_eq!(blocked_upper.action, RouteAction::Block);

        let direct = engine.route(&key(ip("192.168.1.10"), None));
        assert_eq!(direct.action, RouteAction::Direct);
        assert_eq!(direct.name, "lan-direct");

        let default = engine.route(&key(ip("203.0.113.5"), Some("example.com")));
        assert_eq!(default.action, RouteAction::Route, "дефолт для непокрытых");
        assert_eq!(default.name, "default");

        // Матчеры одного правила соединяются по И: чужой хост в той же подсети
        // под правило lan-direct не попадает, если правило требует и хост.
        let both = Rule::new("both", RouteAction::Direct)
            .with_host("a.example")
            .with_cidr(Cidr::parse("10.0.0.0/8").expect("валидный CIDR"));
        let engine_and = Engine::new(RouteAction::Route, vec![both]);
        assert_eq!(
            engine_and.route(&key(ip("10.1.2.3"), Some("a.example"))).action,
            RouteAction::Direct,
            "оба матчера совпали"
        );
        assert_eq!(
            engine_and.route(&key(ip("10.1.2.3"), Some("b.example"))).action,
            RouteAction::Route,
            "хост не совпал — правило не сработало"
        );
    }

    /// Границы CIDR: маска отсекает хост-часть, чужое семейство не совпадает.
    #[test]
    fn cidr_boundary_and_family_mismatch() {
        let cidr = Cidr::parse("198.18.0.0/16").expect("валидный CIDR");
        assert!(cidr.contains(&ip("198.18.42.7")));
        assert!(!cidr.contains(&ip("198.19.0.1")));
        assert!(!cidr.contains(&ip("::1")), "v4-префикс не матчит v6");
        let v6 = Cidr::parse("fd00::/8").expect("валидный CIDR");
        assert!(v6.contains(&ip("fd12::1")));
        assert!(!v6.contains(&ip("fe80::1")));
        assert_eq!(Cidr::parse("10.0.0.0/33"), None, "префикс длиннее 32 отклонён");
        assert_eq!(Cidr::parse("не-адрес/8"), None);
    }
}
