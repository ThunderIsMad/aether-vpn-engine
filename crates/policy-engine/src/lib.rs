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
//! - Пул fake-ip: нормализация хоста (`normalize_host`), потолок `FAKE_IP_POOL_CAP`
//!   с вытеснением старейших привязок вместо паники на исчерпании (`assign` возвращает
//!   `Result`) — страница с десятками тысяч уникальных поддоменов не должна ронять
//!   клиентский процесс (закрытие аудита F-SEC: panic-DoS + unbounded HashMap).

#![deny(unsafe_code)]

use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

/// Диапазон fake-ip DNS (`03-components.md` §8).
pub const FAKE_IP_RANGE: &str = "198.18.0.0/16";

/// Первый выдаваемый fake-ip: `.0` — адрес сети, `.1` традиционно шлюз.
const FAKE_IP_FIRST: u32 = 0xC612_0002; // 198.18.0.2
/// Последний выдаваемый fake-ip (вещательный адрес `198.18.255.255` не выдаётся).
const FAKE_IP_LAST: u32 = 0xC612_FFFE; // 198.18.255.254

/// Потолок пула fake-ip на процесс.
///
/// Пул — по записи на хост; без потолка DNS-флуд растит `HashMap` неограниченно (OOM).
/// **CAP ≤ размеру диапазона** (F-03, аудит 3): выдача адресов — FAKE_IP_FIRST..=FAKE_IP_LAST,
/// т.е. ровно 65 533 уникальных адресов; прежний CAP 65 536 делал вытеснение недостижимым
/// (диапазон кончался раньше потолка) и исчерпание — перманентным. При исчерпании адресов
/// вытесняется старейшая привязка (FIFO — ближайший к LRU аналог без меток времени;
/// точный LRU/TTL — решение Phase 1/2 вместе с DNS-TTL), её адрес возвращается в пул.
pub const FAKE_IP_POOL_CAP: usize = (FAKE_IP_LAST - FAKE_IP_FIRST) as usize + 1;

/// Ручная проверка инварианта «CAP ≤ диапазон» (константы — до `const`-вычисления размера
/// диапазона читаемый; это условие формулы выше).
const _: () = assert!(FAKE_IP_POOL_CAP <= 65_533);

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
    ///
    /// Хост нормализуется при задании (`normalize_host`): `tracker.example.` — тот же
    /// матчер, что и `tracker.example`. `None` (пустой/невалидный) → матчер не задаётся,
    /// правило остаётся без host-условия — это видно вызывающему по полю `host`.
    pub fn with_host(mut self, host: &str) -> Self {
        self.host = normalize_host(host);
        self
    }

    /// Задаёт CIDR-матчер назначения.
    pub fn with_cidr(mut self, cidr: Cidr) -> Self {
        self.cidr = Some(cidr);
        self
    }

    fn matches(&self, flow: &FlowKey) -> bool {
        if let Some(host) = &self.host {
            // Нормализуем и сторону потока: `TRacker.example.` обязан совпасть с
            // правилом `tracker.example`, а не уйти в дефолт мимо блок-листа.
            let Some(flow_host) = flow.host.as_deref().and_then(normalize_host) else {
                return false;
            };
            if &flow_host != host {
                return false;
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

/// Каноническая форма хоста для всех host-сравнений движка (правила и пул fake-ip).
///
/// ASCII-lowercase, один завершающий dot срезается, пустой/с управляющими символами/
/// с пробельными или недопустимыми для имени хоста байтами → `None`. Без нормализации
/// `tracker.example.` и `Example.COM` обходят block-правила и плодят вторые записи
/// в пуле (аудит F-SEC). IDNA для не-ASCII — отдельное решение, здесь не делается:
/// не-ASCII имя отбрасывается как невалидное.
pub fn normalize_host(host: &str) -> Option<String> {
    if host.is_empty() {
        return None;
    }
    let stripped = host.strip_suffix('.').unwrap_or(host);
    let lowered = stripped.to_ascii_lowercase();
    if lowered.is_empty() {
        return None;
    }
    for ch in lowered.chars() {
        let ok = ch.is_ascii_alphanumeric() || ch == '-' || ch == '.';
        if !ok {
            return None;
        }
    }
    Some(lowered)
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

/// Пул fake-ip из `FAKE_IP_RANGE`: один нормализованный хост — один стабильный адрес.
///
/// Стабильность — контракт (`03` §8): по fake-ip поток позже узнаётся как тот же самый.
/// Потолок `FAKE_IP_POOL_CAP` с FIFO-вытеснением старейших привязок вместо паники:
/// исчерпание диапазона и переполнение пула — ошибки, возвращаемые вызывающему, а не
/// крах процесса (аудит F-SEC: expect в lib-коде — process-fatal политика).
/// Вытеснение **возвращает адрес в пул** (free-list, F-03): при исчерпании монотонного
/// хвоста диапазона новый хост получает адрес вытесненной привязки, а не перманентный
/// отказ — пул не «выдыхается» навсегда.
#[derive(Debug, Clone)]
pub struct FakeIpPool {
    by_host: HashMap<String, IpAddr>,
    /// Порядок выдачи привязок — для FIFO-вытеснения при переполнении пула.
    order: Vec<String>,
    /// Следующий адрес диапазона; стартует с `FAKE_IP_FIRST`, исчерпание —
    /// `next > FAKE_IP_LAST`.
    next: u32,
    /// Адреса, возвращённые вытеснением (FIFO free-list) — выдаются раньше
    /// продолжения монотонного хвоста.
    free: VecDeque<u32>,
}

impl Default for FakeIpPool {
    /// Ручной Default вместо derive: `next` обязан стартовать с `FAKE_IP_FIRST`,
    /// а не с нуля адреса — derive дал бы первый fake-ip `0.0.0.0`.
    fn default() -> Self {
        Self {
            by_host: HashMap::new(),
            order: Vec::new(),
            next: FAKE_IP_FIRST,
            free: VecDeque::new(),
        }
    }
}

/// Ошибка выдачи fake-ip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeIpError {
    /// Хост не нормализуется (пустой, управляющие/недопустимые символы).
    BadHost,
    /// Диапазон `FAKE_IP_RANGE` исчерпан и free-list пуст: при `CAP ≤ диапазон`
    /// это значит «вытеснять нечего» — аномалия, а не штатный путь.
    Exhausted,
}

impl FakeIpPool {
    fn assign(&mut self, host: &str) -> Result<IpAddr, FakeIpError> {
        let host = normalize_host(host).ok_or(FakeIpError::BadHost)?;
        if let Some(addr) = self.by_host.get(&host) {
            return Ok(*addr);
        }
        // Пул полон → вытесняем старейшую привязку (FIFO), её адрес — в free-list.
        while self.by_host.len() >= FAKE_IP_POOL_CAP {
            let Some(oldest) = self.order.first().cloned() else {
                return Err(FakeIpError::Exhausted);
            };
            self.order.remove(0);
            if let Some(IpAddr::V4(v4)) = self.by_host.remove(&oldest) {
                self.free.push_back(u32::from(v4));
            }
        }
        // Сначала — возвращённые вытеснением адреса (F-03), потом монотонный хвост.
        let addr_u32 = if let Some(reused) = self.free.pop_front() {
            reused
        } else {
            if self.next > FAKE_IP_LAST {
                return Err(FakeIpError::Exhausted);
            }
            let fresh = self.next;
            self.next = self.next.saturating_add(1);
            fresh
        };
        let addr = IpAddr::V4(Ipv4Addr::from(addr_u32));
        self.by_host.insert(host.clone(), addr);
        self.order.push(host);
        Ok(addr)
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
    /// потока, `03` §8). Хост нормализуется (`normalize_host`): регистр и завершающий
    /// dot не создают вторых записей. Ошибки — `BadHost` (невалидный хост) и `Exhausted`
    /// (диапазон исчерпан); паники нет — классификация потока не должна ронять процесс.
    pub fn assign_fake_ip(&mut self, host: &str) -> Result<IpAddr, FakeIpError> {
        self.fakeip.assign(host)
    }

    /// Сколько хостов сейчас держит fake-ip (телеметрия).
    pub fn fake_ip_entries(&self) -> usize {
        self.fakeip.len()
    }

    /// Есть ли привязка для хоста (телеметрия/тесты, не путь выдачи).
    pub fn fake_ip_contains(&self, host: &str) -> bool {
        match normalize_host(host) {
            Some(h) => self.fakeip.by_host.contains_key(&h),
            None => false,
        }
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
        let first = engine
            .assign_fake_ip("example.com")
            .expect("валидный хост резервирует адрес");
        let again = engine
            .assign_fake_ip("example.com")
            .expect("повтор — тот же хост");
        assert_eq!(first, again, "один хост — один стабильный адрес");

        let range = Cidr::parse(FAKE_IP_RANGE).expect("константа FAKE_IP_RANGE парсится");
        assert!(range.contains(&first), "адрес внутри {FAKE_IP_RANGE}");

        let other = engine
            .assign_fake_ip("other.example")
            .expect("второй хост резервирует адрес");
        assert_ne!(first, other, "разные хосты — разные адреса");
        assert!(range.contains(&other));
        assert_eq!(engine.fake_ip_entries(), 2);
    }

    /// Контракт нормализации: регистр и завершающий dot не создают вторых записей пула
    /// и не обходят блок-правила; пустой/недопустимый хост — `BadHost`, а не запись.
    #[test]
    fn contract_host_normalization_rejects_and_dedups() {
        assert_eq!(
            normalize_host("Example.COM."),
            Some("example.com".to_string()),
            "lowercase + strip trailing dot"
        );
        assert_eq!(normalize_host(""), None, "пустой хост невалиден");
        assert_eq!(normalize_host("."), None, "точка без имени невалидна");
        assert_eq!(
            normalize_host("exa mple.com"),
            None,
            "пробел в имени невалиден"
        );
        assert_eq!(
            normalize_host("ex\u{1}ample.com"),
            None,
            "управляющий символ невалиден"
        );
        assert_eq!(
            normalize_host("пример.test"),
            None,
            "не-ASCII без IDNA отбрасывается, а не кладётся в пул"
        );

        let mut engine = Engine::new(RouteAction::Route, Vec::new());
        let a = engine
            .assign_fake_ip("Example.COM.")
            .expect("нормализуемый хост принимается");
        let b = engine
            .assign_fake_ip("example.com")
            .expect("тот же хост после нормализации");
        assert_eq!(a, b, "регистр/точка не дают второй адрес");
        assert_eq!(engine.fake_ip_entries(), 1, "один хост — одна запись пула");
        assert_eq!(
            engine.assign_fake_ip(""),
            Err(FakeIpError::BadHost),
            "пустой хост — ошибка, не запись"
        );

        // Host-матчер правил нормализуется так же: `tracker.example.` блокируется,
        // `TRacker.example` тоже — обход блокировки точкой/регистром невозможен.
        let engine = Engine::new(
            RouteAction::Route,
            vec![Rule::new("block-tracker", RouteAction::Block).with_host("tracker.example.")],
        );
        let key = |host: &str| FlowKey {
            dst: ip("203.0.113.5"),
            dst_port: 443,
            host: Some(host.to_owned()),
        };
        assert_eq!(engine.route(&key("tracker.example")).action, RouteAction::Block);
        assert_eq!(engine.route(&key("tracker.example.")).action, RouteAction::Block);
        assert_eq!(engine.route(&key("TRACKER.example")).action, RouteAction::Block);
        assert_eq!(engine.route(&key("tracker.example.org")).action, RouteAction::Route);
    }

    /// Контракт отказов пула: переполнение пула — не паника (F-SEC), вытеснение — FIFO.
    /// С F-03 исчерпание диапазона не перманентно (см. тест recovery ниже): здесь
    /// фиксируем стабильность существующих привязок при полной занятости диапазона.
    #[test]
    fn contract_pool_exhaustion_errors_and_evicts_instead_of_panic() {
        let mut engine = Engine::new(RouteAction::Route, Vec::new());
        let first = engine
            .assign_fake_ip("oldest.example")
            .expect("первый адрес диапазона");

        // Выдаем адреса до последнего: FAKE_IP_FIRST..=FAKE_IP_LAST заняты уникальными хостами.
        let span = (FAKE_IP_LAST - FAKE_IP_FIRST) as usize;
        for i in 0..span {
            let host = format!("h{i}.example");
            engine
                .assign_fake_ip(&host)
                .expect("диапазона хватает на все привязки");
        }
        assert_eq!(engine.fake_ip_entries(), FAKE_IP_POOL_CAP.min(span + 1));

        // Существующая привязка по-прежнему резолвится в свой адрес.
        assert_eq!(
            engine.assign_fake_ip("oldest.example").expect("стабильный адрес"),
            first,
            "повтор исчерпанного пула не ломает старые привязки"
        );
    }

    /// Контракт FIFO-вытеснения: при переполнении пула старейшая привязка вытесняется,
    /// потолок удерживается — HashMap не растёт без границ.
    #[test]
    fn contract_pool_fifo_eviction_keeps_cap() {
        let mut pool = FakeIpPool {
            by_host: HashMap::new(),
            order: Vec::new(),
            next: FAKE_IP_FIRST,
            free: VecDeque::new(),
        };
        // Заполняем пул синтетически (не через assign: диапазон и так весь CAP).
        for i in 0..FAKE_IP_POOL_CAP {
            let host = format!("x{i}.example");
            pool.by_host
                .insert(host.clone(), IpAddr::V4(Ipv4Addr::from(FAKE_IP_FIRST)));
            pool.order.push(host);
        }
        let evicted = pool.order[0].clone();

        pool.assign("fresh.example")
            .expect("вытеснение освобождает место под новый хост");
        assert_eq!(pool.len(), FAKE_IP_POOL_CAP, "потолок удержан");
        assert!(!pool.by_host.contains_key(&evicted), "старейшая вытеснена");
        assert!(pool.by_host.contains_key("fresh.example"));
    }

    /// F-03 (аудит 3): исчерпание диапазона НЕ перманентно — вытеснение возвращает адрес
    /// в пул (free-list), новый хост получает адрес вытесненной привязки. И инвариант
    /// CAP ≤ размеру диапазона: вытеснение достижимо ровно на последнем адресе диапазона,
    /// «мёртвой зоны» между CAP и диапазоном больше нет.
    #[test]
    fn contract_pool_exhaustion_recovers_via_eviction_free_list() {
        let mut engine = Engine::new(RouteAction::Route, Vec::new());
        let span = (FAKE_IP_LAST - FAKE_IP_FIRST) as usize;
        assert_eq!(
            FAKE_IP_POOL_CAP,
            span + 1,
            "CAP равен числу выдаваемых адресов диапазона: вытеснение достижимо (F-03)"
        );

        // Занимаем весь диапазон: CAP = span+1 уникальных адресов.
        let oldest_addr = engine
            .assign_fake_ip("oldest.example")
            .expect("первый адрес диапазона");
        for i in 0..span {
            engine
                .assign_fake_ip(&format!("h{i}.example"))
                .expect("диапазон ровно покрывает CAP привязок");
        }
        assert_eq!(engine.fake_ip_entries(), FAKE_IP_POOL_CAP);

        // Пул полон и диапазон исчерпан, но вытеснение возвращает адрес: новый хост жив.
        let recycled = engine
            .assign_fake_ip("fresh.example")
            .expect("вытеснение старейшей отдаёт её адрес — исчерпание не перманентно (F-03)");
        assert_eq!(recycled, oldest_addr, "новый хост получил адрес вытесненной первой");
        assert!(!engine.fake_ip_contains("oldest.example"), "старейшая вытеснена");
        assert_eq!(engine.fake_ip_entries(), FAKE_IP_POOL_CAP, "потолок удержан");

        // Существующие привязки стабильны после вытеснения.
        let second_addr = engine
            .assign_fake_ip("h0.example")
            .expect("непотревоженная привязка жива");
        assert_ne!(second_addr, recycled);
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
