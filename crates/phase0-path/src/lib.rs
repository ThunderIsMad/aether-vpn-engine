//! `phase0-path` — склейка однохопового пути Phase 0 без GUI и сети.
//!
//! **In:** пакет от device-adapter (или мок-пакета), ключи сессии.
//! **Out:** зашифрованные кадры в `CoverBinding` (`MemBinding` в тестах).
//! **Deps:** `policy-engine`, `frame-session`, `transport-mux`, `crypto-core`.
//!
//! Пайплайн (`03-components.md`, порядок зависимостей):
//!
//! ```text
//! packet → policy-engine (route: Block/Direct/Route)
//!        → FrameSession::open_stream (FlowId из fake-ip или адреса)
//!        → FrameSession::seal_record
//!        → CoverBinding::send (кадр len(4B) ‖ record)
//! ```
//!
//! `Route::Block` — пакет отброшен, `Route::Direct` — в туннель не входит
//! (реальный egress мимо туннеля — Phase 1; здесь фиксируется решение).
//! Это **библиотека** склейки, не рантайм: планирование сокетов/потоков — Phase 1.

#![deny(unsafe_code)]

use crypto_core::{KRecord, KSession, RecordAead, RecordCrypto, RecordNonce};
use frame_session::{
    FlowId, RecordError, Session, SessionCrypto, SessionId, StreamId,
};
use policy_engine::{Engine, FlowKey, RouteAction};
use transport_mux::{BindingError, CoverBinding};

/// `sid` сессии: здесь константа вызова, владелец `sid` — `frame-session` (`03` §2).
pub fn session_id(bytes: [u8; 16]) -> SessionId {
    SessionId(bytes)
}

/// Адаптер `crypto-core` → `frame_session::SessionCrypto`.
///
/// Тот же контракт, что в harness `rotation-tests` (один шаг ratchet —
/// `HKDF(sid, K_record, "aether v3 record")`, seal/open — XChaCha20-Poly1305),
/// но живёт в рабочем крейте, чтобы прод-склейка и тесты шли одним кодом.
#[derive(Debug, Default)]
pub struct CoreCrypto;

impl SessionCrypto for CoreCrypto {
    fn ratchet(&self, session_id: &[u8; 16], k_record: &[u8; 32]) -> [u8; 32] {
        crypto_core::ratchet_record(session_id, &KSession(*k_record), 0).0
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

/// Результат одного шага пайплайна.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    /// Пакет отброшен политикой (`RouteAction::Block`).
    Blocked,
    /// Пакет направлен мимо туннеля (`RouteAction::Direct`); в Phase 0 это решение,
    /// реальный egress — Phase 1.
    Direct,
    /// Пакет ушёл в туннель: запись доставлена байндингу.
    Sent(StreamId),
}

/// Ошибка склейки.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    /// Байндинг отказал (`BindingError`): очередь переполнена или транспорт умер.
    Binding(BindingError),
}

/// Отправляет один пакет через пайплайн. Один вызов = одна запись frame-слоя.
///
/// `flows` — таблица соответствия fake-ip → `FlowId`: policy даёт решение по адресу,
/// а `FlowId` — стабильный ключ потока (`03` §8). Поток открывается лениво при первом
/// пакете (`open_stream` идемпотентен по `FlowId`).
pub fn send_packet(
    policy: &Engine,
    flows: &mut std::collections::HashMap<std::net::IpAddr, FlowId>,
    session: &mut Session,
    binding: &mut dyn CoverBinding,
    packet: &[u8],
) -> Result<StepOutcome, PathError> {
    let flow_key = packet_flow_key(packet);
    let rule = policy.route(&flow_key);
    match rule.action {
        RouteAction::Block => Ok(StepOutcome::Blocked),
        RouteAction::Direct => Ok(StepOutcome::Direct),
        RouteAction::Route => {
            let flow_id = if let Some(existing) = flows.get(&flow_key.dst) {
                *existing
            } else {
                let id = FlowId(next_flow_id(flows));
                flows.insert(flow_key.dst, id);
                id
            };
            let stream = session.open_stream(flow_id);
            let record = session.seal_record(stream, packet);
            binding
                .send(&record)
                .map(|()| StepOutcome::Sent(stream))
                .map_err(PathError::Binding)
        }
    }
}

/// `FlowId` = количество уже заведённых потоков + 1 (0 оставлен «неизвестному потоку»).
fn next_flow_id(flows: &std::collections::HashMap<std::net::IpAddr, FlowId>) -> u64 {
    flows.len() as u64 + 1
}

/// Извлекает ключ потока из пакета. Phase 0 распознаёт только IPv4; всё прочее
/// считается «адрес-неизвестен» и маршрутизируется дефолтом политики.
///
/// IPv4-заголовок: `IHL(4b) | version(4b) | … | dst_ip(последние 4 байта)`.
/// Порт не извлекается: для UDP/TCP нужен разбор L4 — Phase 1 (policy Phase 0
/// матчит по адресу и хосту).
fn packet_flow_key(packet: &[u8]) -> FlowKey {
    use std::net::Ipv4Addr;
    let dst = if packet.len() >= 20 && packet[0] >> 4 == 4 {
        let ihl = usize::from(packet[0] & 0x0F) * 4;
        if packet.len() >= ihl && ihl >= 20 {
            let o = ihl - 4;
            let [a, b, c, d] = [packet[o], packet[o + 1], packet[o + 2], packet[o + 3]];
            std::net::IpAddr::V4(Ipv4Addr::new(a, b, c, d))
        } else {
            return unknown_flow_key();
        }
    } else {
        return unknown_flow_key();
    };
    FlowKey {
        dst,
        dst_port: 0,
        host: None,
    }
}

/// Ключ потока «адрес неизвестен»: маршрутизируется дефолтом политики.
/// Свободная функция, а не `impl FlowKey` — тип чужой (orphan rule).
fn unknown_flow_key() -> FlowKey {
    FlowKey {
        dst: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        dst_port: 0,
        host: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_core::derive_session;
    use policy_engine::{Cidr, Rule};
    use std::net::{IpAddr, Ipv4Addr};
    use transport_mux::MemBinding;

    const SID: [u8; 16] = [0x5a; 16];

    fn session(k_session: [u8; 32]) -> Session {
        Session::new(SessionId(SID), k_session, Box::new(CoreCrypto))
    }

    /// Детерминированный ключ сессии для тестов: наш HKDF поверх handshake-hash
    /// (`02 §5`, формула K_session), вход — произвольные байты.
    fn test_key() -> [u8; 32] {
        derive_session(&SID, b"phase0-path test handshake hash").0
    }

    fn ipv4_packet(dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        // Минимальный IPv4-заголовок (ровно 20 B, IHL=5): version/IHL(1), DSCP(1),
        // total_len(2), id(2), flags/frag(2), ttl(1), proto(1), checksum(2),
        // src(4), dst(4) — dst по смещению 16, как читает `packet_flow_key`.
        let mut p = vec![0x45, 0, 0, 0];
        p.extend_from_slice(&[0, 0]); // id
        p.extend_from_slice(&[0, 0]); // flags/frag
        p.push(64); // ttl
        p.push(6); // proto TCP
        p.extend_from_slice(&[0, 0]); // checksum (не проверяем)
        p.extend_from_slice(&[10, 0, 0, 2]); // src
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(payload);
        let total = p.len() as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p
    }

    /// Полный путь: fake-ip пакет → policy Route → seal → MemBinding; принимающая
    /// сторона (зеркало сессии) вскрывает запись и получает исходные байты пакета.
    #[test]
    fn end_to_end_packet_reaches_binding_and_opens() {
        let mut policy = Engine::new(
            RouteAction::Route,
            vec![Rule::new("block", RouteAction::Block).with_host("tracker.example")],
        );
        let fake_ip = policy
            .assign_fake_ip("example.com")
            .expect("валидный хост резервирует адрес");

        let k = test_key();
        let mut sender = session(k);
        let mut binding = MemBinding::new(transport_mux::BindingCaps::QUIC);
        let mut flows = std::collections::HashMap::new();

        let packet = ipv4_packet(match fake_ip { IpAddr::V4(v4) => v4, _ => panic!("v4") }, b"GET /");
        let outcome = send_packet(&policy, &mut flows, &mut sender, &mut binding, &packet)
            .expect("route = Route");
        let stream = match outcome {
            StepOutcome::Sent(s) => s,
            other => panic!("ожидали Sent, получили {other:?}"),
        };

        // Кадр дошёл до байндинга: очередь содержит ровно одну запись этого потока.
        let pending = binding.take_pending();
        assert_eq!(pending.len(), 1, "одна запись в очереди байндинга");
        let (sid_out, frame) = &pending[0];
        assert_eq!(*sid_out, stream);

        // Приёмная сторона: зеркало сессии с тем же потоком вскрывает запись.
        let record = transport_mux::decode_frame(frame).expect("кадр разбирается");
        assert_eq!(record.stream_id, stream);
        let mut mirror = session(k);
        mirror.open_stream(FlowId(1));
        let plaintext = mirror
            .recv_record(&record)
            .expect("вскрытие прошло")
            .expect("не дубликат");
        assert_eq!(plaintext, packet, "получены исходные байты пакета");
    }

    /// Политика решает до шифрования: Block отбрасывает (в байндинге пусто),
    /// Direct не входит в туннель, и то и другое не расходует `seq` сессии.
    #[test]
    fn policy_gates_before_seal() {
        let policy = Engine::new(
            RouteAction::Route,
            vec![
                Rule::new("lan", RouteAction::Direct)
                    .with_cidr(Cidr::parse("192.168.0.0/16").expect("ok")),
                Rule::new("dst-block", RouteAction::Block)
                    .with_cidr(Cidr::parse("203.0.113.0/24").expect("ok")),
            ],
        );
        let k = test_key();
        let mut sender = session(k);
        let mut binding = MemBinding::new(transport_mux::BindingCaps::QUIC);
        let mut flows = std::collections::HashMap::new();

        let blocked = ipv4_packet(Ipv4Addr::new(203, 0, 113, 9), b"x");
        assert_eq!(
            send_packet(&policy, &mut flows, &mut sender, &mut binding, &blocked),
            Ok(StepOutcome::Blocked)
        );
        let direct = ipv4_packet(Ipv4Addr::new(192, 168, 1, 5), b"y");
        assert_eq!(
            send_packet(&policy, &mut flows, &mut sender, &mut binding, &direct),
            Ok(StepOutcome::Direct)
        );
        assert!(binding.take_pending().is_empty(), "ничего не ушло в туннель");
        assert_eq!(sender.last_seq(), frame_session::Seq(0), "seq не израсходован");

        // Непокрытый адрес — дефолт Route: запись уходит.
        let routed = ipv4_packet(Ipv4Addr::new(198, 18, 0, 9), b"z");
        assert!(matches!(
            send_packet(&policy, &mut flows, &mut sender, &mut binding, &routed),
            Ok(StepOutcome::Sent(_))
        ));
        assert_eq!(binding.take_pending().len(), 1);
    }

    /// Один поток на fake-ip: два пакета одного адреса — один `stream_id` и
    /// монотонный `seq`; разные адреса — разные потоки.
    #[test]
    fn flow_identity_is_stable_per_destination() {
        let mut policy = Engine::new(RouteAction::Route, Vec::new());
        let fake_a = policy
            .assign_fake_ip("a.example")
            .expect("валидный хост резервирует адрес");
        let fake_b = policy
            .assign_fake_ip("b.example")
            .expect("валидный хост резервирует адрес");
        let k = test_key();
        let mut sender = session(k);
        let mut binding = MemBinding::new(transport_mux::BindingCaps::QUIC);
        let mut flows = std::collections::HashMap::new();

        let to_v4 = |ip: IpAddr| match ip {
            IpAddr::V4(v4) => ipv4_packet(v4, b"p"),
            _ => panic!("v4"),
        };
        let s1 = match send_packet(&policy, &mut flows, &mut sender, &mut binding, &to_v4(fake_a))
        {
            Ok(StepOutcome::Sent(s)) => s,
            other => panic!("{other:?}"),
        };
        let s2 = match send_packet(&policy, &mut flows, &mut sender, &mut binding, &to_v4(fake_a))
        {
            Ok(StepOutcome::Sent(s)) => s,
            other => panic!("{other:?}"),
        };
        assert_eq!(s1, s2, "один адрес — один поток");

        let s3 = match send_packet(&policy, &mut flows, &mut sender, &mut binding, &to_v4(fake_b))
        {
            Ok(StepOutcome::Sent(s)) => s,
            other => panic!("{other:?}"),
        };
        assert_ne!(s1, s3, "другой адрес — другой поток");
        assert_eq!(sender.stream_table().len(), 2);
    }

    /// Отказ байндинга (`WouldBlock`/`TransportDown`) доходит до вызывающего
    /// как `PathError::Binding`, не проглатывается.
    #[test]
    fn binding_error_propagates() {
        let policy = Engine::new(RouteAction::Route, Vec::new());
        let k = test_key();
        let mut sender = session(k);
        let mut binding = MemBinding::new(transport_mux::BindingCaps::QUIC);
        binding.mark_closed();
        let mut flows = std::collections::HashMap::new();

        let packet = ipv4_packet(Ipv4Addr::new(198, 18, 0, 3), b"q");
        assert_eq!(
            send_packet(&policy, &mut flows, &mut sender, &mut binding, &packet),
            Err(PathError::Binding(transport_mux::BindingError::TransportDown))
        );
    }

    /// Не-IPv4 пакет не паникует и уходит по дефолту политики (адрес неизвестен).
    #[test]
    fn non_ipv4_packet_routes_by_default() {
        let policy = Engine::new(RouteAction::Route, Vec::new());
        let k = test_key();
        let mut sender = session(k);
        let mut binding = MemBinding::new(transport_mux::BindingCaps::QUIC);
        let mut flows = std::collections::HashMap::new();

        let outcome = send_packet(&policy, &mut flows, &mut sender, &mut binding, &[0x60, 0, 0, 0]);
        assert!(matches!(outcome, Ok(StepOutcome::Sent(_))));
    }

    /// Phase 1, кусок 1: тот же путь, но `CoverBinding` — обложка `SsPaddedBinding`
    /// вместо `MemBinding`. Пакет проходит policy → frame-session → cover-кадр,
    /// кадр вскрывается ключом обложки, вложенная запись — зеркальной сессией.
    #[test]
    fn packet_through_cover_binding_roundtrip() {
        use cover_ss2022::{decode_cover_frame, SsPaddedBinding};
        let mut policy = Engine::new(RouteAction::Route, Vec::new());
        let fake = policy
            .assign_fake_ip("example.com")
            .expect("валидный хост резервирует адрес");
        let sid = [0x5au8; 16];
        let cover =
            crypto_core::derive_cover_key(&sid, &crypto_core::derive_session(&sid, b"cover path test"));
        let k = test_key();
        let mut sender = session(k);
        let mut binding = SsPaddedBinding::with_padding(cover, 256);
        let mut flows = std::collections::HashMap::new();
        let packet = ipv4_packet(match fake { IpAddr::V4(v4) => v4, _ => panic!("v4") }, b"cover me");
        let outcome = send_packet(&policy, &mut flows, &mut sender, &mut binding, &packet)
            .expect("обложка принимает запись");
        let stream = match outcome {
            StepOutcome::Sent(s) => s,
            other => panic!("ожидали Sent, получили {other:?}"),
        };
        assert!(!binding.supports().no_hol, "обложка stream-класса");
        // Кадр обложки вынимается и вскрывается тем же ключом.
        let pending = binding.take_pending();
        assert_eq!(pending.len(), 1);
        let (_sid, frame) = &pending[0];
        let record = decode_cover_frame(&cover, frame).expect("cover-кадр вскрывается");
        assert_eq!(record.stream_id, stream);
        // Внутри — та же запись frame-слоя: зеркало вскрывает исходные байты пакета.
        let mut mirror = session(k);
        mirror.open_stream(FlowId(1));
        let plaintext = mirror
            .recv_record(&record)
            .expect("вскрытие записи прошло")
            .expect("не дубликат");
        assert_eq!(plaintext, packet);
    }

    /// Phase 1, кусок 2: тот же путь, но `CoverBinding` — каркас MASQUE CONNECT-UDP
    /// (`MasqueBinding`). Пакет проходит policy → frame-session → DATAGRAM-капсулу
    /// (`Context ID 0 ‖ record.encode()`), капсула вскрывается до записи, запись —
    /// зеркальной сессией до исходных байтов пакета. Caps каркаса — stream-класс:
    /// no-HOL/datagram заявит только реальный h3-клиент (см. доки cover-masque).
    #[test]
    fn packet_through_masque_binding_roundtrip() {
        use cover_masque::{decode_masque_frame, MasqueBinding};

        let mut policy = Engine::new(RouteAction::Route, Vec::new());
        let fake = policy
            .assign_fake_ip("example.org")
            .expect("валидный хост резервирует адрес");
        let k = test_key();
        let mut sender = session(k);
        let mut binding = MasqueBinding::new();
        let mut flows = std::collections::HashMap::new();

        let packet = ipv4_packet(match fake { IpAddr::V4(v4) => v4, _ => panic!("v4") }, b"masque me");
        let outcome = send_packet(&policy, &mut flows, &mut sender, &mut binding, &packet)
            .expect("байндинг принимает запись");
        let stream = match outcome {
            StepOutcome::Sent(s) => s,
            other => panic!("ожидали Sent, получили {other:?}"),
        };
        assert!(!binding.supports().no_hol, "каркас без h3: no-HOL не заявляем");

        // Капсула вынимается из очереди и вскрывается до записи frame-слоя.
        let pending = binding.take_pending();
        assert_eq!(pending.len(), 1);
        let (_sid, capsule) = &pending[0];
        let record = decode_masque_frame(capsule).expect("MASQUE-капсула вскрывается");
        assert_eq!(record.stream_id, stream);

        // Внутри — та же запись frame-слоя: зеркало вскрывает исходные байты пакета.
        let mut mirror = session(k);
        mirror.open_stream(FlowId(1));
        let plaintext = mirror
            .recv_record(&record)
            .expect("вскрытие записи прошло")
            .expect("не дубликат");
        assert_eq!(plaintext, packet);
    }
}
