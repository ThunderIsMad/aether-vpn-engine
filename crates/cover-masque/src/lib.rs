//! `cover-masque` — обложка Phase 1, кусок 2: **MASQUE CONNECT-UDP (RFC 9298)**.
//!
//! **In:** уже sealed records frame-слоя (`frame_session::Record`), не сырой IP.
//! **Out:** UDP Proxying payload (`Context ID(0) ‖ UDP payload`, RFC 9298 §5) в
//! DATAGRAM-капсуле (`type(0x00) ‖ len(varint) ‖ value`, RFC 9297 §3.2).
//! **Deps:** `frame-session` (типы записей), `transport-mux` (контракт `CoverBinding`,
//! `DPI_PROFILE_MASQUE = 0x03`). `quinn`/`h3` не тянутся: пины уже в workspace, а
//! собственный h3-клиент — следующий шаг Phase 1 (см. «Граница каркаса» ниже).
//!
//! ## Граница каркаса: это НЕ RFC 9298-клиент
//!
//! Реализовано и проверено: **формат капсул и запроса** (encode/decode, varint,
//! Context ID 0, лимит 65527) — то, что можно проверить без сети. Не реализовано:
//! HTTP/3-сессия (Extended CONNECT по RFC 9220), exchange SETTINGS_H3_DATAGRAM,
//! чтение ответа узла, приёмная сторона (DATAGRAM-капсулы от узла). В CI нет ни
//! сети, ни рантайма — поэтому `MasqueBinding` кладёт готовые капсулы в `Outbox`
//! (как `SsPaddedBinding` кладёт cover-кадры): капсула — это кадр в Outbox, а не
//! QUIC DATAGRAM frame. Чекбокс «RFC 9298 interop» в `05-roadmap` остаётся `[ ]`.
//!
//! ## Честный caps
//!
//! Пока записи едут кадрами в Outbox (упорядоченная очередь), семантика доставки —
//! stream-класс: `no_hol: false, datagram: false`, как у `SsPaddedBinding`.
//! `no_hol: true, datagram: true` (клейм MASQUE поверх QUIC DATAGRAM, `02 §2.3`)
//! будет выставлен только реальным h3-клиентом, который мультиплексирует QUIC
//! streams и шлёт datagram'ы; врать в `BindingCaps` нельзя (`03` §4).

#![deny(unsafe_code)]

pub mod h3_live;

use frame_session::Record;
use transport_mux::{
    BindingCaps, BindingError, BindingFailure, CoverBinding, DEFAULT_OUTBOX_BYTES,
};

/// Профиль DPI этого байндинга: обложка «HTTP/3 прокси-трафик» (`02 §2.3`).
/// Константа объявлена в `transport-mux` (0x03), здесь — реэкспорт имени.
pub use transport_mux::DPI_PROFILE_MASQUE;

/// Capsule Type DATAGRAM (RFC 9297 §4): единственный тип, который байндинг кодирует.
pub const DATAGRAM_CAPSULE_TYPE: u64 = 0x00;

/// Context ID UDP payload (RFC 9298 §4/§5): 0 зарезервирован под UDP.
pub const CONTEXT_ID_UDP: u64 = 0;

/// Максимум UDP Proxying Payload при Context ID 0 (RFC 9298 §5: «longer than 65527»
/// запрещено — UDP header не позволяет payload длиннее).
pub const MAX_UDP_PAYLOAD: usize = 65527;

/// Максимум QUIC varint: 2⁶²−1 (RFC 9000 §16 — usable bits 62 при любой длине).
pub const MAX_VARINT: u64 = 0x3FFF_FFFF_FFFF_FFFF;

/// Ошибка декодирования MASQUE-кадра (`decode_masque_frame`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MasqueFrameError {
    /// Кадр не разбирается как капсула (короткий заголовок, `len` ≠ телу).
    BadCapsule,
    /// Тип капсулы не DATAGRAM.
    NotDatagram,
    /// Context ID ≠ 0 (не UDP payload — расширение, которое мы не регистрировали).
    BadContextId,
    /// UDP payload длиннее 65527 B (запрещено RFC 9298 §5).
    PayloadTooLong,
    /// Запрос Extended CONNECT malformed (RFC 9298 §3.4): пустое обязательное поле
    /// или порт 0.
    MalformedRequest,
    /// Вложенная запись frame-слоя не разбирается.
    BadRecord,
}

/// Кодирует QUIC varint (RFC 9000 §16): минимальное число байтов, 2MSB — длина.
/// Значение обязано влезать в 62 бита (`≤ MAX_VARINT`) — иначе паника в debug,
/// в release биты будут испорчены маркером длины.
pub fn encode_varint(value: u64, out: &mut Vec<u8>) {
    debug_assert!(value <= MAX_VARINT, "varint вмещает максимум 62 бита");
    if value < 0x40 {
        out.push(value as u8);
    } else if value < 0x4000 {
        out.extend_from_slice(&(0x4000 | value).to_be_bytes()[6..]);
    } else if value < 0x4000_0000 {
        out.extend_from_slice(&(0x8000_0000 | value).to_be_bytes()[4..]);
    } else {
        out.extend_from_slice(&(0xC000_0000_0000_0000 | value).to_be_bytes());
    }
}

/// Длина varint по первому байту (2 старших бита); `None` — вход пуст.
pub fn varint_len(first: u8) -> Option<usize> {
    match first >> 6 {
        0 => Some(1),
        1 => Some(2),
        2 => Some(4),
        _ => Some(8),
    }
}

/// Декодирует QUIC varint; `None` — вход обрезан. Неканонические (overlong) кодировки
/// отклоняются (аудит F-12): RFC 9000 §16 требует минимальной кодировки, «одно значение —
/// один проводной вид», иначе неоднозначность разбора между сторонами.
///
/// У любой длины (включая 8 байтов) старшие 2 бита первого байта — маркер длины,
/// а не значение: максимум varint — 2⁶²−1 (RFC 9000 §16).
pub fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let len = varint_len(*buf.first()?)?;
    let bytes = buf.get(..len)?;
    let mut value = [0u8; 8];
    // Байты поля кладутся в МЛАДШИЕ позиции массива, поэтому маркер длины
    // (2 верхних бита первого байта поля) сидит в бите len*8-1…len*8-2 значения,
    // а маска — несдвинутая: `[0x7B, 0xBD] & 0x3FFF = 0x3BBD` (15293, RFC 9000 §16).
    value[8 - len..].copy_from_slice(bytes);
    let raw = u64::from_be_bytes(value);
    let mask = match len {
        1 => 0x3F,
        2 => 0x3FFF,
        4 => 0x3FFF_FFFF,
        // У 8-байтового маркер тоже есть: максимум — 2⁶²−1, не u64::MAX.
        _ => MAX_VARINT,
    };
    let decoded = raw & mask;
    // Каноничность (RFC 9000 §16): n-байтовая форма — только для значений, не влезающих
    // в более короткую: 2B ≥ 2⁶, 4B ≥ 2¹⁴, 8B ≥ 2³⁰. Меньшее значение в длинной форме —
    // overlong, отвергаем (иначе одно значение имеет два проводных вида).
    let canonical = match len {
        1 => true,
        2 => decoded >= 0x40,
        4 => decoded >= 0x4000,
        _ => decoded >= 0x4000_0000,
    };
    if !canonical {
        return None;
    }
    Some((decoded, len))
}

/// UDP Proxying HTTP Datagram payload (RFC 9298 §5): `Context ID(varint) ‖ payload`.
/// Context ID фиксирован 0 — байндинг не регистрирует расширений.
pub fn encode_udp_proxying_payload(udp_payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + udp_payload.len());
    encode_varint(CONTEXT_ID_UDP, &mut out);
    out.extend_from_slice(udp_payload);
    out
}

/// Разбирает UDP Proxying payload: Context ID обязан быть 0, длина ≤ 65527.
pub fn decode_udp_proxying_payload(payload: &[u8]) -> Result<&[u8], MasqueFrameError> {
    let (context_id, used) = decode_varint(payload).ok_or(MasqueFrameError::BadCapsule)?;
    if context_id != CONTEXT_ID_UDP {
        return Err(MasqueFrameError::BadContextId);
    }
    let udp = payload.get(used..).ok_or(MasqueFrameError::BadCapsule)?;
    if udp.len() > MAX_UDP_PAYLOAD {
        return Err(MasqueFrameError::PayloadTooLong);
    }
    Ok(udp)
}

/// DATAGRAM-капсула (RFC 9297 §4): `type(0x00, varint) ‖ len(varint) ‖ value`.
/// Значение — UDP Proxying payload (`RFC 9298 §5`).
pub fn encode_datagram_capsule(udp_payload: &[u8]) -> Vec<u8> {
    let datagram = encode_udp_proxying_payload(udp_payload);
    let mut out = Vec::with_capacity(2 + datagram.len());
    encode_varint(DATAGRAM_CAPSULE_TYPE, &mut out);
    encode_varint(datagram.len() as u64, &mut out);
    out.extend_from_slice(&datagram);
    out
}

/// Разбирает DATAGRAM-капсулу; чужой тип, Context ID ≠ 0 или превышение лимита —
/// ошибки без паник. Возвращает UDP payload.
pub fn decode_datagram_capsule(capsule: &[u8]) -> Result<&[u8], MasqueFrameError> {
    let (capsule_type, used) = decode_varint(capsule).ok_or(MasqueFrameError::BadCapsule)?;
    if capsule_type != DATAGRAM_CAPSULE_TYPE {
        return Err(MasqueFrameError::NotDatagram);
    }
    let (declared_len, used2) =
        decode_varint(&capsule[used..]).ok_or(MasqueFrameError::BadCapsule)?;
    let value = capsule
        .get(used + used2..)
        .ok_or(MasqueFrameError::BadCapsule)?;
    if declared_len as usize != value.len() {
        return Err(MasqueFrameError::BadCapsule);
    }
    decode_udp_proxying_payload(value)
}

/// Запрос установления туннеля: Extended CONNECT (RFC 9298 §3.4, HTTP/3 по RFC 9220).
///
/// Это **описание запроса**, а не HTTP/3-кадры: `h3`-клиент (следующий шаг) превратит
/// его в HEADERS на request-стриме. Поля — ровно те, что §3.4 требует не пустыми:
/// `:method = CONNECT`, `:protocol = connect-udp`, непустые `:scheme`/`:path`/
/// `:authority`, `target_host`/`target_port` — из URI Template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectUdpRequest {
    /// `:authority` прокси (например, `proxy.example.org:4443`).
    pub authority: String,
    /// `:scheme` (RFC 9298 §3.4: не пустой; для h3 — `https`).
    pub scheme: String,
    /// `:path` после раскрытия URI Template (например,
    /// `/.well-known/masque/udp/192.0.2.6/443/`).
    pub path: String,
    /// `target_host` из шаблона (reg-name, IPv4 или percent-encoded IPv6 literal).
    pub target_host: String,
    /// `target_port`: 1..=65535 (RFC 9298 §3).
    pub target_port: u16,
}

impl ConnectUdpRequest {
    /// Значение `:protocol` — upgrade token из RFC 9298 §8.1.
    pub const PROTOCOL: &'static str = "connect-udp";

    /// Собирает запрос; непустые `authority`/`scheme`/`path`/`target_host` и порт
    /// в диапазоне — обязательны (§3.4: иначе запрос malformed).
    pub fn new(
        authority: impl Into<String>,
        scheme: impl Into<String>,
        path: impl Into<String>,
        target_host: impl Into<String>,
        target_port: u16,
    ) -> Result<Self, MasqueFrameError> {
        let req = Self {
            authority: authority.into(),
            scheme: scheme.into(),
            path: path.into(),
            target_host: target_host.into(),
            target_port,
        };
        if req.authority.is_empty()
            || req.scheme.is_empty()
            || req.path.is_empty()
            || req.target_host.is_empty()
            || req.target_port == 0
        {
            return Err(MasqueFrameError::MalformedRequest);
        }
        Ok(req)
    }

    /// Заголовки запроса в порядке псевдо-поля → обычные; `capsule-protocol: ?1` —
    /// по RFC 9298 §3.5 (пример Figure 5). Проверка форм — дело h3-клиента.
    pub fn headers(&self) -> Vec<(&'static str, String)> {
        vec![
            (":method", "CONNECT".to_string()),
            (":protocol", Self::PROTOCOL.to_string()),
            (":scheme", self.scheme.clone()),
            (":path", self.path.clone()),
            (":authority", self.authority.clone()),
            ("capsule-protocol", "?1".to_string()),
        ]
    }
}

/// MASQUE CONNECT-UDP байндинг — **каркас** (`03` §4, Phase 1 кусок 2).
///
/// Структура повторяет `SsPaddedBinding`: `Outbox` (backpressure байтами) +
/// асинхронный отказ ровно один раз. Отличие: кадр в очереди — DATAGRAM-капсула
/// с UDP Proxying payload, внутрь которой положена запись frame-слоя. h3-сессии
/// нет, поэтому caps — stream-класс (см. «Честный caps» в шапке модуля).
#[derive(Debug)]
pub struct MasqueBinding {
    outbox: transport_mux::Outbox,
    failure: Option<BindingFailure>,
    closed: bool,
}

impl MasqueBinding {
    /// Байндинг с потолком очереди по умолчанию.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_OUTBOX_BYTES)
    }

    /// Байндинг с явным потолком очереди (в тестах — маленький для WouldBlock).
    pub fn with_capacity(cap_bytes: usize) -> Self {
        Self {
            outbox: transport_mux::Outbox::new(cap_bytes),
            failure: None,
            closed: false,
        }
    }

    /// Закрывает канал: следующий `send` даст `TransportDown` + `BindingFailure::Closed`.
    pub fn mark_closed(&mut self) {
        self.closed = true;
    }

    /// Закрыт ли канал.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Забирает очередь капсул (в тестах — эмуляция async-писателя).
    pub fn take_pending(&mut self) -> Vec<(frame_session::StreamId, Vec<u8>)> {
        self.outbox.drain()
    }

    /// Размер очереди в байтах.
    pub fn pending_bytes(&self) -> usize {
        self.outbox.bytes()
    }

    /// Инжектирует асинхронный отказ — путь к FSM морфа (`02 §4`).
    pub fn inject_failure(&mut self, failure: BindingFailure) {
        self.failure = Some(failure);
    }
}

impl Default for MasqueBinding {
    fn default() -> Self {
        Self::new()
    }
}

impl CoverBinding for MasqueBinding {
    fn send(&mut self, rec: &Record) -> Result<(), BindingError> {
        if self.closed {
            self.failure = Some(BindingFailure::Closed);
            return Err(BindingError::TransportDown);
        }
        // UDP payload капсулы — сама запись frame-слоя (`rec.encode()`): обложка
        // не шифрует второй раз, она упаковывает уже sealed record.
        let body = rec.encode();
        if body.len() > MAX_UDP_PAYLOAD {
            // RFC 9298 §5: «endpoints MUST NOT send HTTP Datagrams … longer than
            // 65527» — такую запись байндинг не возьмёт (не отказ транспорта).
            return Err(BindingError::Unsupported);
        }
        let capsule = encode_datagram_capsule(&body);
        self.outbox.push(rec.stream_id, capsule)
    }

    fn supports(&self) -> BindingCaps {
        // Каркас: кадры едут через упорядоченный Outbox — no-HOL и datagram нельзя
        // заявлять, пока нет реального h3-клиента (QUIC streams + DATAGRAM frames).
        BindingCaps {
            no_hol: false,
            datagram: false,
            dpi_profile: DPI_PROFILE_MASQUE,
        }
    }

    fn on_failure(&mut self) -> Option<BindingFailure> {
        self.failure.take()
    }
}

/// Вскрывает капсулу из очереди до записи frame-слоя (принимающая сторона теста).
pub fn decode_masque_frame(capsule: &[u8]) -> Result<Record, MasqueFrameError> {
    let udp_payload = decode_datagram_capsule(capsule)?;
    Record::decode(udp_payload).map_err(|_| MasqueFrameError::BadRecord)
}

#[cfg(test)]
mod tests {
    use super::*;
    use frame_session::{RecordType, Seq, StreamId};

    fn record(seq: u64, payload: &[u8]) -> Record {
        Record {
            kind: RecordType::Data,
            stream_id: StreamId(0),
            flags: 0,
            seq: Seq(seq),
            ciphertext: payload.to_vec(),
        }
    }

    /// Varint по примерам RFC 9000 §16: 0/1/63/15293/494878333/151288809941952654
    /// и минимальная кодировка (значение, что влезает в 2 байта, не кодируется 4-мя).
    #[test]
    fn varint_matches_rfc9000_examples() {
        let cases: &[(u64, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            (63, &[0x3F]),
            (15293, &[0x7B, 0xBD]),
            (494878333, &[0x9D, 0x7F, 0x3E, 0x7D]),
            (
                151288809941952654,
                &[0xC2, 0x19, 0x7C, 0x5E, 0xFF, 0x14, 0xE8, 0x8E],
            ),
        ];
        for (value, expected) in cases {
            let mut encoded = Vec::new();
            encode_varint(*value, &mut encoded);
            assert_eq!(encoded, *expected, "encode {value}");
            assert_eq!(decode_varint(&encoded), Some((*value, encoded.len())));
        }
        // Минимальность: 15293 (0x3BBD) — ровно 2 байта, не 4.
        let mut encoded = Vec::new();
        encode_varint(15293, &mut encoded);
        assert_eq!(encoded.len(), 2);
    }

    /// Varint: обрезанный вход — `None`, не паника; максимум 2⁶²−1 кодируется
    /// 8 байтами с маркером длины в старших битах.
    #[test]
    fn varint_rejects_truncated_and_roundtrips_max() {
        assert_eq!(decode_varint(&[]), None);
        assert_eq!(decode_varint(&[0x40]), None, "обрезан 2-байтовый");
        assert_eq!(decode_varint(&[0x80, 0]), None, "обрезан 4-байтовый");
        assert_eq!(decode_varint(&[0xC0]), None, "обрезан 8-байтовый");
        let max = MAX_VARINT; // 2⁶²−1 — максимум RFC 9000 §16
        let mut encoded = Vec::new();
        encode_varint(max, &mut encoded);
        // Старшие 62 бита значения — все единицы, маркер (2 бита) сливается с ними.
        assert_eq!(encoded, [0xFF; 8]);
        assert_eq!(decode_varint(&encoded), Some((max, 8)));
        // Чужеродный вход: 8-байтовый varint с «лишними» битами маскируется —
        // читаются только младшие 62 бита, паники нет.
        assert_eq!(
            decode_varint(&[0xFF; 8]),
            Some((MAX_VARINT, 8)),
            "старшие 2 бита — маркер длины, не значение"
        );
        // Каноничность (аудит F-12): overlong-кодировка — отвергается. Те же значения,
        // что выше кодируются короткой формой, в длинной форме недопустимы.
        assert_eq!(decode_varint(&[0x40, 0x00]), None, "0 в 2-байтовой форме");
        assert_eq!(
            decode_varint(&[0x80, 0x00, 0x00, 0x01]),
            None,
            "1 в 4-байтовой"
        );
        assert_eq!(
            decode_varint(&[0x01]),
            Some((0x01, 1)),
            "1 в 1-байтовой форме — ок"
        );
        assert_eq!(
            decode_varint(&[0x41, 0x00]),
            Some((0x0100, 2)),
            "256 в 2-байтовой форме — ок (0x0100 ≥ 2⁶)"
        );
        assert_eq!(
            decode_varint(&[0x40, 0x01]),
            None,
            "1 в 2-байтовой форме — overlong"
        );
        assert_eq!(
            decode_varint(&[0x7B, 0xBD]),
            Some((15293, 2)),
            "15293 в 2-байтовой форме — ок (0x3BBD ≥ 2⁶)"
        );
    }

    /// Roundtrip капсулы: запись frame-слоя пакуется в UDP payload → DATAGRAM-капсулу
    /// и вскрывается байт в байт.
    #[test]
    fn capsule_roundtrip() {
        let rec = record(7, b"masque payload");
        let capsule = encode_datagram_capsule(&rec.encode());
        assert_eq!(decode_masque_frame(&capsule).expect("вскрывается"), rec);
    }

    /// Структура капсулы по RFC: тип 0x00 одним байтом, длина — varint, внутри —
    /// Context ID 0 перед payload.
    #[test]
    fn capsule_layout_matches_rfc() {
        let udp = [0xAAu8; 300];
        let capsule = encode_datagram_capsule(&udp);
        assert_eq!(capsule[0], 0x00, "DATAGRAM capsule type = 0x00");
        assert_eq!(
            decode_varint(&capsule[1..]),
            Some((301, 2)),
            "len(varint) = 1 + 300"
        );
        let (context_id, used) = decode_varint(&capsule[3..]).expect("context id");
        assert_eq!(context_id, 0, "Context ID 0 = UDP payload");
        assert_eq!(used, 1, "Context ID 0 кодируется одним байтом");
        assert_eq!(&capsule[3 + used..], &udp[..], "payload без изменений");
    }

    /// Битые капсулы и чужой ключ/тип: ошибки без паник (обрезанный заголовок,
    /// несовпадение длины, не-DATAGRAM тип, Context ID ≠ 0, payload > 65527,
    /// битая вложенная запись).
    #[test]
    fn malformed_frames_are_errors() {
        assert_eq!(
            decode_datagram_capsule(&[]),
            Err(MasqueFrameError::BadCapsule)
        );
        assert_eq!(
            decode_datagram_capsule(&[0x00]),
            Err(MasqueFrameError::BadCapsule),
            "нет len"
        );
        assert_eq!(
            decode_datagram_capsule(&[0x00, 0x05, 0x00, 0xAA]),
            Err(MasqueFrameError::BadCapsule),
            "len ≠ телу"
        );
        assert_eq!(
            decode_datagram_capsule(&[0x01, 0x00]),
            Err(MasqueFrameError::NotDatagram),
            "capsule type ≠ DATAGRAM"
        );
        assert_eq!(
            decode_datagram_capsule(&[0x00, 0x01, 0x01]),
            Err(MasqueFrameError::BadContextId),
            "Context ID ≠ 0"
        );
        // Объявленная длина совпадает с телом, но payload > 65527 → PayloadTooLong
        // (а не BadCapsule): value = ctx(1) + udp(65528), len = MAX+2.
        let mut oversized = vec![0x00u8];
        encode_varint((MAX_UDP_PAYLOAD + 2) as u64, &mut oversized);
        oversized.push(0x00);
        oversized.resize(oversized.len() + MAX_UDP_PAYLOAD + 1, 0);
        assert_eq!(
            decode_datagram_capsule(&oversized),
            Err(MasqueFrameError::PayloadTooLong),
            "payload > 65527 запрещён"
        );
        // Капсула корректна, но внутри не запись frame-слоя.
        assert_eq!(
            decode_masque_frame(&encode_datagram_capsule(&[0xDE, 0xAD])),
            Err(MasqueFrameError::BadRecord)
        );
    }

    /// Лимит RFC 9298 §5 соблюдается на границе: 65527 проходит, 65528 — нет.
    /// Первый байт входа — Context ID 0, остальные — UDP payload.
    #[test]
    fn udp_payload_limit_boundary() {
        let mut ok = vec![0x00u8];
        ok.resize(MAX_UDP_PAYLOAD + 1, 0); // payload = 65527 B
        assert_eq!(decode_udp_proxying_payload(&ok), Ok(&ok[1..]));

        let mut too_long = vec![0x00u8];
        too_long.resize(MAX_UDP_PAYLOAD + 2, 0); // payload = 65528 B
        assert_eq!(
            decode_udp_proxying_payload(&too_long),
            Err(MasqueFrameError::PayloadTooLong)
        );
    }

    /// Запрос Extended CONNECT: заголовки по §3.4/Figure 5; malformed-входы
    /// (пустое поле, порт 0) отвергаются.
    #[test]
    fn connect_udp_request_shape() {
        let req = ConnectUdpRequest::new(
            "proxy.example.org:4443",
            "https",
            "/.well-known/masque/udp/192.0.2.6/443/",
            "192.0.2.6",
            443,
        )
        .expect("запрос корректен");
        assert_eq!(req.headers()[0], (":method", "CONNECT".to_string()));
        assert_eq!(req.headers()[1], (":protocol", "connect-udp".to_string()));
        assert_eq!(req.headers()[5], ("capsule-protocol", "?1".to_string()));
        for malformed in [
            ConnectUdpRequest::new("", "https", "/p/", "h", 443),
            ConnectUdpRequest::new("a", "", "/p/", "h", 443),
            ConnectUdpRequest::new("a", "https", "", "h", 443),
            ConnectUdpRequest::new("a", "https", "/p/", "", 443),
            ConnectUdpRequest::new("a", "https", "/p/", "h", 0),
        ] {
            assert!(malformed.is_err(), "malformed обязан отвергаться");
        }
    }

    /// Caps не врут: каркас без h3-клиента — stream-класс, как у `SsPaddedBinding`.
    #[test]
    fn caps_skeleton_not_rfc_client() {
        let binding = MasqueBinding::new();
        let caps = binding.supports();
        assert!(!caps.no_hol, "каркас кладёт капсулы в Outbox: no-HOL нет");
        assert!(!caps.datagram, "QUIC DATAGRAM frames не отправляются");
        assert_eq!(caps.dpi_profile, DPI_PROFILE_MASQUE);
    }

    /// Отказные пути как у остальных байндингов: закрытый канал — синхронный
    /// `TransportDown` + асинхронный `Closed` ровно один раз; инжектированный
    /// отказ доходит до FSM.
    #[test]
    fn closed_channel_and_failure_paths() {
        let mut binding = MasqueBinding::new();
        binding.mark_closed();
        assert_eq!(
            binding.send(&record(1, b"x")),
            Err(BindingError::TransportDown)
        );
        assert_eq!(binding.on_failure(), Some(BindingFailure::Closed));
        assert_eq!(binding.on_failure(), None, "событие отдаётся один раз");

        let mut binding = MasqueBinding::new();
        binding.inject_failure(BindingFailure::Probed);
        assert_eq!(binding.on_failure(), Some(BindingFailure::Probed));
        assert_eq!(binding.on_failure(), None);
    }

    /// Очередь: капсулы вынимаются и вскрываются; порядок сохранён; переполнение —
    /// `WouldBlock` (backpressure, не OOM).
    #[test]
    fn queue_roundtrip_and_backpressure() {
        let mut binding = MasqueBinding::new();
        for seq in 0..3u64 {
            binding
                .send(&record(seq, b"queued payload"))
                .expect("очередь не переполнена");
        }
        let pending = binding.take_pending();
        assert_eq!(pending.len(), 3, "три капсулы в очереди");
        for (i, (stream, capsule)) in pending.iter().enumerate() {
            assert_eq!(*stream, StreamId(0));
            let decoded = decode_masque_frame(capsule).expect("капсула вскрывается");
            assert_eq!(decoded.seq, Seq(i as u64), "порядок и seq сохранены");
            assert_eq!(decoded.ciphertext, b"queued payload");
        }
        assert!(binding.take_pending().is_empty(), "очередь вычерпана");

        let mut small = MasqueBinding::with_capacity(64);
        let big_payload = vec![0u8; 200];
        assert_eq!(
            small.send(&record(1, &big_payload)),
            Err(BindingError::WouldBlock)
        );
    }

    /// Запись длиннее 65527 B байндинг не берёт (RFC 9298 §5: «MUST NOT send»):
    /// синхронный `Unsupported` без паники и без попадания в очередь.
    #[test]
    fn send_rejects_payload_over_rfc_limit() {
        let mut binding = MasqueBinding::new();
        let oversized = vec![0u8; MAX_UDP_PAYLOAD + 1];
        assert_eq!(
            binding.send(&record(1, &oversized)),
            Err(BindingError::Unsupported)
        );
        assert!(binding.take_pending().is_empty(), "в очередь не попала");
        // Граница: размер payload подобран так, что encode() записи ровно 65527
        // (заголовок записи — type+seq+stream+flags+len(3B ULEB128) = 7 байт).
        // Считаем от фактического кодирования, а не руками (урок куска 1).
        let at_limit = vec![0u8; MAX_UDP_PAYLOAD - 7];
        let rec = record(2, &at_limit);
        assert_eq!(
            rec.encode().len(),
            MAX_UDP_PAYLOAD,
            "граница: encode() = 65527"
        );
        binding.send(&rec).expect("payload на границе проходит");
        assert_eq!(binding.take_pending().len(), 1);
    }
}
