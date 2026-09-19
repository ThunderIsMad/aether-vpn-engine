//! Receiver-side (прод-сервер) CONNECT-UDP (RFC 9298 §3.4/§4): симметрия
//! клиентскому live-слою (`MasqueH3Client`, кусок 4). Один h3-коннект:
//! Extended CONNECT-UDP → 2xx → проксирование HTTP/3-датаграмм ↔ UDP-сокет.
//!
//! Формат payload'а — тот же прод-путь, что у клиента: `encode/decode_
//! udp_proxying_payload` (Context ID 0, RFC 9298 §5). Каждому CONNECT —
//! свой UDP-сокет к целевому адресу; датаграмма клиента после срезки
//! Context ID уходит в сокет, ответ с сокета оборачивается обратно и
//! уходит клиенту на его же стрим (Quarter Stream ID сохраняет h3-datagram).
//!
//! Целевой адрес берётся из URI-шаблона `:path` запроса
//! `/.well-known/masque/udp/{target_host}/{target_port}/` (RFC 9298 §3.4,
//! параграф 2.1.1 пути-шаблона): литералы IPv4/IPv6 в path h3 0.0.8
//! percent-декодирует (src/proto/headers.rs → `resolve_uri_template`... в
//! нашем дереве `Request::uri()` уже раскрытый `http::Uri`). Рег-имена здесь
//! НЕ резолвим: узел проксирует по литералам, DNS — ответственность клиента
//! (тот же выбор, что в `ConnectUdpRequest`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use h3::server::RequestResolver;
use h3_quinn::Connection as QConnection;
use quinn::Connection as QuinnConnection;

use crate::{
    decode_udp_proxying_payload, encode_udp_proxying_payload, MasqueFrameError, MAX_UDP_PAYLOAD,
};

/// Ошибки receiver-пути.
#[derive(Debug)]
pub enum ReceiverError {
    /// h3-соединение/запрос/ответ.
    H3(String),
    /// Целевой адрес из `:path` не разобрался (не литерал/порт вне диапазона).
    BadTarget(String),
    /// UDP-сокет к цели не открылся.
    Udp(std::io::Error),
    /// Payload датаграммы не прошёл разбор UDP Proxying (Context ID ≠ 0 и пр.).
    Frame(MasqueFrameError),
}

impl std::fmt::Display for ReceiverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::H3(e) => write!(f, "h3: {e}"),
            Self::BadTarget(e) => write!(f, "target: {e}"),
            Self::Udp(e) => write!(f, "udp: {e}"),
            Self::Frame(e) => write!(f, "frame: {e:?}"),
        }
    }
}

impl std::error::Error for ReceiverError {}

/// Разбирает `:path` Extended CONNECT-UDP по URI-шаблону RFC 9298 §3.4:
/// `/.well-known/masque/udp/{target_host}/{target_port}/`. Возвращает
/// `SocketAddr` литерала (IPv4/IPv6; percent-decoding здесь — для IPv6-скобок).
fn parse_target_from_path(path: &str) -> Result<SocketAddr, ReceiverError> {
    const PREFIX: &str = "/.well-known/masque/udp/";
    let rest = path
        .strip_prefix(PREFIX)
        .ok_or_else(|| ReceiverError::BadTarget(format!("path не по шаблону: {path}")))?;
    let rest = rest.trim_end_matches('/');
    let (host_raw, port_raw) = rest
        .rsplit_once('/')
        .ok_or_else(|| ReceiverError::BadTarget(format!("нет порта в path: {path}")))?;
    // h3/uri-template может оставить percent-encoding для литералов; раскрываем
    // только безопасный поднабор (%XX → байт), без паник.
    let host = percent_decode(host_raw).ok_or_else(|| {
        ReceiverError::BadTarget(format!("host: плохой percent-encoding: {host_raw}"))
    })?;
    let port: u16 = port_raw
        .parse()
        .map_err(|_| ReceiverError::BadTarget(format!("порт: {port_raw}")))?;
    if port == 0 {
        return Err(ReceiverError::BadTarget("порт 0".into()));
    }
    // Сокетный литерал: IPv4 как есть; IPv6 (после срезания скобок шаблона)
    // обратно в скобках — так требует SocketAddr::from_str.
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let addr: SocketAddr = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
    .parse()
    .map_err(|_| ReceiverError::BadTarget(format!("литерал: {host}:{port}")))?;
    Ok(addr)
}

/// Минимальный percent-decode (RFC 3986): `%XX` → байт, остальное как есть.
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            let hi = (hex[0] as char).to_digit(16)?;
            let lo = (hex[1] as char).to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Обрабатывает ОДНО quinn-соединение: h3-сессия, один Extended CONNECT-UDP
/// (обложка шлёт единственный запрос на соединение), затем прокси-цикл:
/// клиент → UDP и UDP → клиент до закрытия любой из сторон.
///
/// Тело запроса не читается (CONNECT-UDP не несёт тела до капсул), ответ —
/// `200` с `capsule-protocol: ?1` (RFC 9298 §4, Figure 3).
pub async fn serve_connect_udp(quinn_conn: QuinnConnection) -> Result<(), ReceiverError> {
    let mut h3_conn = h3::server::builder()
        .enable_datagram(true)
        .enable_extended_connect(true)
        .build(QConnection::new(quinn_conn))
        .await
        .map_err(|e| ReceiverError::H3(format!("build: {e}")))?;

    use h3_datagram::datagram_handler::HandleDatagramsExt as _;
    let mut reader = h3_conn.get_datagram_reader();

    let resolver = h3_conn
        .accept()
        .await
        .map_err(|e| ReceiverError::H3(format!("accept: {e}")))?
        .ok_or_else(|| ReceiverError::H3("соединение закрыто до запроса".into()))?;
    let (request, mut stream) = resolver
        .resolve_request()
        .await
        .map_err(|e| ReceiverError::H3(format!("resolve: {e}")))?;

    let protocol = request.extensions().get::<h3::ext::Protocol>().copied();
    if protocol != Some(h3::ext::Protocol::CONNECT_UDP) {
        return Err(ReceiverError::H3(format!(
            "ожидали connect-udp, получено {protocol:?}"
        )));
    }

    let target = parse_target_from_path(request.uri().path())?;
    // Per-CONNECT UDP-сокет: connected-socket — ядро само фильтрует чужие
    // источники, отвечать можно без адресной пары.
    let udp = tokio::net::UdpSocket::bind(if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await
    .map_err(ReceiverError::Udp)?;
    udp.connect(target).await.map_err(ReceiverError::Udp)?;

    let response = http::Response::builder()
        .status(http::StatusCode::OK)
        .header("capsule-protocol", "?1")
        .body(())
        .expect("200 без тела — статически валиден");
    stream
        .send_response(response)
        .await
        .map_err(|e| ReceiverError::H3(format!("send 200: {e}")))?;

    // RFC 9298 §4: после 2xx — обмен датаграммами. Две задачи:
    //  1) клиент → цель: h3-датаграмма → срезать Context ID → UDP-сокет;
    //  2) цель → клиент: UDP → обернуть Context ID → h3-датаграмма на стрим.
    // sender'у нужен stream_id запроса; reader — общий на соединение.
    let request_stream_id = stream.id();
    let mut sender = h3_conn.get_datagram_sender(request_stream_id);

    let uplink = async {
        loop {
            let datagram = match reader.read_datagram().await {
                Ok(d) => d,
                Err(_) => return, // соединение закрыто — нормальный конец
            };
            let payload = datagram.into_payload();
            let udp_bytes = match decode_udp_proxying_payload(&payload) {
                Ok(b) => b,
                // Чужой Context ID/битые капсулы молча дропаем (RFC 9298 §5:
                // получатель обязан игнорировать неизвестные Context ID).
                Err(MasqueFrameError::BadContextId) => continue,
                Err(e) => {
                    debug_assert!(false, "битая капсула от нашего клиента: {e:?}");
                    continue;
                }
            };
            if udp_bytes.len() > MAX_UDP_PAYLOAD {
                continue;
            }
            if udp.send(udp_bytes).await.is_err() {
                return;
            }
        }
    };

    let downlink = async {
        let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
        loop {
            let n = match udp.recv(&mut buf).await {
                Ok(n) => n,
                Err(_) => return,
            };
            let payload = encode_udp_proxying_payload(&buf[..n]);
            if sender.send_datagram(Bytes::from(payload)).is_err() {
                return;
            }
        }
    };

    // Первое закрытие рвёт join: uplink живёт на reader'е соединения, downlink —
    // на UDP-сокете; конец любого = конец обслуживания (соединение закроет drop).
    tokio::select! {
        _ = uplink => {}
        _ = downlink => {}
    }
    Ok(())
}

/// Реэкспорт для тестов: резолвер используется в интеграционной лаборатории.
pub type H3Resolver = RequestResolver<QConnection, Bytes>;

/// Карта «CONNECT → цель» для наблюдаемости (лаборатория/метрики; прод —
/// на узле, не в библиотеке).
pub type TargetMap = Arc<std::sync::Mutex<HashMap<SocketAddr, u64>>>;

#[cfg(test)]
mod tests {
    use super::*;

    /// URI-шаблон RFC 9298 §3.4: IPv4-литерал + порт.
    #[test]
    fn target_parse_ipv4() {
        let addr = parse_target_from_path("/.well-known/masque/udp/192.0.2.6/443/")
            .expect("валидный путь");
        assert_eq!(
            addr,
            "192.0.2.6:443".parse::<SocketAddr>().expect("сокет"),
            "IPv4-литерал → SocketAddr"
        );
    }

    /// IPv6-литерал в скобках (шаблон требует скобки для литералов).
    #[test]
    fn target_parse_ipv6_bracketed() {
        let addr = parse_target_from_path("/.well-known/masque/udp/%5B2001:db8::1%5D/53")
            .expect("percent-encoded IPv6");
        assert_eq!(
            addr,
            "[2001:db8::1]:53".parse::<SocketAddr>().expect("сокет")
        );
    }

    /// Не-литерал (reg-name) отвергается: прокси по литералам (см. шапку модуля).
    #[test]
    fn target_rejects_reg_name() {
        assert!(parse_target_from_path("/.well-known/masque/udp/example.com/443/").is_err());
        assert!(parse_target_from_path("/.well-known/masque/udp/192.0.2.6/0").is_err());
        assert!(parse_target_from_path("/other/192.0.2.6/443/").is_err());
    }

    /// Полный UDP Proxying payload-цикл на прод-функциях: encode (клиентская
    /// форма) → decode (серверная) — байт-в-байт.
    #[test]
    fn payload_roundtrip_context_id_zero() {
        let payload = encode_udp_proxying_payload(b"\xde\xad\xbe\xef");
        let (context_id, used) = crate::decode_varint(&payload).expect("varint читается");
        assert_eq!(context_id, crate::CONTEXT_ID_UDP);
        let udp = decode_udp_proxying_payload(&payload).expect("payload");
        assert_eq!(&payload[used..], udp, "срез после Context ID");
        assert_eq!(udp, b"\xde\xad\xbe\xef");
    }
}
