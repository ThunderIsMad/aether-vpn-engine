//! MASQUE-лаборатория (фича `e2e`, Phase 1 кусок 4): **живой h3-сервер**
//! CONNECT-UDP + двусторонний прогон обложки на loopback.
//!
//! Серверная сторона здесь — **лабораторная**, не прод: прод-приёмник обложек
//! (узел с пулом UDP-сокетов, интеграция с frame-зеркалом сессии) — отдельный
//! кусок Phase 1. Что сервер лаборатории делает по спеке RFC 9298/9297:
//!
//! 1. принимает h3-соединение (`h3::server::Connection` над `h3_quinn`) с
//!    SETTINGS: H3_DATAGRAM=1, ENABLE_CONNECT_PROTOCOL=1 (`server::builder()`);
//! 2. принимает Extended CONNECT-UDP (`:protocol: connect-udp` — сервер h3 0.0.8
//!    кладёт `Protocol` в `Request::extensions`), отвечает `200`;
//! 3. эхо: каждая HTTP/3-датаграмма клиента возвращается на его же стрим
//!    (Quarter Stream ID совпадает) — приёмник-заглушка, не UDP-прокси.
//!
//! Клиентская сторона — **прод-тип** `cover_masque::h3_live::MasqueH3Client`
//! поверх прод-`MasqueBinding`: склейка «пакет → frame-сессия → капсула →
//! h3-датаграмма → эхо сервера → вскрытие капсулы → исходная запись».
//!
//! TLS/QUIC транспорт — те же лабораторные функции `quic_lab` (TOFU-пин
//! сертификата, SAN `localhost`), что у основного e2e-прогона.

#![cfg(feature = "e2e")]

use std::time::Duration;

use bytes::Bytes;
use cover_masque::h3_live::{drive_until_closed, MasqueH3Client};
use cover_masque::{ConnectUdpRequest, MasqueBinding};
use transport_mux::CoverBinding as _;

/// Как долго тест ждёт соединения/ответов: лаборатория на loopback, запас —
/// на холодный handshake.
const LAB_TIMEOUT: Duration = Duration::from_secs(15);

/// Поднимает h3 CONNECT-UDP эхо-сервер на свободном порту; возвращает порт.
///
/// Задача живёт, пока жив возвращённый `JoinHandle`: завершается сама, когда
/// клиент закрывает QUIC-соединение.
pub async fn spawn_h3_echo_server(cert: crate::quic_lab::LabCert) -> Result<u16, String> {
    let (endpoint, port) = crate::quic_lab::server_endpoint(0, &cert)?;
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let quinn_conn = match incoming.await {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            let _ = serve_h3_echo(quinn_conn).await;
        }
    });
    Ok(port)
}

/// Один quinn-коннект: h3-сессия + эхо датаграмм до закрытия пира.
async fn serve_h3_echo(quinn_conn: quinn::Connection) -> Result<(), String> {
    let mut h3_conn = h3::server::builder()
        .enable_datagram(true)
        .enable_extended_connect(true)
        .build(h3_quinn::Connection::new(quinn_conn))
        .await
        .map_err(|e| format!("server h3 build: {e}"))?;

    use h3_datagram::datagram_handler::HandleDatagramsExt as _;
    let reader_from_client = h3_conn.get_datagram_reader();

    // Принять ровно один Extended CONNECT-UDP (обложка шлёт единственный запрос).
    let resolver = h3_conn
        .accept()
        .await
        .map_err(|e| format!("accept: {e}"))?
        .ok_or("соединение закрыто до запроса")?;
    let (request, mut stream) = resolver
        .resolve_request()
        .await
        .map_err(|e| format!("resolve: {e}"))?;

    let protocol = request.extensions().get::<h3::ext::Protocol>().copied();
    if protocol != Some(h3::ext::Protocol::CONNECT_UDP) {
        return Err(format!("ожидали connect-udp, получено {protocol:?}"));
    }

    let response = http::Response::builder()
        .status(http::StatusCode::OK)
        .body(())
        .expect("200 без тела");
    stream
        .send_response(response)
        .await
        .map_err(|e| format!("send 200: {e}"))?;

    // Эхо: датаграмма клиента → обратно на его стрим (тот же Quarter Stream ID).
    // h3-datagram кодирует/декодирует RFC 9297 §4 на обеих сторонах.
    let mut reader = reader_from_client;
    let echo_task = async move {
        loop {
            let datagram = match reader.read_datagram().await {
                Ok(d) => d,
                Err(_) => return, // соединение закрыто — нормальное завершение
            };
            let mut back = h3_conn.get_datagram_sender(datagram.stream_id());
            let payload: Bytes = datagram.into_payload();
            let _ = back.send_datagram(payload);
        }
    };
    tokio::spawn(echo_task);

    // Держать стрим и драйвер живыми до конца обмена.
    let _ = stream.recv_data().await;
    Ok(())
}

/// Живой прогон: прод-обложка (каркас + live-слой) против лабораторного сервера.
///
/// Это и есть недостающая половина клейма: двусторонний обмен MASQUE-капсулами
/// по HTTP/3-датаграммам через реальный quinn. После него `caps` live-слоя
/// (datagram: true) проверен обоими концами.
pub async fn masque_live_roundtrip() -> Result<Vec<Vec<u8>>, String> {
    let cert = crate::quic_lab::self_signed_cert();
    // Пин — CA цепочки (корень доверия); leaf сервер отдаст сам (см. quic_lab).
    let ca_der = cert
        .ca_cert_der
        .clone()
        .expect("лабораторный сертификат — цепочка CA→leaf");
    let port = spawn_h3_echo_server(cert).await?;
    let manifest = crate::NodeManifest {
        node_id: 1,
        port,
        identity: [0; 32],
        node_static: [0; 32],
        node_static_kem: vec![],
        quic_cert_der: ca_der,
    };

    let endpoint = crate::quic_lab::client_endpoint()?;
    let quinn_conn = crate::quic_lab::connect(&endpoint, &manifest).await?;

    let request = ConnectUdpRequest::new(
        "localhost",
        "https",
        "/.well-known/masque/udp/192.0.2.6/443/",
        "192.0.2.6",
        443,
    )
    .map_err(|e| format!("request: {e:?}"))?;

    let mut binding = MasqueBinding::new();

    // Три записи frame-слоя (наполнение повторяет интеграцию `phase0-path`):
    // каркас кадрирует их в капсулы — live-слой должен вычерпать все три.
    let mut sent_records = Vec::new();
    for i in 0..3u64 {
        let payload = format!("masque live record #{i}").into_bytes();
        sent_records.push(payload.clone());
        binding
            .send(&frame_session::Record {
                kind: frame_session::RecordType::Data,
                stream_id: frame_session::StreamId(0),
                flags: 0,
                seq: frame_session::Seq(i),
                ciphertext: payload,
            })
            .map_err(|e| format!("binding send: {e:?}"))?;
    }

    // Прод-live-слой: h3-сессия + Extended CONNECT + вычерпывание Outbox.
    let client = tokio::time::timeout(
        LAB_TIMEOUT,
        MasqueH3Client::connect_udp(quinn_conn.clone(), &request),
    )
    .await
    .map_err(|_| "connect_udp: timeout".to_string())?
    .map_err(|e| format!("connect_udp: {e}"))?;

    let (h3_conn_for_driver, mut half) = client.split();

    // Драйвер h3 — фоновая задача: без него сервер не увидит SETTINGS клиента.
    let driver = tokio::spawn(async move {
        let err = drive_until_closed(h3_conn_for_driver).await;
        Err::<(), _>(err)
    });

    let sent = half
        .drain_binding(&mut binding)
        .map_err(|e| format!("drain: {e}"))?;
    assert_eq!(sent, 3, "все три капсулы ушли датаграммами");

    // Эхо: читать, пока не соберём все три; порядок датаграмм QUIC не гарантирует.
    let mut got = Vec::new();
    let deadline = tokio::time::Instant::now() + LAB_TIMEOUT;
    while got.len() < 3 {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return Err(format!("echo: получили {}/3 датаграмм, время вышло", got.len()));
        }
        let datagram = tokio::time::timeout(left, half.read_datagram())
            .await
            .map_err(|_| "echo: timeout".to_string())?
            .map_err(|e| format!("echo read: {e}"))?;
        let (_stream_id, payload) = datagram;
        // Payload эха — капсула куска 2: вскрываем прод-функцией в запись.
        let record = cover_masque::decode_masque_frame(&payload)
            .map_err(|e| format!("echo decode: {e:?}"))?;
        got.push(record.ciphertext);
    }
    got.sort();
    sent_records.sort();
    assert_eq!(got, sent_records, "эхо = исходные записи (byte-for-byte)");

    // Корректное завершение: закрыть QUIC — сервер выйдет из accept-цикла.
    drop(half);
    quinn_conn.close(0u32.into(), b"masque lab done");
    let _ = driver.await;

    Ok(got)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Живой двусторонний прогон: prod-клиент (MasqueBinding + MasqueH3Client) ↔
    /// лабораторный h3-эхо-сервер на реальном quinn. Требует UDP-loopback —
    /// допустимо в тестах фичи `e2e` (см. quic_lab::endpoints_bind).
    #[tokio::test]
    async fn masque_rfc9298_live_roundtrip() {
        let records = masque_live_roundtrip()
            .await
            .expect("живой MASQUE-прогон должен пройти");
        assert_eq!(records.len(), 3);
    }
}
