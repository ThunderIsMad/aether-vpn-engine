//! MASQUE receiver-лаборатория (фича `e2e`, Phase 1): **прод-приёмник**
//! `cover_masque::receiver::serve_connect_udp` против прод-клиента
//! `MasqueH3Client` через реальный UDP-эхо-эндпоинт.
//!
//! Отличие от `masque_lab` (эхо-сервер-заглушка): здесь датаграмма клиента
//! реально выходит из per-CONNECT UDP-сокета приёмника, проходит по loopback
//! до UDP-эха, возвращается и оборачивается обратно в h3-датаграмму — то есть
//! проверен полный путь RFC 9298 §4, а не только капсульный формат.
//!
//! Клиентская сторона и TLS/QUIC — те же, что в `masque_lab` (прод-обложка,
//! `quic_lab` TOFU-пин).

#![cfg(feature = "e2e")]

use std::time::Duration;

use cover_masque::h3_live::{drive_until_closed, MasqueH3Client};
use cover_masque::{ConnectUdpRequest, MasqueBinding};
use transport_mux::CoverBinding as _;

const LAB_TIMEOUT: Duration = Duration::from_secs(15);

/// Поднимает UDP-эхо на 127.0.0.1:0; возвращает порт. Живёт, пока жив handle.
pub async fn spawn_udp_echo() -> Result<u16, String> {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("udp bind: {e}"))?;
    let port = sock
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?
        .port();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let (n, peer) = match sock.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(_) => return,
            };
            if sock.send_to(&buf[..n], peer).await.is_err() {
                return;
            }
        }
    });
    Ok(port)
}

/// Живой прогон: прод-клиент → прод-receiver → реальный UDP-эхо → обратно.
/// Возвращает записи, которые клиент получил через полный путь.
pub async fn masque_receiver_roundtrip() -> Result<Vec<Vec<u8>>, String> {
    let echo_port = spawn_udp_echo().await?;

    let cert = crate::quic_lab::self_signed_cert();
    let ca_der = cert
        .ca_cert_der
        .clone()
        .expect("лабораторный сертификат — цепочка CA→leaf");

    // Прод-receiver на свободном порту.
    let (endpoint_server, server_port) = crate::quic_lab::server_endpoint(0, &cert)?;
    tokio::spawn(async move {
        while let Some(incoming) = endpoint_server.accept().await {
            let Ok(conn) = incoming.await else { continue };
            let _ = cover_masque::receiver::serve_connect_udp(conn).await;
        }
    });

    // Прод-клиент: цель — UDP-эхо на loopback (литерал из шаблона).
    let request = ConnectUdpRequest::new(
        "localhost",
        "https",
        format!("/.well-known/masque/udp/127.0.0.1/{echo_port}/"),
        "127.0.0.1",
        echo_port,
    )
    .map_err(|e| format!("request: {e:?}"))?;

    let manifest = crate::NodeManifest {
        node_id: 1,
        port: server_port,
        identity: [0; 32],
        node_static: [0; 32],
        node_static_kem: vec![],
        quic_cert_der: ca_der,
    };

    let endpoint = crate::quic_lab::client_endpoint()?;
    let quinn_conn = crate::quic_lab::connect(&endpoint, &manifest).await?;

    let mut binding = MasqueBinding::new();
    let mut sent_records = Vec::new();
    for i in 0..3u64 {
        let payload = format!("receiver live record #{i}").into_bytes();
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

    let client = tokio::time::timeout(
        LAB_TIMEOUT,
        MasqueH3Client::connect_udp(quinn_conn.clone(), &request),
    )
    .await
    .map_err(|_| "connect_udp: timeout".to_string())?
    .map_err(|e| format!("connect_udp: {e}"))?;

    let (h3_conn_for_driver, mut half) = client.split();
    let driver = tokio::spawn(async move {
        let err = drive_until_closed(h3_conn_for_driver).await;
        Err::<(), _>(err)
    });

    let sent = half
        .drain_binding(&mut binding)
        .map_err(|e| format!("drain: {e}"))?;
    assert_eq!(sent, 3, "все три капсулы ушли датаграммами");

    // Читаем эхо через полный путь: капсула → (receiver) → UDP-эхо → капсула.
    let mut got = Vec::new();
    let deadline = tokio::time::Instant::now() + LAB_TIMEOUT;
    while got.len() < 3 {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return Err(format!(
                "echo: получили {}/3 датаграмм, время вышло",
                got.len()
            ));
        }
        let datagram = tokio::time::timeout(left, half.read_datagram())
            .await
            .map_err(|_| "echo: timeout".to_string())?
            .map_err(|e| format!("echo read: {e}"))?;
        let (_stream_id, payload) = datagram;
        let record = cover_masque::decode_masque_frame(&payload)
            .map_err(|e| format!("echo decode: {e:?}"))?;
        got.push(record.ciphertext);
    }
    got.sort();
    sent_records.sort();
    assert_eq!(got, sent_records, "эхо через UDP = исходные записи");

    drop(half);
    quinn_conn.close(0u32.into(), b"receiver lab done");
    let _ = driver.await;

    Ok(got)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Полный путь RFC 9298: прод-клиент ↔ прод-receiver ↔ живой UDP-эхо.
    #[tokio::test]
    async fn masque_receiver_live_udp_roundtrip() {
        let records = masque_receiver_roundtrip()
            .await
            .expect("живой receiver-прогон должен пройти");
        assert_eq!(records.len(), 3);
    }
}
