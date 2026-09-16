//! Wire-слой E2E: length-префикс поверх QUIC-стримов и парсер форматов, заданных
//! прод-крейтами. Никаких собственных крипто-форматов здесь нет:
//!
//! * mint-запрос — `kind 0x01 ‖ node_id(4B)` как `Rotation::request_ticket`
//!   (`key-coordinator`) **плюс лабораторное расширение** `sid(16) ‖ client_auth(32) ‖
//!   last_seq(8)` — то, что в проде узел узнаёт из авторизованного набора манифеста и
//!   своего состояния handshake. `K_session` в запросе **не ходит**: узел, который провёл
//!   Noise_IK с клиентом, вывел его сам (`IkResponder::respond`), пересылать секрет нет
//!   причин ни в проде, ни в лаборатории.
//! * `RESUME` — `ClientRotation::build_resume` байт в байт: `kind(0x02) ‖ len(2B) ‖
//!   ticket_blob ‖ nonce(24B) ‖ AEAD{K_resume}`, `ticket_blob` вне AEAD (`02 §3.3`).
//! * `RESUME_ACK` — формат harness-мока `rotation-tests`: `kind(0x01) ‖ nonce(24B) ‖
//!   AEAD{K_resume}(continuity(8) ‖ window(16) ‖ eph_node(32) ‖ sig_node(64))`, AAD — сам
//!   запрос. Прод-крейт ACK-кадр пока не собирает (проверка — в `key-coordinator`,
//!   `accept_response`), для живого прогона собирать его пока приходится здесь;
//!   задокументировано в `docs/phase-reports/e2e-manual.md`.

#![cfg_attr(not(test), deny(unsafe_code))]

use crypto_core::{RecordAead, RecordCrypto};
use std::io::ErrorKind;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Тег bi-стрима handshake (Noise_IK msg1/msg2).
pub const TAG_HANDSHAKE: u8 = 0x01;
/// Тег bi-стрима mint-запроса.
pub const TAG_MINT: u8 = 0x02;
/// Тег bi-стрима RESUME.
pub const TAG_RESUME: u8 = 0x03;

/// Расширение mint-запроса лаборатории: `sid(16) ‖ client_auth(32) ‖ last_seq(8)` — 56 B.
pub const MINT_EXT_LEN: usize = 16 + 32 + 8;
/// Полная длина mint-запроса лаборатории: `kind(1) ‖ node_id(4) ‖ ext_len(2) ‖ ext`.
pub const MINT_REQUEST_LEN: usize = 1 + 4 + 2 + MINT_EXT_LEN;

/// Ошибка wire-слоя.
#[derive(Debug)]
pub enum WireError {
    /// Соединение/стрим закрыт.
    Closed,
    /// Кадр не соответствует формату.
    BadFrame(String),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "stream closed"),
            Self::BadFrame(reason) => write!(f, "bad frame: {reason}"),
        }
    }
}

/// Читает один length-префиксованный кадр: `len(4B BE) ‖ payload` (лимит 256 KiB).
pub async fn read_frame(recv: &mut (impl AsyncReadExt + Unpin)) -> Result<Vec<u8>, WireError> {
    let mut prefix = [0u8; 4];
    match recv.read_exact(&mut prefix).await {
        Ok(_) => {}
        Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Err(WireError::Closed),
        Err(err) => return Err(WireError::BadFrame(format!("read len: {err}"))),
    }
    let len = u32::from_be_bytes(prefix) as usize;
    if len > 256 * 1024 {
        return Err(WireError::BadFrame(format!("frame too long: {len}")));
    }
    let mut payload = vec![0u8; len];
    recv.read_exact(&mut payload)
        .await
        .map_err(|err| WireError::BadFrame(format!("read payload: {err}")))?;
    Ok(payload)
}

/// Пишет length-префиксованный кадр.
pub async fn send_frame(
    send: &mut (impl AsyncWriteExt + Unpin),
    payload: &[u8],
) -> Result<(), WireError> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    send.write_all(&out)
        .await
        .map_err(|err| WireError::BadFrame(format!("write frame: {err}")))?;
    send.flush()
        .await
        .map_err(|err| WireError::BadFrame(format!("flush: {err}")))?;
    Ok(())
}

/// Читает кадр и возвращает `(тег, payload)`: первый байт payload — тег стрима.
pub async fn read_tagged(
    recv: &mut (impl AsyncReadExt + Unpin),
) -> Result<(u8, Vec<u8>), WireError> {
    let payload = read_frame(recv).await?;
    let (tag, rest) = payload.split_first().ok_or(WireError::Closed)?;
    Ok((*tag, rest.to_vec()))
}

/// Пишет кадр с тегом в первом байте.
pub async fn send_tagged(
    send: &mut (impl AsyncWriteExt + Unpin),
    tag: u8,
    payload: &[u8],
) -> Result<(), WireError> {
    let mut buf = Vec::with_capacity(1 + payload.len());
    buf.push(tag);
    buf.extend_from_slice(payload);
    send_frame(send, &buf).await
}

/// Собирает mint-запрос лаборатории: `KIND_MINT_REQ(0x01) ‖ node_id(4B BE) ‖ ext_len(2B BE) ‖
/// sid ‖ client_auth ‖ last_seq`. Без `K_session` — см. шапку модуля.
pub fn build_mint_request(
    node_id: u32,
    session_id: [u8; 16],
    client_auth: [u8; 32],
    last_seq: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(MINT_REQUEST_LEN);
    out.push(0x01); // KIND_MINT_REQ — как в `Rotation::request_ticket`
    out.extend_from_slice(&node_id.to_be_bytes());
    out.extend_from_slice(&(MINT_EXT_LEN as u16).to_be_bytes());
    out.extend_from_slice(&session_id);
    out.extend_from_slice(&client_auth);
    out.extend_from_slice(&last_seq.to_be_bytes());
    out
}

/// Разбирает mint-запрос лаборатории; не тот формат — `None`.
pub fn parse_mint_request(request: &[u8]) -> Option<(u32, [u8; 16], [u8; 32], u64)> {
    if request.len() != MINT_REQUEST_LEN || request.first() != Some(&0x01) {
        return None;
    }
    let node_id = u32::from_be_bytes(request[1..5].try_into().ok()?);
    let ext_len = u16::from_be_bytes(request[5..7].try_into().ok()?) as usize;
    if ext_len != MINT_EXT_LEN {
        return None;
    }
    let sid = request[7..23].try_into().ok()?;
    let client_auth = request[23..55].try_into().ok()?;
    let last_seq = u64::from_be_bytes(request[55..63].try_into().ok()?);
    Some((node_id, sid, client_auth, last_seq))
}

/// Разбирает `RESUME` в формате `ClientRotation::build_resume`:
/// `kind(0x02) ‖ len(2B BE) ‖ ticket_blob ‖ nonce(24B) ‖ AEAD(...)`.
pub fn parse_resume_request(request: &[u8]) -> Option<(Vec<u8>, [u8; 24], Vec<u8>)> {
    if request.first() != Some(&0x02) {
        return None;
    }
    let len = u16::from_be_bytes(request.get(1..3)?.try_into().ok()?) as usize;
    let blob = request.get(3..3 + len)?.to_vec();
    let rest = request.get(3 + len..)?;
    let (nonce, sealed) = rest.split_at_checked(24)?;
    let nonce: [u8; 24] = nonce.try_into().ok()?;
    Some((blob, nonce, sealed.to_vec()))
}

/// `RESUME_ACK` в формате harness-мока `rotation-tests` (wire-ACK):
/// `kind(0x01) ‖ nonce(24B) ‖ AEAD{K_resume}(ack_plain)`, AAD — сам `RESUME`.
/// `ack_plain = continuity(8) ‖ window_lo(8) ‖ window_hi(8) ‖ eph_node(32) ‖ sig_node(64)`.
pub fn build_resume_ack(
    client_nonce: &[u8; 16],
    ack_plain: &[u8],
    request_aad: &[u8],
    k_resume: [u8; 32],
) -> Vec<u8> {
    let nonce = key_coordinator::ack_nonce(client_nonce);
    let sealed = RecordAead.seal(
        &crypto_core::KRecord(k_resume),
        &crypto_core::RecordNonce(nonce),
        request_aad,
        ack_plain,
    );
    let mut out = vec![0x01]; // KIND_ACK
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Кадр roundtrip: length-префикс читается ровно один payload.
    #[tokio::test]
    async fn frame_roundtrip() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let (mut r1, mut w1) = tokio::io::split(client);
        let (mut r2, mut w2) = tokio::io::split(server);
        send_frame(&mut w1, b"hello frame").await.expect("write");
        send_frame(&mut w2, b"second").await.expect("write");
        assert_eq!(read_frame(&mut r2).await.expect("read"), b"hello frame");
        assert_eq!(read_frame(&mut r1).await.expect("read"), b"second");
    }

    /// Слишком длинный кадр — BadFrame, не аллокация.
    #[tokio::test]
    async fn oversized_frame_is_rejected() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let (_, mut w2) = tokio::io::split(server);
        let (mut r1, _) = tokio::io::split(client);
        let mut malicious = Vec::new();
        malicious.extend_from_slice(&(1u32 << 30).to_be_bytes());
        w2.write_all(&malicious).await.expect("write");
        w2.flush().await.expect("flush");
        assert!(matches!(read_frame(&mut r1).await, Err(WireError::BadFrame(_))));
    }

    /// Тегированный кадр roundtrip: тег и payload не путаются.
    #[tokio::test]
    async fn tagged_roundtrip() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let (mut r1, mut w1) = tokio::io::split(client);
        let (mut r2, mut w2) = tokio::io::split(server);
        send_tagged(&mut w1, TAG_HANDSHAKE, b"msg1").await.expect("write");
        send_tagged(&mut w2, TAG_RESUME, b"resume").await.expect("write");
        assert_eq!(
            read_tagged(&mut r2).await.expect("read"),
            (TAG_HANDSHAKE, b"msg1".to_vec())
        );
        assert_eq!(
            read_tagged(&mut r1).await.expect("read"),
            (TAG_RESUME, b"resume".to_vec())
        );
        // Пустой payload: тег есть, данных нет — не Closed.
        send_tagged(&mut w1, TAG_MINT, b"").await.expect("write");
        assert_eq!(read_tagged(&mut r2).await.expect("read"), (TAG_MINT, Vec::new()));
    }

    /// Mint-запрос: сборка и разбор совпадают по полям; длина ровно 63 B.
    #[test]
    fn mint_request_roundtrip() {
        let request = build_mint_request(7, [1u8; 16], [2u8; 32], 41);
        assert_eq!(request.len(), MINT_REQUEST_LEN);
        assert_eq!(MINT_REQUEST_LEN, 63, "kind(1) ‖ node_id(4) ‖ ext_len(2) ‖ 56");
        assert_eq!(request[0], 0x01, "KIND_MINT_REQ как в Rotation::request_ticket");
        assert_eq!(
            parse_mint_request(&request),
            Some((7, [1u8; 16], [2u8; 32], 41))
        );
        assert_eq!(parse_mint_request(&request[..20]), None);
        assert_eq!(parse_mint_request(&[0x02, 0, 0, 0, 1]), None);
    }

    /// RESUME-запрос: формат `build_resume` разбирается на составляющие.
    #[test]
    fn resume_request_parse() {
        let blob = vec![0xABu8; 161];
        let mut request = vec![0x02];
        request.extend_from_slice(&(blob.len() as u16).to_be_bytes());
        request.extend_from_slice(&blob);
        let nonce = [9u8; 24];
        request.extend_from_slice(&nonce);
        request.extend_from_slice(&[0xCC; 40]);
        let (parsed_blob, parsed_nonce, sealed) = parse_resume_request(&request).expect("формат");
        assert_eq!(parsed_blob, blob);
        assert_eq!(parsed_nonce, nonce);
        assert_eq!(sealed, vec![0xCC; 40]);
        assert_eq!(parse_resume_request(&[0x01, 0, 0]), None);
        assert_eq!(parse_resume_request(&[0x02, 0x00]), None);
    }
}
