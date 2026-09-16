//! `aether-node` — сторона узла живого E2E-прогона (Phase 1, ручной запуск).
//!
//! Полный протокол `02-protocols.md` на реальном QUIC (quinn):
//! 1. QUIC-сервер на localhost (datagram включены), самоподписанный сертификат и
//!    манифест узла публикуются в файл (его читает клиент).
//! 2. Handshake-стрим: гибридный Noise_IK (Clatter, `crypto_core::IkResponder`)
//!    → `K_session` с обеих сторон.
//! 3. Control-стримы: mint ticket (`ticket_mint::TicketFactory`), разбор `RESUME`
//!    с PoP (`TicketFactory::handle_resume`), `RESUME_ACK` (подпись `node_identity`).
//! 4. Datagram: записи frame-слоя, зеркало `Session` вскрывает их (дедуп по `(sid, seq)`).
//! 5. Ротация: узел-приёмник (N2) держит приватную половину `eph_node` и выводит
//!    `K_session'` той же `derive_rotated_session`, что и клиент — совпадение видно в логах.
//!
//! Логи — то, что подтверждает прогон: хеши `K_session`/`K_session'`, `seq` записей,
//! continuity point, окно дедупа. Секреты в лог не печатаются, только sha256-префиксы.
//!
//! Запуск: `aether-node <PORT> <SEED_HEX_32B> <MANIFEST_PATH> [--node-id N]`;
//! подробности — `scripts/e2e-manual.sh`.

#![cfg_attr(not(test), deny(unsafe_code))]

use crypto_core::{
    ed25519_pubkey, x25519_keypair, Handshake, IkResponder, KSession, RecordAead, RecordCrypto,
};
use e2e_harness::quic_lab;
use e2e_harness::wire::{
    build_resume_ack, parse_mint_request, parse_resume_request, read_tagged, send_tagged,
    TAG_HANDSHAKE, TAG_MINT, TAG_RESUME,
};
use e2e_harness::{
    decode_record_frame, new_session, seed_from_hex, short_hash, tfk_epoch, ClientKeys, LabConfig,
    NodeKeys,
};
use frame_session::{DedupWindow, Seq, Session};
use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;
use ticket_mint::{ResumeVerdict, Signature as MintSignature, TicketFactory, Window as MintWindow};

/// Флаги соединения: handshake — один раз (повторный handshake-стрим — ошибка).
#[derive(Default)]
struct ConnFlags {
    handshake_done: bool,
}

/// Состояние узла: зеркало сессии, минтер, consumed-set, ключи.
struct NodeState {
    node_id: u32,
    keys: NodeKeys,
    /// Приватная половина `eph_node` этой ротации (`02 §3.3`); pub — в RESUME_ACK.
    eph_node_priv: [u8; 32],
    factory: TicketFactory,
    now: u64,
    session: Option<Session>,
    session_id: [u8; 16],
    /// `K_session` из handshake (N1) или `K_session'` после RESUME (N2) — для лога.
    k_session: Option<[u8; 32]>,
    /// Авторизованные `client_identity` (лаборатория: клиент из фиксированного seed).
    authorized_clients: HashSet<[u8; 32]>,
    records_accepted: u64,
    duplicates: u64,
}

impl NodeState {
    fn new(config: &LabConfig, node_id: u32, keys: NodeKeys, eph_node_priv: [u8; 32]) -> Self {
        let mut factory = TicketFactory::new(tfk_epoch(), 0, 0, config.ticket_ttl_seconds);
        factory.set_now(config.now);
        let client = ClientKeys::from_seed([0xCD; 32]);
        Self {
            node_id,
            keys,
            eph_node_priv,
            factory,
            now: config.now,
            session: None,
            session_id: config.session_id,
            k_session: None,
            authorized_clients: HashSet::from([client.identity_pub()]),
            records_accepted: 0,
            duplicates: 0,
        }
    }

    fn node_static_keypair(&self) -> crypto_core::X25519KeyPair {
        x25519_keypair(&self.keys.static_priv)
    }

    fn eph_node_pub(&self) -> [u8; 32] {
        x25519_keypair(&self.eph_node_priv).public
    }

    /// Лог: event | seq | K_session# | счётчики. Секреты не печатаются.
    fn log(&self, event: &str) {
        let k_hash = self
            .k_session
            .as_ref()
            .map(|k| short_hash(k, 6))
            .unwrap_or_else(|| "—".to_string());
        let seq = self
            .session
            .as_ref()
            .map(|s| s.last_seq().0.to_string())
            .unwrap_or_else(|| "—".to_string());
        println!(
            "[node{}] {event} | seq={seq} | K_session#={k_hash} | accepted={} dups={}",
            self.node_id, self.records_accepted, self.duplicates
        );
    }
}

/// Разбор расшифрованной полезной нагрузки `RESUME` в контекст узла:
/// `last_seq(8) ‖ window_lo(8) ‖ window_hi(8) ‖ eph_client(32) ‖ client_nonce(16) ‖ sig_client(64)`.
fn resume_ctx_from_plain(
    blob: &[u8],
    plain: &[u8],
) -> Option<(ticket_mint::ResumeCtx, MintSignature)> {
    if plain.len() != 8 + 8 + 8 + 32 + 16 + 64 {
        return None;
    }
    let ctx = ticket_mint::ResumeCtx {
        ticket_hash: crypto_core::sha256(blob),
        last_seq: u64::from_be_bytes(plain[0..8].try_into().ok()?),
        window: MintWindow {
            lo: u64::from_be_bytes(plain[8..16].try_into().ok()?),
            hi: u64::from_be_bytes(plain[16..24].try_into().ok()?),
        },
        eph_client: plain[24..56].try_into().ok()?,
        client_nonce: plain[56..72].try_into().ok()?,
    };
    let sig = MintSignature(plain[72..136].try_into().ok()?);
    Some((ctx, sig))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: aether-node <PORT> <SEED_HEX_32B> <MANIFEST_PATH> [--node-id N]");
        std::process::exit(2);
    }
    let port: u16 = args[1].parse().expect("PORT — число");
    let seed = seed_from_hex(&args[2]).expect("SEED — 64 hex-символа");
    let manifest_path = std::path::PathBuf::from(&args[3]);
    let node_id = args
        .iter()
        .position(|a| a == "--node-id")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);

    // Узел однопоточный: `Session` держит `Box<dyn SessionCrypto>`, трейт не `Send`,
    // значит `NodeState` нельзя пересылать между потоками — состояние живёт в `LocalSet`
    // (`spawn_local`), а не в `tokio::spawn`. Для лаборатории этого достаточно.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let local = tokio::task::LocalSet::new();
    runtime.block_on(local.run_until(run(port, seed, manifest_path, node_id)));
}

async fn run(port: u16, seed: [u8; 32], manifest_path: std::path::PathBuf, node_id: u32) {
    let config = LabConfig::new(port, port);
    let keys = NodeKeys::from_seed(seed);
    // Свежая эфемерная пара ротации (`02 §3.3`) — по одной на узел лаборатории.
    let (eph_pub, eph_priv) = e2e_harness::fresh_eph_node();

    let cert = quic_lab::self_signed_cert();
    let (endpoint, bound_port) =
        quic_lab::server_endpoint(port, &cert).expect("QUIC endpoint на localhost:PORT");
    e2e_harness::write_manifest(&keys, node_id, bound_port, &cert.cert_der, &manifest_path)
        .expect("записать манифест узла");
    println!(
        "[node{node_id}] QUIC listening on 127.0.0.1:{bound_port} | identity#={} | static#={} | eph#={} | manifest={}",
        short_hash(&ed25519_pubkey(&keys.identity_priv).0, 8),
        short_hash(&x25519_keypair(&keys.static_priv).public, 8),
        short_hash(&eph_pub, 8),
        manifest_path.display()
    );

    // Состояние однопоточное (LocalSet): `Rc<RefCell>` вместо `Arc<tokio::sync::Mutex>` —
    // клонти-линт требует, чтобы `Arc` был Send+Sync, а `NodeState` (через `Session`) им не является.
    let state = Rc::new(RefCell::new(NodeState::new(
        &config, node_id, keys, eph_priv,
    )));
    while let Some(incoming) = endpoint.accept().await {
        let state = Rc::clone(&state);
        tokio::task::spawn_local(async move {
            if let Err(err) = serve_connection(incoming, state).await {
                eprintln!("[node] connection error: {err}");
            }
        });
    }
}

async fn serve_connection(
    incoming: quinn::Incoming,
    state: Rc<RefCell<NodeState>>,
) -> Result<(), String> {
    let connection = incoming
        .await
        .map_err(|err| format!("QUIC handshake: {err}"))?;
    let node_id = state.borrow().node_id;
    println!("[node{node_id}] client connected from {}", connection.remote_address());
    let flags = Rc::new(RefCell::new(ConnFlags::default()));

    // Датаграммный цикл — один на соединение, независимо от порядка стримов: на N2
    // handshake-стрима нет (клиент сразу RESUME), записи до установки состояния
    // отбрасываются с логом. Спавнить по TAG_HANDSHAKE нельзя — N2 их не прочитает.
    {
        let ds = Rc::clone(&state);
        let dc = connection.clone();
        tokio::task::spawn_local(datagram_loop(dc, ds));
    }

    // Bi-стримы по одному: первый — handshake, далее control (mint/RESUME).
    loop {
        let (mut send, mut recv) = match connection.accept_bi().await {
            Ok(pair) => pair,
            Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
            Err(err) => return Err(format!("accept_bi: {err}")),
        };
        let (tag, payload) = read_tagged(&mut recv)
            .await
            .map_err(|err| format!("stream read: {err}"))?;
        match tag {
            TAG_HANDSHAKE => {
                {
                    let mut fl = flags.borrow_mut();
                    if fl.handshake_done {
                        return Err("повторный handshake-стрим".into());
                    }
                    fl.handshake_done = true;
                }
                let (session_id, msg2, k_session) = {
                    // Borrow'и не пересекают await: на LocalSet датаграммный цикл
                    // между await'ами может обратиться к состоянию, пересекающийся
                    // borrow_mut — паника RefCell.
                    let st = state.borrow();
                    let mut responder = IkResponder::new(
                        st.session_id,
                        st.node_static_keypair(),
                        st.keys.kem.clone(),
                    )
                    .map_err(|err| format!("responder init: {err:?}"))?;
                    let (msg2, k_session) = responder
                        .respond(&payload)
                        .map_err(|err| format!("Noise_IK respond: {err:?}"))?;
                    (st.session_id, msg2, k_session.0)
                };
                {
                    let mut st = state.borrow_mut();
                    st.k_session = Some(k_session);
                    let mut session = new_session(session_id, k_session);
                    // Зеркало узла: поток открывается тем же `FlowId`, что у клиента —
                    // `stream_id` выдаётся по порядку открытия (`02 §1`).
                    session.open_stream(frame_session::FlowId(1));
                    st.session = Some(session);
                    st.log("Noise_IK handshake complete: K_session выведен, msg2 отправлен");
                }
                send_tagged(&mut send, TAG_HANDSHAKE, &msg2)
                    .await
                    .map_err(|err| format!("send msg2: {err}"))?;
            }
            TAG_MINT | TAG_RESUME => {
                let response = {
                    let mut st = state.borrow_mut();
                    handle_control(&mut st, tag, &payload)
                };
                send_tagged(&mut send, tag, &response)
                    .await
                    .map_err(|err| format!("control response: {err}"))?;
            }
            other => eprintln!("[node] unknown stream tag {other:#x} — закрыт"),
        }
    }

    let st = state.borrow();
    st.log("connection closed");
    Ok(())
}

/// Датаграммный цикл: записи frame-слоя вскрываются зеркалом сессии.
async fn datagram_loop(connection: quinn::Connection, state: Rc<RefCell<NodeState>>) {
    loop {
        match connection.read_datagram().await {
            Ok(payload) => {
                let mut st = state.borrow_mut();
                match decode_record_frame(&payload) {
                    Ok(record) => {
                        let seq = record.seq.0;
                        let Some(session) = st.session.as_mut() else {
                            eprintln!("[node] record seq={seq} до handshake — отброшена");
                            continue;
                        };
                        match session.recv_record(&record) {
                            Ok(Some(plaintext)) => {
                                st.records_accepted += 1;
                                println!(
                                    "[node{}] record seq={seq} accepted ({} B: {:?})",
                                    st.node_id,
                                    plaintext.len(),
                                    String::from_utf8_lossy(&plaintext)
                                );
                            }
                            Ok(None) => {
                                st.duplicates += 1;
                                println!(
                                    "[node{}] record seq={seq} DUPLICATE (дедуп по (sid, seq))",
                                    st.node_id
                                );
                            }
                            Err(err) => {
                                eprintln!("[node{}] record seq={seq} rejected: {err:?}", st.node_id);
                            }
                        }
                    }
                    Err(err) => eprintln!("[node] bad frame: {err:?}"),
                }
            }
            Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
            Err(err) => {
                eprintln!("[node] datagram: {err}");
                break;
            }
        }
    }
}

/// Разбор control-кадра: mint или RESUME. Форматы — из прод-крейтов (`wire.rs`).
fn handle_control(st: &mut NodeState, tag: u8, request: &[u8]) -> Vec<u8> {
    if tag == TAG_MINT {
        return handle_mint(st, request);
    }
    if tag == TAG_RESUME {
        return handle_resume(st, request);
    }
    vec![0x02, 0xFF]
}

/// Mint: `kind ‖ node_id ‖ ext{sid ‖ client_auth ‖ last_seq}` → ticket.
/// `K_session` берётся из завершённого handshake — по проводу он не ходит.
fn handle_mint(st: &mut NodeState, request: &[u8]) -> Vec<u8> {
    let Some((_node_id, sid, client_auth, last_seq)) = parse_mint_request(request) else {
        st.log("mint request malformed");
        return vec![0x02, 0xFF];
    };
    if !st.authorized_clients.contains(&client_auth) {
        st.log("mint rejected: клиент не в авторизованном наборе");
        return vec![0x02, 0xFF];
    }
    let Some(k_session) = st.k_session else {
        st.log("mint rejected: handshake не завершён");
        return vec![0x02, 0xFF];
    };
    let window = MintWindow {
        lo: last_seq.saturating_sub(4096),
        hi: last_seq,
    };
    let blob = st.factory.mint_at(
        ticket_mint::SessionId(sid),
        ticket_mint::Ed25519Pub(client_auth),
        window,
        &k_session,
        st.now,
    );
    st.log(&format!(
        "ticket minted ({} B) для клиента auth#={}, ticket window=({}, {})",
        blob.0.len(),
        short_hash(&client_auth, 6),
        window.lo,
        window.hi
    ));
    blob.0
}

/// RESUME: unwrap → consumed-set → PoP → консумирование → re-key на узле → ACK.
fn handle_resume(st: &mut NodeState, request: &[u8]) -> Vec<u8> {
    let Some((blob, nonce, sealed)) = parse_resume_request(request) else {
        st.log("RESUME malformed");
        return vec![0x02, 0xFF];
    };
    let blob_owned = ticket_mint::TicketBlob(blob.clone());
    let ticket = match st.factory.unwrap_at(&blob_owned, st.now) {
        Ok(ticket) => ticket,
        Err(err) => {
            st.log(&format!("RESUME unwrap failed: {err:?}"));
            return vec![0x02, 0xFF];
        }
    };
    let k_resume = crypto_core::derive_k_resume(&ticket.sid.0, &KSession(ticket.k_session));
    let plain = match RecordAead.open(
        &crypto_core::KRecord(k_resume),
        &crypto_core::RecordNonce(nonce),
        &blob,
        &sealed,
    ) {
        Ok(plain) => plain,
        Err(_) => {
            st.log("RESUME AEAD open failed");
            return vec![0x02, 0xFF];
        }
    };
    let Some((ctx, sig)) = resume_ctx_from_plain(&blob, &plain) else {
        st.log("RESUME bad plaintext layout");
        return vec![0x02, 0xFF];
    };
    match st.factory.handle_resume(&blob_owned, &sig, &ctx, st.now) {
        ResumeVerdict::Accept { ticket, anomaly } => {
            st.log(&format!(
                "RESUME accepted: last_seq={}, window=({}, {}){}, ticket consumed ({})",
                ctx.last_seq,
                ticket.window.lo,
                ticket.window.hi,
                if anomaly { " [ANOMALY]" } else { "" },
                st.factory.consumed_len(),
            ));
            // Пост-ротационный re-key на узле (`02 §3.3`): DH(eph_node_priv, eph_client)
            // и тот же `derive_rotated_session`, что у клиента.
            let shared = crypto_core::x25519_dh(&st.eph_node_priv, &crypto_core::X25519Pub(ctx.eph_client))
                .expect("DH eph состоялся");
            let k_session_prime = crypto_core::derive_rotated_session(
                &ticket.sid.0,
                &KSession(ticket.k_session),
                &shared,
            )
            .0;

            // Зеркало сессии N2: тот же `K_session'`, окно дедупа — из подписанного
            // клиентом `last_seq` (`02 §3.5`, «Потеря состояния»).
            let mut session = new_session(ticket.sid.0, k_session_prime);
            session.restore_dedup_from_signed_last_seq(Seq(ctx.last_seq));
            session.open_stream(frame_session::FlowId(1));
            st.session = Some(session);
            st.k_session = Some(k_session_prime);
            st.log(&format!(
                "re-key: K_session'#={} (ожидается тот же у клиента)",
                short_hash(&k_session_prime, 6)
            ));

            // ACK: continuity = подписанный клиентом last_seq; окно — из ticket;
            // `sig_node` — Ed25519 `node_identity` над транскриптом
            // (`key_coordinator::ack_signing_payload`).
            let window = DedupWindow::new(Seq(ticket.window.lo), Seq(ctx.last_seq)).window();
            let client_ctx = key_coordinator::ResumeCtx {
                ticket_hash: ctx.ticket_hash,
                last_seq: ctx.last_seq,
                window: (ctx.window.lo, ctx.window.hi),
                eph_client: ctx.eph_client,
                client_nonce: ctx.client_nonce,
            };
            let transcript = crypto_core::sha256(&key_coordinator::resume_signing_payload(&client_ctx));
            let eph_node_pub = st.eph_node_pub();
            let payload = key_coordinator::ack_signing_payload(
                &transcript,
                ctx.last_seq,
                (window.lo.0, window.hi.0),
                &eph_node_pub,
            );
            let sig_node = crypto_core::ed25519_sign(&st.keys.identity_priv, &payload);
            let mut ack_plain = Vec::with_capacity(8 + 8 + 8 + 32 + 64);
            ack_plain.extend_from_slice(&ctx.last_seq.to_be_bytes());
            ack_plain.extend_from_slice(&window.lo.0.to_be_bytes());
            ack_plain.extend_from_slice(&window.hi.0.to_be_bytes());
            ack_plain.extend_from_slice(&eph_node_pub);
            ack_plain.extend_from_slice(&sig_node.0);
            st.log(&format!(
                "RESUME_ACK: continuity_point={}, window=({}, {})",
                ctx.last_seq, window.lo.0, window.hi.0
            ));
            build_resume_ack(&ctx.client_nonce, &ack_plain, request, k_resume)
        }
        verdict => {
            st.log(&format!("RESUME rejected: {verdict:?}"));
            vec![0x02, 0xFF]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RESUME-полезная нагрузка: ровно 136 B разбирается, кривая длина — `None`.
    #[test]
    fn resume_ctx_from_plain_layout() {
        assert!(resume_ctx_from_plain(&[0u8; 161], &[0u8; 100]).is_none());
        let mut plain = vec![0u8; 136];
        plain[0..8].copy_from_slice(&41u64.to_be_bytes());
        let (ctx, _sig) = resume_ctx_from_plain(&[7u8; 161], &plain).expect("валидная длина");
        assert_eq!(ctx.last_seq, 41);
        assert_eq!(ctx.window.lo, 0);
        assert_eq!(ctx.eph_client, [0u8; 32]);
    }
}
