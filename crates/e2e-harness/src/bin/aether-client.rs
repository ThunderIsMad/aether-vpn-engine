//! `aether-client` — сторона клиента живого E2E-прогона (Phase 1, ручной запуск).
//!
//! Путь по компонентам из `03-components.md`:
//! 1. `policy-engine`: правило лаборатории → решение `Route` (решение печатается).
//! 2. Noise_IK handshake (Clatter, `crypto_core::IkInitiator`) → `K_session`.
//! 3. `frame_session::Session`: seal записей; `transport_mux::QuicBinding` — прод-байндинг
//!    (outbox + `encode_frame`), кадры уходят QUIC-датаграммами на N1.
//! 4. Ротация N1→N2: mint у N1, `RESUME` на N2 — прод-`ClientRotation`
//!    (`key-coordinator`): PoP `sig_client`, проверка `sig_node` над ACK, re-key
//!    `K_session' = derive_rotated_session(DH(eph_client, eph_node))`, `ratchet_from`
//!    — и `seq` продолжается без сброса (`02 §3.3`).
//! 5. Записи после re-key уходят к N2; N2 вскрывает их своим `K_session'`.
//!
//! Continuity подтверждается по логам обеих сторон: `seq` не сбрасывается, хеши
//! `K_session'` совпадают, дедуп N2 принимает продолжение нумерации.
//!
//! Запуск: `aether-client <MANIFEST_N1> <MANIFEST_N2> [--records N] [--after N]`;
//! подробности — `scripts/e2e-manual.sh`.

#![cfg_attr(not(test), deny(unsafe_code))]

use crypto_core::{x25519_keypair, Handshake, IkInitiator};
use e2e_harness::quic_lab;
use e2e_harness::wire::{
    build_mint_request, read_tagged, send_tagged, TAG_HANDSHAKE, TAG_MINT,
};
use e2e_harness::{new_session, read_manifest, short_hash, ClientKeys, LabConfig};
use frame_session::FlowId;
use key_coordinator::{
    ChannelError, ClientRotation, Ed25519Pub as KcEd25519Pub, Node, NodeId, Rotation,
    RotationChannel, Ticket, TicketBlob, X25519Pub as KcX25519Pub,
};
use transport_mux::{CoverBinding, QuicBinding};

/// Канал до узла поверх QUIC bi-стрима (`RotationChannel` из `key-coordinator`).
/// Трейт синхронный — вызовы блокируются через `block_in_place` (multi-thread runtime).
struct QuicChannel {
    connection: quinn::Connection,
}

impl RotationChannel for QuicChannel {
    fn exchange(&mut self, _node: NodeId, request: &[u8]) -> Result<Vec<u8>, ChannelError> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let (mut send, mut recv) = self
                    .connection
                    .open_bi()
                    .await
                    .map_err(|_| ChannelError::Unreachable)?;
                send_tagged(&mut send, e2e_harness::wire::TAG_RESUME, request)
                    .await
                    .map_err(|_| ChannelError::Unreachable)?;
                let (_tag, response) = read_tagged(&mut recv)
                    .await
                    .map_err(|_| ChannelError::Timeout)?;
                Ok(response)
            })
        })
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: aether-client <MANIFEST_N1> <MANIFEST_N2> [--records N] [--after N]");
        std::process::exit(2);
    }
    let manifest1 = read_manifest(std::path::Path::new(&args[1])).expect("манифест N1");
    let manifest2 = read_manifest(std::path::Path::new(&args[2])).expect("манифест N2");
    let records_n = flag_value(&args, "--records").unwrap_or(5);
    let after_n = flag_value(&args, "--after").unwrap_or(5);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime
        .block_on(run(manifest1, manifest2, records_n, after_n))
        .expect("E2E прогон");
}

fn flag_value(args: &[String], flag: &str) -> Option<u64> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
}

async fn run(
    manifest1: e2e_harness::NodeManifest,
    manifest2: e2e_harness::NodeManifest,
    records_n: u64,
    after_n: u64,
) -> Result<(), String> {
    let mut config = LabConfig::new(manifest1.port, manifest2.port);
    config.rotate_after_records = records_n;
    config.records_after_rotation = after_n;
    // Клиент лаборатории: тот же seed, что в авторизованном наборе узлов.
    let client_keys = ClientKeys::from_seed([0xCD; 32]);

    println!(
        "[client] identity#={} | manifests: N1@{}{} N2@{}{}",
        short_hash(&client_keys.identity_pub(), 8),
        manifest1.node_id,
        manifest1.port,
        manifest2.node_id,
        manifest2.port
    );

    // ── 1. policy-engine: правило лаборатории → Route ──────────────────────────
    let mut engine = policy_engine::Engine::new(
        policy_engine::RouteAction::Direct,
        vec![policy_engine::Rule::new("tunnel-lab", policy_engine::RouteAction::Route)
            .with_host("lab.aether.test")],
    );
    let fake_ip = engine
        .assign_fake_ip("lab.aether.test")
        .expect("лабовый хост валиден: резервирует fake-ip");
    let flow = policy_engine::FlowKey {
        dst: fake_ip,
        dst_port: 443,
        host: Some("lab.aether.test".to_string()),
    };
    let rule = engine.route(&flow);
    println!(
        "[client] policy: {}:{} ({:?}) → {:?} ({})",
        flow.dst,
        flow.dst_port,
        flow.host,
        rule.action,
        rule.name
    );
    if rule.action != policy_engine::RouteAction::Route {
        return Err("правило лаборатории должно давать Route".into());
    }

    // ── 2. QUIC к N1 + Noise_IK handshake ──────────────────────────────────────
    let endpoint = quic_lab::client_endpoint().map_err(|e| format!("client endpoint: {e}"))?;
    let conn1 = quic_lab::connect(&endpoint, &manifest1).await?;
    println!("[client] QUIC connected to N1 ({})", conn1.remote_address());
    let (send, mut recv) = conn1
        .open_bi()
        .await
        .map_err(|e| format!("handshake stream: {e}"))?;
    let mut send = send;
    let client_static = x25519_keypair(&client_keys.static_priv);
    let client_static_kem = crypto_core::mlkem768_genkey().map_err(|e| format!("kem genkey: {e:?}"))?;
    let mut initiator = IkInitiator::new(
        config.session_id,
        client_static,
        client_static_kem,
        crypto_core::X25519Pub(manifest1.node_static),
        crypto_core::mlkem768_pub_from_bytes(&manifest1.node_static_kem)
            .map_err(|e| format!("kem из манифеста: {e:?}"))?,
    )
    .map_err(|e| format!("initiator init: {e:?}"))?;
    let msg1 = initiator.initiate().map_err(|e| format!("msg1: {e:?}"))?;
    send_tagged(&mut send, TAG_HANDSHAKE, &msg1)
        .await
        .map_err(|e| format!("send msg1: {e}"))?;
    let (_tag, msg2) = read_tagged(&mut recv)
        .await
        .map_err(|e| format!("read msg2: {e}"))?;
    let k_session = initiator
        .finish_initiator(&msg2)
        .map_err(|e| format!("finish: {e:?}"))?
        .0;
    println!(
        "[client] Noise_IK complete: K_session#={} (ожидается тот же у N1)",
        short_hash(&k_session, 6)
    );

    // ── 3. FrameSession + прод-байндинг QuicBinding → датаграммы на N1 ─────────
    let mut session = new_session(config.session_id, k_session);
    let stream = session.open_stream(FlowId(1));
    let mut binding = QuicBinding::new(conn1.clone());
    for i in 0..config.rotate_after_records {
        let payload = format!("payload-{i:03} via {}", rule.name);
        let record = session.seal_record(stream, payload.as_bytes());
        let seq = record.seq.0;
        binding
            .send(&record)
            .map_err(|e| format!("binding send seq={seq}: {e:?}"))?;
        let mut frames = 0usize;
        for (_stream_id, frame) in binding.take_pending() {
            frames += 1;
            conn1
                .send_datagram(frame.into())
                .map_err(|e| format!("datagram seq={seq}: {e}"))?;
        }
        println!(
            "[client] record seq={seq} sent ({frames} QUIC datagram, {} B)",
            record.ciphertext.len()
        );
    }
    let last_seq = session.last_seq().0;
    let client_window = (0u64, last_seq);
    println!(
        "[client] before rotation: last_seq={last_seq}, window=({},{})",
        client_window.0, client_window.1
    );

    // ── 4. Ротация N1 → N2: mint у N1, RESUME на N2 (прод ClientRotation) ──────
    let (mint_send, mut mint_recv) = conn1
        .open_bi()
        .await
        .map_err(|e| format!("mint stream: {e}"))?;
    let mut mint_send = mint_send;
    let mint_request = build_mint_request(
        manifest1.node_id,
        config.session_id,
        client_keys.identity_pub(),
        last_seq,
    );
    send_tagged(&mut mint_send, TAG_MINT, &mint_request)
        .await
        .map_err(|e| format!("send mint: {e}"))?;
    let (_tag, blob) = read_tagged(&mut mint_recv)
        .await
        .map_err(|e| format!("read ticket: {e}"))?;
    println!("[client] ticket minted at N1 ({} B)", blob.len());

    let conn2 = quic_lab::connect(&endpoint, &manifest2).await?;
    println!("[client] QUIC connected to N2 ({})", conn2.remote_address());

    let (eph_pub, eph_priv) = crypto_core::x25519_genkey().map_err(|e| format!("eph: {e:?}"))?;
    let mut rotation = ClientRotation::new(
        config.session_id,
        k_session,
        QuicChannel {
            connection: conn2.clone(),
        },
    );
    rotation.set_client_identity(client_keys.identity_priv);
    rotation.set_eph_client(eph_priv, KcX25519Pub(eph_pub.0));
    rotation.set_resume_state(last_seq, client_window);
    let node2 = Node {
        id: NodeId(manifest2.node_id),
        node_identity: KcEd25519Pub(manifest2.identity),
        node_static: KcX25519Pub(manifest2.node_static),
    };
    let ticket = Ticket {
        blob: TicketBlob(blob),
    };
    let eph = rotation.eph_public().expect("eph_client установлен");
    let continuity = rotation
        .resume(&node2, &ticket, eph)
        .map_err(|e| format!("RESUME на N2: {e:?}"))?;
    println!(
        "[client] RESUME accepted by N2: continuity_point={}, window=({}, {})",
        continuity.point, continuity.window_lo, continuity.window_hi
    );
    // ACK принят: передаём frame-слою (окно + подтверждённый continuity point).
    session.on_resume_ack(
        frame_session::Seq(continuity.point),
        frame_session::DuplicateWindow {
            lo: frame_session::Seq(continuity.window_lo),
            hi: frame_session::Seq(continuity.window_hi),
        },
        frame_session::X25519Pub(continuity.eph_node.0),
        frame_session::Signature(continuity.sig_node.0),
    );
    rotation
        .post_rotation_rekey(&continuity.eph_node)
        .map_err(|e| format!("re-key: {e:?}"))?;
    let k_prime = rotation
        .k_session_prime()
        .expect("K_session' после re-key");
    session.ratchet_from(&k_prime);
    println!(
        "[client] re-key: K_session'#={} (ожидается тот же у N2), seq продолжается с {}",
        short_hash(&k_prime, 6),
        session.last_seq().0 + 1
    );

    // ── 5. Записи после ротации — к N2 под K_session' ──────────────────────────
    let mut binding2 = QuicBinding::new(conn2.clone());
    for i in 0..config.records_after_rotation {
        let payload = format!("post-rotation-{i:03} via {}", rule.name);
        let record = session.seal_record(stream, payload.as_bytes());
        let seq = record.seq.0;
        binding2
            .send(&record)
            .map_err(|e| format!("binding send seq={seq}: {e:?}"))?;
        for (_stream_id, frame) in binding2.take_pending() {
            conn2
                .send_datagram(frame.into())
                .map_err(|e| format!("datagram seq={seq}: {e}"))?;
        }
        println!("[client] record seq={seq} sent to N2 under K_session'");
    }

    // Датаграммы от узлов в лаборатории не ожидаются; короткая пауза, чтобы логи
    // узлов (accepted/dedup) успели дойти до консоли до завершения клиента.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    println!(
        "[client] E2E DONE: seq 0..{last_seq} на N1, seq {}..{} на N2 — сверить с логами узлов",
        last_seq + 1,
        session.last_seq().0
    );
    Ok(())
}
