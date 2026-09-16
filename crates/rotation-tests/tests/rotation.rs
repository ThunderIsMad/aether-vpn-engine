//! Ротация egress-узла N1 → N2: happy path, continuity, forward secrecy, ретрай после потери ACK.
//!
//! Утверждения взяты из `design/02-protocols.md` §1, §3.3, §3.5, §3.6, §3.7, §3.9 и
//! `design/05-roadmap.md` Phase 0 → «Интеграционный тест ротации» (главный риск проекта).
//!
//! Моки: два in-memory байндинга (`transport_mux::MemBinding` — тот же тип, что в юнит-тестах
//! `transport-mux`) со счётчиками и журналом `(stream_id, seq)`; узлы — `NodeSim` в harness'е
//! поверх `ticket_mint::TicketFactory` со своим флотским `TFK_epoch`. Сети нет.
//!
//! Граница измерения: frame-слой, не payload-соединения (`05-roadmap`). Разрыв прикладных
//! TCP/QUIC сменой source IP — ожидаемый эффект Phase 0, не регресс.
//!
//! Тесты сняты с `#[ignore]` вместе с реализацией (клип `02 §4`: `T_morph`/`T_ack` = 2 × SRTT).

mod harness;

use harness::*;

/// **Сценарий 1 (главный тест Phase 0): happy path ротации — 3 потока, N1 → N2 по ticket, 0 потерь.**
///
/// Источник: `02 §3.3` (RESUME/RESUME_ACK, make-before-break), `§3.5` (окно дедупа), `§3.9`
/// («Duplicate-окно при ротации ≈ 1 RTT дублированного трафика — bounded»), `05-roadmap` Phase 0.
#[test]
fn rotation_happy_path_three_streams_no_loss() {
    // 1. Три прикладных потока, по записи в каждом; нумерация `seq` сквозная по сессии.
    let mut driver = RotationDriver::new(session(K_SESSION), MemBinding::new(BindingCaps::QUIC));
    let streams: Vec<StreamId> = [FlowId(10), FlowId(11), FlowId(12)]
        .iter()
        .map(|flow| driver.session.open_stream(*flow))
        .collect();
    assert_eq!(streams.len(), 3, "три прикладных потока (`02 §1`)");

    let mut records = Vec::new();
    for (index, stream) in streams.iter().enumerate() {
        records.push(driver.emit(*stream, format!("pre-{index}").as_bytes(), 0));
    }
    let last_seq = driver.session.last_seq().0;
    assert_eq!(last_seq, 2, "seq монотонен по сессии, а не по потоку (`02 §1`)");

    // 2. Ticket клиент не минтит сам, а просит у узла; N2 — узел той же эпохи флота.
    let (client_identity, client_identity_priv) = ed25519_genkey();
    let network = MockNetwork::new(ClientCreds {
        auth: client_identity,
        k_session: K_SESSION,
        last_seq,
    });
    network
        .borrow_mut()
        .add_node(NodeSim::new(2, 0x21, 0x31, EPOCH_ID));
    let n2_manifest = network.borrow().nodes[&2].manifest();
    let (eph_public, eph_private) = fresh_eph();
    let mut rotation = coordinator(
        network.clone(),
        &client_identity_priv,
        eph_public,
        eph_private,
        last_seq,
        (0, 0),
    );
    let ticket = rotation.request_ticket(&n2_manifest).expect("узел выдал ticket");
    assert_eq!(ticket.blob.0.len(), 161, "blob = nonce(24)+plaintext(121)+tag(16)");

    // 3. Окно перекрытия открыто до ACK: записи идут на оба канала (make-before-break, `02 §3.8`).
    let timeout = driver.start_overlap(MemBinding::new(BindingCaps::QUIC), SRTT_MS);
    assert_eq!(timeout, 300, "T_morph = 2 × SRTT = 300 мс, внутри клипа");
    assert_eq!(t_ack_ms(SRTT_MS), timeout, "T_ack = 2 × SRTT, владелец — FrameSession (`02 §3.7`)");
    let during = [
        driver.emit(streams[0], b"during-0", 0),
        driver.emit(streams[1], b"during-1", 0),
    ];
    assert_eq!(driver.duplicated, 2, "окно дублирует записи на оба канала");

    // 4. RESUME: PoP-подпись по `client_identity`, свежий `eph_client`, ticket вне `K_resume`.
    let continuity = rotation
        .resume(&n2_manifest, &ticket, eph_public)
        .expect("валидный ACK");
    let request = last_request(&network);
    let response = last_response(&network);
    let k_resume = k_resume_for(&K_SESSION);
    let (ctx, sig_client) = resume_ctx(&request, &k_resume);
    assert_eq!(ctx.last_seq, last_seq, "RESUME несёт `last_seq` клиента");
    assert_eq!(ctx.window, (0, 0), "RESUME несёт окно клиента (`02 §3.5`)");
    assert_eq!(ctx.eph_client, eph_public.0, "RESUME несёт `eph_client`");
    assert!(
        ed25519_verify(
            &client_identity,
            &resume_signing_payload(&ctx),
            &sig_client
        ),
        "sig_client покрывает `aether-resume-v3` ‖ sha256(ticket) ‖ last_seq ‖ окно ‖ eph ‖ nonce"
    );
    assert!(
        request
            .windows(ticket.blob.0.len())
            .any(|window| window == ticket.blob.0),
        "ticket_blob идёт вне `K_resume` (`02 §3.3`)"
    );

    // 5. N2 развернул ticket флотским ключом, проверил PoP и консумировал его один раз.
    assert_eq!(
        network.borrow().nodes[&2].accepted,
        1,
        "PoP пройден (`02 §3.3`, `§3.8`)"
    );
    assert_eq!(
        network.borrow().nodes[&2].consumed_tickets(),
        1,
        "consumed-set эпохи (`02 §3.6`)"
    );
    let node_identity = network.borrow().nodes[&2].identity;
    let parts = parse_ack(&request, &response, &k_resume);
    assert!(
        node_signature_verifies(&node_identity, &parts, &ctx),
        "sig_node проверяется по node_identity из манифеста (`02 §3.3`)"
    );
    assert_eq!(
        parts.continuity_point, last_seq,
        "continuity_point = граница дублированного окна (`02 §3.5`)"
    );
    assert_eq!(continuity.point, parts.continuity_point);

    // 6. Frame-слой принимает ACK: окно узла, его `eph_node` и `sig_node`; окно закрывается ACK.
    let client_window = driver.session.on_resume_ack(
        Seq(parts.continuity_point),
        DuplicateWindow {
            lo: Seq(parts.window.0),
            hi: Seq(parts.window.1),
        },
        FrameX25519Pub(parts.eph_node),
        FrameSignature(parts.sig_node),
    );
    assert_eq!(client_window.hi, Seq(last_seq));
    assert!(driver.promote_on_ack(true), "валидный ACK закрывает окно (`02 §4`)");
    assert!(
        driver.session.overlap().expect("окно открыто").is_closed(),
        "старый канал гасится только после валидного ACK (`02 §3.8`)"
    );
    assert!(driver.duplicated <= frame_session::DUPLICATE_WINDOW_RECORDS);

    // Повтор `seq` внутри окна его не двигает, дубль отсекается дедупом `(sid, seq)`.
    let mut node_window = DedupWindow::new(Seq(parts.window.0), Seq(parts.continuity_point));
    assert_eq!(
        node_window.accept(Seq(during[0].seq.0)),
        DedupOutcome::Accepted
    );
    assert_eq!(
        node_window.accept(Seq(during[0].seq.0)),
        DedupOutcome::Duplicate,
        "дубль окна отсекается по `(sid, seq)` (`02 §3.5`)"
    );
    assert_eq!(
        node_window.continuity_point(),
        Seq(during[0].seq.0),
        "повтор не двигает continuity_point"
    );

    // 7. Post-rotation re-key: `K_session'` из свежего DH, ratchet перезапущен, `seq` продолжается.
    rotation
        .post_rotation_rekey(&KcX25519Pub(parts.eph_node))
        .expect("свежий DH");
    let k_prime = rotation.k_session_prime().expect("K_session' посчитан");
    assert_ne!(k_prime, K_SESSION);
    let node_eph = network.borrow().nodes[&2].eph_node;
    assert_eq!(
        ss_rotate(&eph_private, &node_eph),
        ss_rotate(&network.borrow().nodes[&2].eph_node_private(), &eph_public),
        "обе стороны считают один и тот же `ss_rotate` (`02 §3.3`)"
    );
    driver.session.ratchet_from(&k_prime);
    assert_eq!(driver.session.ratchet_restarts(), 1);
    let after = [
        driver.emit_after_rotation(streams[2], b"post-0"),
        driver.emit_after_rotation(streams[1], b"post-1"),
    ];
    assert!(after[0].seq > during[1].seq, "нумерация продолжается, сессия — не соединение (`02 §1`)");

    // 8. Ни одна запись не потеряна на обоих каналах: старый несёт всё до ACK, новый — дубли
    //    окна и пост-ротационный трафик; ниже continuity_point доставлено старым каналом.
    records.extend(during.iter().cloned());
    records.extend(after.iter().cloned());
    let n1 = delivered(&driver.old);
    let n2 = delivered(driver.new.as_ref().expect("новый канал подключён"));
    assert_eq!(n1.len(), 5, "3 записи до ротации + 2 дубля окна");
    assert_eq!(n2.len(), 4, "2 дубля окна + 2 пост-ротационные записи");
    assert_eq!(
        n2.iter().map(|(_, seq)| *seq).min(),
        Some(parts.continuity_point + 1),
        "дубли начинаются с `seq > continuity_point` (`02 §3.3` шаг 5)"
    );
    assert_eq!(
        records_set(&records),
        n1.union(&n2).copied().collect::<std::collections::BTreeSet<_>>(),
        "ни одна запись не потеряна на обоих каналах"
    );

    // 9. Новый узел читает пост-ротационный трафик ключом от `K_session'`, сессия цела.
    let mut new_view = mirror(k_prime, &[10, 11, 12]);
    assert_eq!(
        new_view.recv_record(&after[0]).expect("приём"),
        Some(b"post-0".to_vec())
    );
    assert_eq!(
        new_view.recv_record(&after[0]).expect("повтор"),
        None,
        "дубль отсекается дедупом на узле"
    );
    assert_eq!(driver.session.stream_table().len(), 3, "таблица потоков пережила ротацию");
    assert_eq!(driver.session.session_id(), SessionId(SID));
}

/// **Сценарий 1, re-key-часть (ТЗ): forward secrecy после ротации — старый `K_session` не открывает новые records.**
///
/// Источник: `02 §3.3` (post-rotation re-key), `§3.8` (инвариант «Пост-ротационный трафик читает
/// только новый узел»), `§3.9` (компрометация `K_session` у N1 → трафик до ротации).
#[test]
fn rotation_forward_secrecy_old_k_session_cannot_open_new_records() {
    let mut driver = RotationDriver::new(session(K_SESSION), MemBinding::new(BindingCaps::QUIC));
    let streams: Vec<StreamId> = [FlowId(10), FlowId(11), FlowId(12)]
        .iter()
        .map(|flow| driver.session.open_stream(*flow))
        .collect();
    let pre = driver.emit(streams[0], b"pre-rotation", 0);
    let last_seq = driver.session.last_seq().0;

    // 5. Записи до ротации старый ключ открывает — тест ловит ротацию, а не сломанный AEAD.
    let mut old_view = mirror(K_SESSION, &[10, 11, 12]);
    assert_eq!(
        old_view.recv_record(&pre).expect("приём"),
        Some(b"pre-rotation".to_vec())
    );

    // Ротация: ticket от узла N2 и валидный ACK.
    let (client_identity, client_identity_priv) = ed25519_genkey();
    let network = MockNetwork::new(ClientCreds {
        auth: client_identity,
        k_session: K_SESSION,
        last_seq,
    });
    network
        .borrow_mut()
        .add_node(NodeSim::new(2, 0x21, 0x31, EPOCH_ID));
    let manifest = network.borrow().nodes[&2].manifest();
    let (eph_public, eph_private) = fresh_eph();
    let mut rotation = coordinator(
        network.clone(),
        &client_identity_priv,
        eph_public,
        eph_private,
        last_seq,
        (0, 0),
    );
    let ticket = rotation.request_ticket(&manifest).expect("ticket");
    driver.start_overlap(MemBinding::new(BindingCaps::QUIC), SRTT_MS);
    rotation
        .resume(&manifest, &ticket, eph_public)
        .expect("валидный ACK");
    let k_resume = k_resume_for(&K_SESSION);
    let parts = parse_ack(&last_request(&network), &last_response(&network), &k_resume);
    assert!(driver.promote_on_ack(true), "окно закрыто валидным ACK");

    // 2. `ss_rotate` недостижим владельцу одного `K_session`.
    let ss = ss_rotate(&eph_private, &KcX25519Pub(parts.eph_node));
    assert_eq!(
        ss,
        ss_rotate(&network.borrow().nodes[&2].eph_node_private(), &eph_public),
        "ss_rotate совпадает у обеих сторон"
    );
    let without_dh = derive_rotated_session(&SID, &KSession(K_SESSION), &[0u8; 32]);
    rotation
        .post_rotation_rekey(&KcX25519Pub(parts.eph_node))
        .expect("свежий DH");
    let k_prime = rotation.k_session_prime().expect("K_session'");
    assert_ne!(k_prime, K_SESSION, "K_session' ≠ K_session");
    assert_ne!(without_dh.0, k_prime, "re-key — именно свежий DH, а не вывод из K_session");
    driver.session.ratchet_from(&k_prime);

    // 1/3. Пост-ротационная запись не открывается ни старым ключом цепочки, ни старым `K_session`.
    let post = driver.emit_after_rotation(streams[0], b"post-rotation");
    let old_chain_key = ratchet_record(&SID, &KSession(K_SESSION), post.seq.0);
    assert!(
        RecordAead
            .open(
                &KRecord(old_chain_key.0),
                &RecordNonce(record_nonce(post.seq, &SessionId(SID))),
                &post.aad_bytes(),
                &post.ciphertext,
            )
            .is_err(),
        "AEAD-отказ, а не паника (`02 §1`)"
    );
    let mut old_after = mirror(K_SESSION, &[10, 11, 12]);
    assert_eq!(
        old_after.recv_record(&post),
        Err(RecordError::OpenFailed),
        "N1 с одним K_session пост-ротационный трафик не читает (`02 §3.8`)"
    );
    let mut new_view = mirror(k_prime, &[10, 11, 12]);
    assert_eq!(
        new_view.recv_record(&post).expect("приём"),
        Some(b"post-rotation".to_vec()),
        "новый узел читает тот же record"
    );

    // 4. Подмена `eph_node` (попытка N1 сохранить чтение) отклоняется: `sig_node` обязательна.
    let (hostile_eph_public, _) = fresh_eph();
    let mut hostile = NodeSim::new(3, 0x31, 0x41, EPOCH_ID);
    hostile.corrupt_sig_node = true;
    hostile.eph_override = Some(hostile_eph_public);
    network.borrow_mut().add_node(hostile);
    let hostile_manifest = network.borrow().nodes[&3].manifest();
    let (eph2_public, eph2_private) = fresh_eph();
    let mut victim = coordinator(
        network.clone(),
        &client_identity_priv,
        eph2_public,
        eph2_private,
        driver.session.last_seq().0,
        (0, 0),
    );
    let ticket2 = victim.request_ticket(&hostile_manifest).expect("ticket");
    assert_eq!(
        victim.resume(&hostile_manifest, &ticket2, eph2_public),
        Err(ResumeError::BadNodeSignature),
        "подменённый `eph_node` без валидной `sig_node` не проходит (`02 §3.3`)"
    );
    assert_eq!(victim.confirmed_eph_node(), None);
    assert_eq!(
        victim.k_session_prime(),
        None,
        "re-key не применяется от неподтверждённого ACK"
    );
}

/// **Доп. (`02 §3.6`): потеря `RESUME_ACK` → ретрай с новым nonce, тот же ticket принимается один раз.**
///
/// Источник: `02 §3.6` (ретрай), `§3.7` (таймаут `T_ack`), `§3.8` (make-before-break).
#[test]
fn rotation_retry_after_lost_ack_new_nonce_same_ticket_accepted_once() {
    let mut driver = RotationDriver::new(session(K_SESSION), MemBinding::new(BindingCaps::QUIC));
    let streams: Vec<StreamId> = [FlowId(10), FlowId(11)]
        .iter()
        .map(|flow| driver.session.open_stream(*flow))
        .collect();
    driver.emit(streams[0], b"pre-0", 0);
    let last_seq = driver.session.last_seq().0;

    let (client_identity, client_identity_priv) = ed25519_genkey();
    let network = MockNetwork::new(ClientCreds {
        auth: client_identity,
        k_session: K_SESSION,
        last_seq,
    });
    network
        .borrow_mut()
        .add_node(NodeSim::new(2, 0x21, 0x31, EPOCH_ID));
    let manifest = network.borrow().nodes[&2].manifest();
    let (eph_a, eph_a_priv) = fresh_eph();
    let mut rotation = coordinator(
        network.clone(),
        &client_identity_priv,
        eph_a,
        eph_a_priv,
        last_seq,
        (0, 0),
    );
    let ticket = rotation.request_ticket(&manifest).expect("ticket");
    let timeout = driver.start_overlap(MemBinding::new(BindingCaps::QUIC), SRTT_MS);
    assert_eq!(timeout, 300, "T_morph/T_ack = 2 × SRTT = 300 мс, внутри клипа");

    // 1. ACK не пришёл → `T_ack`; узел при этом уже обработал RESUME (потерян был ответ).
    network.borrow_mut().drop_next_ack = true;
    assert_eq!(
        rotation.resume(&manifest, &ticket, eph_a),
        Err(ResumeError::AckTimeout)
    );
    assert_eq!(rotation.attempts(), 1);
    assert_eq!(
        network.borrow().nodes[&2].accepted,
        1,
        "узел принял RESUME и ответил — потерян именно ACK"
    );
    assert_eq!(
        network.borrow().nodes[&2].consumed_tickets(),
        1,
        "ticket принят один раз (`02 §3.6`)"
    );

    // 2. Ретрай: новый `client_nonce` и новый `eph_client`, ticket тот же.
    let (eph_b, eph_b_priv) = fresh_eph();
    rotation.set_eph_client(eph_b_priv, eph_b);
    assert_eq!(
        rotation.resume(&manifest, &ticket, eph_b),
        Err(ResumeError::Nacked),
        "тот же ticket на том же узле → `RESUME_NAK replay` (`02 §3.7`)"
    );
    assert_eq!(rotation.attempts(), 2);
    assert_eq!(
        network.borrow().nodes[&2].consumed_tickets(),
        1,
        "вторая сессия из повтора не появляется (`02 §3.5`: at-most-once на узел)"
    );
    assert_eq!(rotation.k_session_prime(), None, "NAK не даёт `K_session'`");
    assert_eq!(rotation.confirmed_eph_node(), None);

    // 4. Replay детектится по ticket, а не по nonce: тот же ticket с исходным nonce — тоже replay.
    let (same_nonce_request, _) = rotation
        .build_resume(&ticket, CLIENT_NONCE)
        .expect("RESUME собран");
    let replay = network
        .clone()
        .exchange(NodeId(2), &same_nonce_request)
        .expect("ответ узла");
    assert_eq!(
        replay,
        vec![WIRE_NAK, NAK_REPLAY],
        "ключ consumed-set — `epoch_id ‖ sha256(ticket_blob)` (`02 §3.6`)"
    );

    // 3. Потолок ретраев: третьей попытки нет, откат на старый канал.
    let sent_before = network.borrow().requests.len();
    assert_eq!(
        rotation.resume(&manifest, &ticket, eph_b),
        Err(ResumeError::AckTimeout),
        "больше двух попыток не делается (`02 §3.7`)"
    );
    assert_eq!(
        network.borrow().requests.len(),
        sent_before,
        "откат на старый канал — без нового RESUME"
    );

    // 6. Сессия не рвётся: старый канал жив, `seq` продолжается, потоков столько же.
    let during = driver.emit(streams[1], b"during", 0);
    assert!(delivered(&driver.old).contains(&(streams[1].0, during.seq.0)));
    assert_eq!(driver.session.stream_table().len(), 2);
    assert_eq!(driver.session.ratchet_restarts(), 0, "NAK не перезапускает ratchet");

    // 5. `K_session'` выводится от `eph_client` успешной попытки: новая попытка — новый ticket.
    let (client2, client2_priv) = ed25519_genkey();
    let network2 = MockNetwork::new(ClientCreds {
        auth: client2,
        k_session: K_SESSION,
        last_seq: driver.session.last_seq().0,
    });
    network2
        .borrow_mut()
        .add_node(NodeSim::new(2, 0x21, 0x31, EPOCH_ID));
    let manifest2 = network2.borrow().nodes[&2].manifest();
    let (eph_c, eph_c_priv) = fresh_eph();
    let mut retry = coordinator(
        network2.clone(),
        &client2_priv,
        eph_c,
        eph_c_priv,
        driver.session.last_seq().0,
        (0, 0),
    );
    let ticket2 = retry.request_ticket(&manifest2).expect("ticket");
    retry
        .resume(&manifest2, &ticket2, eph_c)
        .expect("валидный ACK");
    let node_eph = network2.borrow().nodes[&2].eph_node;
    retry.post_rotation_rekey(&node_eph).expect("re-key");
    let k_prime = retry.k_session_prime().expect("K_session'");
    assert_eq!(
        derive_rotated_session(&SID, &KSession(K_SESSION), &ss_rotate(&eph_c_priv, &node_eph)),
        KSession(k_prime),
        "K_session' выведен из `eph_client` успешной попытки (`02 §3.3`)"
    );
    assert_eq!(network2.borrow().nodes[&2].accepted, 1);
}
