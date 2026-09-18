//! Негативные сценарии ротации: NAK-ветки, гонка двух RESUME, подписи, падение узла.
//!
//! Утверждения — из `design/02-protocols.md` §3.3, §3.5, §3.6, §3.7, §3.8, §3.9 и
//! `design/05-roadmap.md` Phase 0 → «Негативные тесты ротации». Ни одного порога «по смыслу»:
//! все числа (`T_ack`, `T_quar`, окно 4096) — из таблиц спеки и `frame-session`.
//!
//! Во всех тестах проверяется общий инвариант `§3.8`: **Aether-сессия не рвётся на ротации** —
//! старый канал гасится только после валидного `RESUME_ACK` (make-before-break). Негативный
//! исход ротации не превращается в разрыв сессии.
//!
//! Тесты сняты с `#[ignore]` вместе с реализацией: assert'ы исходных спек сценариев 2–5
//! (и двух дополнительных из `05-roadmap`) реализованы в телах ниже.

mod harness;

use harness::*;

/// Три потока и одна запись — общий старт негативных прогонов.
fn three_streams() -> (RotationDriver, Vec<StreamId>) {
    let mut driver = RotationDriver::new(session(K_SESSION), MemBinding::new(BindingCaps::QUIC));
    let streams: Vec<StreamId> = [FlowId(10), FlowId(11), FlowId(12)]
        .iter()
        .map(|flow| driver.session.open_stream(*flow))
        .collect();
    driver.emit(streams[0], b"pre-0", 0);
    (driver, streams)
}

/// **Сценарий 2 (ТЗ): `epoch_id` не совпал → `RESUME_NAK epoch` → полный IK-handshake, старый канал жив.**
#[test]
fn rotation_epoch_mismatch_naks_and_falls_back_to_full_handshake() {
    let (mut driver, streams) = three_streams();
    let last_seq = driver.session.last_seq().0;
    let (client_identity, client_identity_priv) = ed25519_genkey();
    let network = SharedNetwork::new(ClientCreds {
        auth: client_identity,
        k_session: K_SESSION,
        last_seq,
    });
    // N1 — узел своей эпохи (он и минтит ticket), N2 — узел с чужой эпохой флота.
    network
        .borrow_mut()
        .add_node(NodeSim::new(1, 0x11, 0x21, EPOCH_ID));
    network
        .borrow_mut()
        .add_node(NodeSim::with_epoch(2, 0x31, 0x41, EPOCH_ID + 1));
    let mint_manifest = network.borrow().nodes[&1].manifest();
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
    let ticket = rotation
        .request_ticket(&mint_manifest)
        .expect("ticket эпохи N1");

    // 1/5. Узел чужой эпохи не разворачивает ticket и отвечает веткой `epoch`.
    assert_eq!(
        network.borrow().nodes[&2].unwrap_probe(&ticket),
        Err(TicketError::EpochMismatch),
        "`unwrap_ticket` не даёт `TicketPlain` на чужой эпохе (`ticket-mint`)"
    );
    assert_eq!(
        rotation.resume(&n2_manifest, &ticket, eph_public),
        Err(ResumeError::Nacked(KcResumeNak::Epoch)),
        "NAK с причиной доходит клиенту (F-06); ветка `epoch` (`02 §3.7`)"
    );
    assert_eq!(
        last_response(&network),
        vec![WIRE_NAK, NAK_EPOCH],
        "ветка `epoch` (`02 §3.7`)"
    );
    assert_eq!(
        network.borrow().nodes[&2].consumed_tickets(),
        0,
        "чужой узел ничего не консумирует"
    );
    assert_eq!(
        rotation.k_session_prime(),
        None,
        "второй сессии не появилось"
    );

    // 2. Фолбэк — полный гибридный IK-handshake (`02 §5`), один RTT, общий `K_session`.
    let (_, node_static_priv) = x25519_genkey().expect("node static");
    let mut responder = IkResponder::new(
        SID,
        x25519_keypair(&node_static_priv),
        mlkem768_genkey().expect("node static kem"),
    )
    .expect("responder");
    let node_static = responder.node_static();
    let node_static_kem = responder.node_static_kem();
    let (_, client_static_priv) = x25519_genkey().expect("client static");
    let mut initiator = IkInitiator::new(
        SID,
        x25519_keypair(&client_static_priv),
        mlkem768_genkey().expect("client static kem"),
        node_static,
        node_static_kem,
    )
    .expect("initiator");
    let msg1 = initiator.initiate().expect("msg1");
    assert!(
        msg1.len() >= MLKEM768_EK_BYTES,
        "msg1 несёт KEM-ключ инициатора: {} ≥ {MLKEM768_EK_BYTES} (`02 §5`)",
        msg1.len()
    );
    let (msg2, ks_node) = responder.respond(&msg1).expect("msg2");
    let ks_client = initiator.finish_initiator(&msg2).expect("K_session");
    assert_eq!(ks_client, ks_node, "фолбэк даёт общий `K_session`");
    assert!(
        msg2.len() >= crypto_core::MLKEM768_CT_BYTES,
        "msg2 несёт `kem_ct`"
    );

    // 3/4. Старый канал жив, состояние сессии не сброшено: NAK — не разрыв (`02 §1`, `§3.8`).
    let during = driver.emit(streams[1], b"during-nak", 0);
    assert!(delivered(&driver.old).contains(&(streams[1].0, during.seq.0)));
    assert_eq!(driver.session.stream_table().len(), 3);
    assert_eq!(driver.session.last_seq(), during.seq, "seq продолжается");
    assert_eq!(driver.session.ratchet_restarts(), 0);
}

/// **Доп. (`05-roadmap`): украденный ticket без валидной `sig_client` → `RESUME_NAK bad_pop`.**
#[test]
fn rotation_stolen_ticket_naks_bad_pop_and_is_not_consumed() {
    let (driver, _) = three_streams();
    let last_seq = driver.session.last_seq().0;
    let (client_identity, client_identity_priv) = ed25519_genkey();
    let (attacker_identity, attacker_priv) = ed25519_genkey();
    let network = SharedNetwork::new(ClientCreds {
        auth: client_identity,
        k_session: K_SESSION,
        last_seq,
    });
    network
        .borrow_mut()
        .add_node(NodeSim::new(2, 0x21, 0x31, EPOCH_ID));
    let manifest = network.borrow().nodes[&2].manifest();
    let (eph_public, eph_private) = fresh_eph();
    let mut client = coordinator(
        network.clone(),
        &client_identity_priv,
        eph_public,
        eph_private,
        last_seq,
        (0, 0),
    );
    let ticket = client.request_ticket(&manifest).expect("ticket");

    // 1. У атакующего есть ticket (и даже K_session), но нет приватного `client_identity`.
    let (thief_eph, thief_eph_priv) = fresh_eph();
    let mut thief = coordinator(
        network.clone(),
        &attacker_priv,
        thief_eph,
        thief_eph_priv,
        last_seq,
        (0, 0),
    );
    assert_eq!(
        thief.resume(&manifest, &ticket, thief_eph),
        Err(ResumeError::Nacked(KcResumeNak::BadPop)),
        "чужая подпись не даёт сессии (`02 §3.8`); причина — bad_pop (F-06)"
    );
    // 2. Узел проверил `sig_client` по ключу **из ticket** и не консумировал билет.
    assert_eq!(last_response(&network), vec![WIRE_NAK, NAK_BAD_POP]);
    assert_eq!(
        network.borrow().nodes[&2].consumed_tickets(),
        0,
        "bad_pop не консумирует ticket (`02 §3.7`)"
    );

    // 5. Побайтовое покрытие: подпись валидна, но чужим ключом — иначе NAK был бы ложным.
    let k_resume = k_resume_for(&K_SESSION);
    let (ctx, sig) = resume_ctx(&last_request(&network), &k_resume);
    assert!(
        ed25519_verify(&attacker_identity, &resume_signing_payload(&ctx), &sig),
        "подпись вором сделана корректно — но своим ключом"
    );
    assert!(
        !ed25519_verify(&client_identity, &resume_signing_payload(&ctx), &sig),
        "по `client_auth_pub` из ticket она не проходит (`02 §3.3`)"
    );

    // 4. Легитимная сессия не затронута: тот же ticket у того же узла проходит.
    client
        .resume(&manifest, &ticket, eph_public)
        .expect("билет не съеден отказом");
    assert_eq!(network.borrow().nodes[&2].accepted, 1);
    assert_eq!(network.borrow().nodes[&2].consumed_tickets(), 1);
    assert_eq!(driver.session.stream_table().len(), 3);
}

/// **Сценарий 4 (ТЗ): replay того же RESUME → идемпотентный NAK, а не вторая сессия.**
#[test]
fn rotation_replay_same_ticket_is_idempotent_nak_not_second_session() {
    let (driver, _) = three_streams();
    let last_seq = driver.session.last_seq().0;
    let (client_identity, client_identity_priv) = ed25519_genkey();
    let network = SharedNetwork::new(ClientCreds {
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
    rotation
        .resume(&manifest, &ticket, eph_public)
        .expect("первый резюм проходит");
    let first_request = last_request(&network);
    let parts = last_ack(&rotation);
    assert_eq!(
        network.borrow().nodes[&2].consumed_tickets(),
        1,
        "ticket принят один раз (`02 §3.6`)"
    );

    // 1/2. Повтор того же запроса и повтор того же ticket с другим nonce — оба replay.
    assert_eq!(
        network
            .clone()
            .exchange(NodeId(2), &first_request)
            .expect("ответ узла"),
        vec![WIRE_NAK, NAK_REPLAY],
        "ключ consumed-set — `epoch_id ‖ sha256(ticket_blob)`, а не nonce (`02 §3.6`)"
    );
    let (other_nonce_request, _) = rotation
        .build_resume(&ticket, [0x11; 16])
        .expect("RESUME собран");
    assert_eq!(
        network
            .clone()
            .exchange(NodeId(2), &other_nonce_request)
            .expect("ответ узла"),
        vec![WIRE_NAK, NAK_REPLAY],
        "другой nonce не меняет вердикт: replay детектится по ticket"
    );
    assert_eq!(network.borrow().nodes[&2].consumed_tickets(), 1);

    // 3/4. Второй сессии и второго `K_session'` нет; NAK идемпотентен, канал прежний.
    let mut node_window = DedupWindow::new(Seq(parts.window.0), Seq(parts.continuity_point));
    assert_eq!(
        node_window.accept(Seq(parts.continuity_point)),
        DedupOutcome::Accepted,
        "граница окна принимается один раз"
    );
    assert_eq!(
        node_window.accept(Seq(parts.continuity_point)),
        DedupOutcome::Duplicate,
        "повтор того же seq — дубль"
    );
    assert_eq!(
        node_window.continuity_point(),
        Seq(parts.continuity_point),
        "повтор не сдвигает continuity_point (`02 §3.5`)"
    );
    assert_eq!(
        rotation.attempts(),
        1,
        "повтор идёт мимо клиентского ретрая"
    );
    assert_eq!(rotation.k_session_prime(), None);

    // 5. В пределах жизни узла: набор теряется только при рестарте узла — принято (`02 §3.6`).
    let before = network.borrow().nodes[&2].consumed_tickets();
    let restarted = NodeSim::new(2, 0x21, 0x31, EPOCH_ID);
    assert_eq!(
        restarted.consumed_tickets(),
        0,
        "после рестарта набор пуст — митигация: короткие эпохи и `exp`"
    );
    assert_eq!(network.borrow().nodes[&2].consumed_tickets(), before);
    assert_eq!(driver.session.ratchet_restarts(), 0);
}

/// **Сценарий 5 (ТЗ): битые подписи — `sig_client` (узел) и `sig_node` (клиент) — сессия жива.**
#[test]
fn rotation_bad_signatures_reject_and_keep_old_channel() {
    let (mut driver, streams) = three_streams();
    let last_seq = driver.session.last_seq().0;
    let (client_identity, client_identity_priv) = ed25519_genkey();
    let (attacker_identity, attacker_priv) = ed25519_genkey();
    let network = SharedNetwork::new(ClientCreds {
        auth: client_identity,
        k_session: K_SESSION,
        last_seq,
    });
    network
        .borrow_mut()
        .add_node(NodeSim::new(2, 0x21, 0x31, EPOCH_ID));
    network
        .borrow_mut()
        .add_node(NodeSim::new(3, 0x51, 0x61, EPOCH_ID));
    let n2_manifest = network.borrow().nodes[&2].manifest();
    let n3_manifest = network.borrow().nodes[&3].manifest();
    network
        .borrow_mut()
        .nodes
        .get_mut(&3)
        .expect("узел 3")
        .corrupt_sig_node = true;

    // (а) битый `sig_client`: узел отвечает `bad_pop` и не консумирует ticket.
    let (eph_a, eph_a_priv) = fresh_eph();
    let mut thief = coordinator(
        network.clone(),
        &attacker_priv,
        eph_a,
        eph_a_priv,
        last_seq,
        (0, 0),
    );
    let ticket = thief.request_ticket(&n2_manifest).expect("ticket");
    assert_eq!(
        thief.resume(&n2_manifest, &ticket, eph_a),
        Err(ResumeError::Nacked(KcResumeNak::BadPop))
    );
    assert_eq!(last_response(&network), vec![WIRE_NAK, NAK_BAD_POP]);
    assert_eq!(network.borrow().nodes[&2].consumed_tickets(), 0);
    let k_resume = k_resume_for(&K_SESSION);
    let (thief_ctx, thief_sig) = resume_ctx(&last_request(&network), &k_resume);
    assert!(
        ed25519_verify(
            &attacker_identity,
            &resume_signing_payload(&thief_ctx),
            &thief_sig
        ),
        "подпись вором сделана корректно, но своим ключом"
    );
    assert!(
        !ed25519_verify(
            &client_identity,
            &resume_signing_payload(&thief_ctx),
            &thief_sig
        ),
        "по `client_auth_pub` из ticket она не проходит (`02 §3.3`)"
    );

    // (б) битый `sig_node`: клиент отклоняет канал, `K_session'` не применяется.
    let (eph_b, eph_b_priv) = fresh_eph();
    let mut victim = coordinator(
        network.clone(),
        &client_identity_priv,
        eph_b,
        eph_b_priv,
        last_seq,
        (0, 0),
    );
    let ticket_b = victim.request_ticket(&n3_manifest).expect("ticket");
    let err = victim
        .resume(&n3_manifest, &ticket_b, eph_b)
        .expect_err("битая sig_node обязана отклоняться");
    assert_eq!(err, ResumeError::BadNodeSignature);
    assert_ne!(
        err,
        ResumeError::Nacked(KcResumeNak::BadPop),
        "спека различает эти исходы (`02 §3.7`)"
    );
    assert_eq!(victim.confirmed_eph_node(), None, "канал не подтверждён");
    assert_eq!(victim.k_session_prime(), None, "ratchet не перезапущен");
    assert_eq!(
        network.borrow().nodes[&3].accepted,
        1,
        "узел-нарушитель ответил"
    );

    // 3/5. Сессия не рвётся: `K_session`, `seq` и потоки на месте, старый канал несёт трафик.
    let during = driver.emit(streams[2], b"during-bad-sig", 0);
    assert!(delivered(&driver.old).contains(&(streams[2].0, during.seq.0)));
    assert_eq!(driver.session.stream_table().len(), 3);
    assert_eq!(driver.session.ratchet_restarts(), 0);
    assert_eq!(driver.session.confirmed_ack(), None);
}

/// **Сценарий 3 (ТЗ): гонка двух RESUME — первый валидный ACK побеждает, второй в quarantine.**
///
/// Замечание о границе Phase 0: **применение** quarantine — ребро FSM морфинга
/// (`morph-controller`, Phase 1, в Phase 0 не создаётся). Тест фиксирует то, что уже
/// существует: оба ACK валидны (набором гонка не решается), применяется ровно один
/// результат, а проигравший канал уходит в quarantine на `T_quar` из `02 §4`.
#[test]
fn rotation_two_acks_race_first_valid_wins_second_quarantined() {
    let (mut driver, streams) = three_streams();
    let last_seq = driver.session.last_seq().0;
    let (client_identity, client_identity_priv) = ed25519_genkey();
    let network = SharedNetwork::new(ClientCreds {
        auth: client_identity,
        k_session: K_SESSION,
        last_seq,
    });
    network
        .borrow_mut()
        .add_node(NodeSim::new(2, 0x21, 0x31, EPOCH_ID));
    network
        .borrow_mut()
        .add_node(NodeSim::new(3, 0x51, 0x61, EPOCH_ID));
    let n2_manifest = network.borrow().nodes[&2].manifest();
    let n3_manifest = network.borrow().nodes[&3].manifest();
    let n2_identity = network.borrow().nodes[&2].identity;
    let n3_identity = network.borrow().nodes[&3].identity;

    let (eph_a, eph_a_priv) = fresh_eph();
    let mut rotation = coordinator(
        network.clone(),
        &client_identity_priv,
        eph_a,
        eph_a_priv,
        last_seq,
        (0, 0),
    );
    let ticket = rotation.request_ticket(&n2_manifest).expect("ticket");
    let timeout = driver.start_overlap(MemBinding::new(BindingCaps::QUIC), SRTT_MS);
    assert_eq!(timeout, 300);
    let k_resume = k_resume_for(&K_SESSION);

    // 1. Оба разных узла принимают один ticket: consumed-set живёт на узле, не на флоте.
    rotation
        .resume(&n2_manifest, &ticket, eph_a)
        .expect("ACK от N2");
    let request_n2 = last_request(&network);
    let parts_n2 = last_ack(&rotation);
    let (ctx_n2, _) = resume_ctx(&request_n2, &k_resume);

    // 2/4. Первый валидный ACK побеждает и применяется сразу: `K_session'` считается от его
    //      `eph_node` и `eph_client` той же попытки, ratchet перезапускается один раз.
    assert!(node_signature_verifies(&n2_identity, &parts_n2, &ctx_n2));
    apply_confirmed_ack(&mut driver.session, &parts_n2);
    rotation
        .post_rotation_rekey(&KcX25519Pub(parts_n2.eph_node))
        .expect("re-key от победителя");
    let k_prime = rotation.k_session_prime().expect("K_session'");
    assert_eq!(
        derive_rotated_session(
            &SID,
            &KSession(K_SESSION),
            &ss_rotate(&eph_a_priv, &KcX25519Pub(parts_n2.eph_node))
        ),
        KSession(k_prime),
        "ключ победителя выведен из `eph_client` и `eph_node` одной попытки (`02 §3.3`)"
    );
    driver.session.ratchet_from(&k_prime);
    let seq_after_winner = driver.session.last_seq();
    assert_eq!(driver.session.ratchet_restarts(), 1);

    // Поздний второй ACK от N3 приходит уже после победы: он тоже валиден.
    let (eph_b, eph_b_priv) = fresh_eph();
    rotation.set_eph_client(eph_b_priv, eph_b);
    rotation
        .resume(&n3_manifest, &ticket, eph_b)
        .expect("ACK от N3 на тот же ticket");
    let request_n3 = last_request(&network);
    let parts_n3 = last_ack(&rotation);
    let (ctx_n3, _) = resume_ctx(&request_n3, &k_resume);
    assert_eq!(network.borrow().nodes[&2].accepted, 1);
    assert_eq!(network.borrow().nodes[&3].accepted, 1);
    assert_eq!(network.borrow().nodes[&2].consumed_tickets(), 1);
    assert_eq!(network.borrow().nodes[&3].consumed_tickets(), 1);

    // 3. Оба ACK валидны — то есть гонка не решается «кто настоящий».
    assert!(node_signature_verifies(&n3_identity, &parts_n3, &ctx_n3));
    assert_ne!(
        parts_n2.eph_node, parts_n3.eph_node,
        "разные узлы — разные `eph_node`"
    );

    // Проигравший канал не применяется: ключ победителя не подменён, ratchet не перезапущен.
    assert_eq!(
        rotation.k_session_prime(),
        Some(k_prime),
        "в сессии остался ключ победителя"
    );
    assert_eq!(
        driver.session.ratchet_restarts(),
        1,
        "второй ACK ничего не меняет"
    );
    assert_eq!(driver.session.last_seq(), seq_after_winner);
    assert_ne!(
        derive_rotated_session(
            &SID,
            &KSession(K_SESSION),
            &ss_rotate(&eph_b_priv, &KcX25519Pub(parts_n3.eph_node))
        ),
        KSession(k_prime),
        "ключ проигравшего в сессию не попал"
    );

    // 5. Проигравший канал — quarantine `T_quar` = 5 мин (исполнение — FSM, Phase 1).
    assert_eq!(T_QUARANTINE_MS, 300_000);

    // 6. Сессия не рвётся: победивший канал несёт `seq` дальше.
    let after = driver.emit_after_rotation(streams[0], b"after-race");
    assert!(after.seq > seq_after_winner, "нумерация продолжается");
    assert!(
        delivered(driver.new.as_ref().expect("новый канал")).contains(&(streams[0].0, after.seq.0)),
        "трафик идёт по победившему каналу"
    );
}

/// **Доп. (`05-roadmap`): узел упал между RESUME и RESUME_ACK → откат без разрыва сессии.**
///
/// Граница Phase 0: буфер фолбэка frame-слоя (**≤ 16 МБ или ≤ 5 с**, `05-roadmap`, таблица
/// рисков) в Phase 0 не реализован — в `03-components` типа буфера нет. Тест фиксирует то,
/// что существует (сессия жива, дубли окна уже у нового узла, трафик продолжается), а сам
/// буфер вынесен в `QUESTIONS.md` как BLOCKER, а не выдан за сделанный.
#[test]
fn rotation_node_down_mid_rotation_rolls_back_without_session_break() {
    let (mut driver, streams) = three_streams();
    let last_seq = driver.session.last_seq().0;
    let (client_identity, client_identity_priv) = ed25519_genkey();
    let network = SharedNetwork::new(ClientCreds {
        auth: client_identity,
        k_session: K_SESSION,
        last_seq,
    });
    network
        .borrow_mut()
        .add_node(NodeSim::new(2, 0x21, 0x31, EPOCH_ID));
    let n2_manifest = network.borrow().nodes[&2].manifest();
    let (eph_a, eph_a_priv) = fresh_eph();
    let mut rotation = coordinator(
        network.clone(),
        &client_identity_priv,
        eph_a,
        eph_a_priv,
        last_seq,
        (0, 0),
    );
    let ticket = rotation.request_ticket(&n2_manifest).expect("ticket");
    driver.start_overlap(MemBinding::new(BindingCaps::QUIC), SRTT_MS);

    // (а) Новый узел недоступен до ACK: `T_ack`, а старый канал жив.
    network.borrow_mut().unreachable.insert(2);
    assert_eq!(
        rotation.resume(&n2_manifest, &ticket, eph_a),
        Err(ResumeError::AckTimeout),
        "T_ack истёк — ветка таймаута (`02 §3.7`)"
    );
    assert_eq!(rotation.attempts(), 1);
    let during = driver.emit(streams[0], b"during-node-down", 0);
    assert!(
        delivered(&driver.old).contains(&(streams[0].0, during.seq.0)),
        "старый канал живёт до валидного ACK (`02 §3.8`)"
    );

    // Берём другой узел набора: набор не пуст, пока есть хоть один живой узел.
    network.borrow_mut().unreachable.clear();
    network
        .borrow_mut()
        .add_node(NodeSim::new(3, 0x51, 0x61, EPOCH_ID));
    let n3_manifest = network.borrow().nodes[&3].manifest();
    let (eph_b, eph_b_priv) = fresh_eph();
    rotation.set_eph_client(eph_b_priv, eph_b);
    let continuity = rotation
        .resume(&n3_manifest, &ticket, eph_b)
        .expect("другой узел набора принял тот же ticket");
    assert_eq!(continuity.point, last_seq);

    // (б) Старый узел снят **до** ACK: окно ещё открыто, поэтому запись идёт на оба канала,
    //      отказ старого канала фиксируется, а дубль доносит её новым узлом — сессия жива.
    let parts = last_ack(&rotation);
    driver.old.mark_closed();
    let during_down = driver.emit_tolerant(streams[1], b"old-down-before-ack", 0);
    assert_eq!(
        driver.old_failures, 1,
        "старый канал снят — его отказ не разрывает сессию"
    );
    assert!(
        delivered(driver.new.as_ref().expect("новый канал"))
            .contains(&(streams[1].0, during_down.seq.0)),
        "дубль окна донёс запись новым каналом до применения ACK"
    );

    // Теперь ACK применяется: окно закрывается, ключ меняется, трафик идёт новым каналом.
    apply_confirmed_ack(&mut driver.session, &parts);
    rotation
        .post_rotation_rekey(&KcX25519Pub(parts.eph_node))
        .expect("re-key");
    let k_prime = rotation.k_session_prime().expect("K_session'");
    driver.session.ratchet_from(&k_prime);
    assert!(driver.promote_on_ack(true), "окно закрыто валидным ACK");
    assert!(driver.session.overlap().expect("окно").is_closed());
    let after = driver.emit_after_rotation(streams[2], b"after-old-down");
    assert!(
        delivered(driver.new.as_ref().expect("новый канал")).contains(&(streams[2].0, after.seq.0)),
        "запись доставлена новым каналом"
    );

    // 5. Сессия цела: `K_session`/`seq`/потоки на месте.
    assert_eq!(driver.session.stream_table().len(), 3);
    assert_eq!(driver.session.ratchet_restarts(), 1);
    assert_eq!(driver.session.last_seq(), after.seq);
    assert!(after.seq > during_down.seq);
    assert!(after.seq > during.seq);
}
