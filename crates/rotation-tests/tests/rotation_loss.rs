//! Потери при ротации: отдельный прогон на **одном** канале и отдельный — на **обоих**.
//!
//! Разделение прогонов задано в `design/05-roadmap.md` Phase 0: «Отдельно — прогон с потерей на
//! одном канале и прогон с потерей на обоих (фолбэк-путь)». Смешивать их нельзя: у них разные
//! ожидаемые исходы (деградация против провала ротации).
//!
//! Бюджеты — из `design/02-protocols.md` §4 (таблица окна морфа) и `§3.5` (окно дедупа):
//! `T_morph` = 2 × SRTT, клип [200 ms, 2 s]; дублирование `N ≤ 4096` записей **или** `T_morph` —
//! что раньше; исчерпание → `MorphFailed` → откат + quarantine `T_quar` = 5 мин.
//!
//! Граница Phase 0: буфер фолбэка (**≤ 16 МБ или ≤ 5 с**) не реализован — в `03-components`
//! такого типа нет; он вынесен в `QUESTIONS.md` как BLOCKER. Здесь проверяется то, что
//! существует: выживший канал, дубли, бюджет окна и `MorphFailed` → откат.

mod harness;

use harness::*;

/// **Сценарий 6a (ТЗ): потеря на одном канале — дубли укладываются в `T_morph` и `N ≤ 4096`.**
#[test]
fn rotation_loss_on_one_channel_stays_within_duplicate_budget() {
    let mut driver = RotationDriver::new(session(K_SESSION), MemBinding::new(BindingCaps::QUIC));
    let streams: Vec<StreamId> = [FlowId(10), FlowId(11), FlowId(12)]
        .iter()
        .map(|flow| driver.session.open_stream(*flow))
        .collect();
    let mut records = Vec::new();
    for stream in &streams {
        records.push(driver.emit(*stream, b"pre", 0));
    }
    let last_seq = driver.session.last_seq().0;

    // Ротация: новый канал теряет каждую третью запись — потерь «в сети» хватает, чтобы
    // выживание обеспечивалось именно дублированием на старый канал (`02 §3.3` шаг 5).
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
    let timeout = driver.start_overlap(MemBinding::new(BindingCaps::QUIC).with_loss_every(3), SRTT_MS);
    assert_eq!(timeout, 300, "T_morph = 2 × SRTT, внутри клипа `[200 ms, 2 s]`");

    // Окно: 6 записей на оба канала, затем валидный ACK.
    let mut during = Vec::new();
    for (index, stream) in streams.iter().enumerate() {
        during.push(driver.emit(*stream, format!("loss-{index}").as_bytes(), 0));
    }
    let continuity = rotation
        .resume(&manifest, &ticket, eph_public)
        .expect("валидный ACK");
    let k_resume = k_resume_for(&K_SESSION);
    let parts = parse_ack(&last_request(&network), &last_response(&network), &k_resume);
    driver.session.on_resume_ack(
        Seq(parts.continuity_point),
        DuplicateWindow {
            lo: Seq(parts.window.0),
            hi: Seq(parts.window.1),
        },
        FrameX25519Pub(parts.eph_node),
        FrameSignature(parts.sig_node),
    );
    assert!(driver.promote_on_ack(true));
    assert_eq!(continuity.point, parts.continuity_point);

    records.extend(during.iter().cloned());
    let n1 = delivered(&driver.old);
    let n2 = delivered(driver.new.as_ref().expect("новый канал"));

    // 1. Выживший канал (N1) донёс всё: ни одна запись не потеряна.
    assert_eq!(
        records_set(&records),
        n1.union(&n2).copied().collect::<std::collections::BTreeSet<_>>(),
        "выживший канал донёс все записи"
    );
    assert!(
        n2.len() < during.len(),
        "новый канал действительно терял ({} из {})",
        n2.len(),
        during.len()
    );

    // 2. Дубли идут по `seq >= continuity_point` и отсекаются дедупом `(sid, seq)`.
    let mut node_window = DedupWindow::new(Seq(parts.window.0), Seq(parts.continuity_point));
    for record in &during {
        assert_eq!(
            node_window.accept(record.seq),
            DedupOutcome::Accepted,
            "запись {} выше continuity_point — новая",
            record.seq.0
        );
    }
    let boundary = node_window.continuity_point();
    assert_eq!(node_window.accept(boundary), DedupOutcome::Duplicate);
    assert_eq!(
        node_window.continuity_point(),
        boundary,
        "повтор не двигает continuity_point (`02 §3.5`)"
    );

    // 3/5. Бюджет окна соблюдён: `N ≤ 4096` записей **или** `T_morph` — что раньше; `T_ack` тот же.
    assert!(driver.duplicated <= frame_session::DUPLICATE_WINDOW_RECORDS);
    assert_eq!(driver.duplicated as usize, during.len());
    assert_eq!(driver.exhausted, 0, "бюджет не исчерпан — это деградация, не провал");
    assert_eq!(t_ack_ms(SRTT_MS), timeout, "T_ack владеет FrameSession (`02 §3.7`)");

    // 6. Сессия не рвётся, `seq` продолжается.
    let after = driver.emit_after_rotation(streams[0], b"after-loss");
    assert!(after.seq > during[2].seq);
    assert_eq!(driver.session.stream_table().len(), 3);
}

/// **Сценарий 6b (ТЗ): потеря на обоих каналах — фолбэк-путь и граница бюджета.**
///
/// Assert'ы 1–2 исходной спеки частично упираются в отсутствующий буфер фолбэка: он назван
/// в `05-roadmap` (≤ 16 МБ или ≤ 5 с), но типа буфера в `03-components` нет, и Phase 0 его
/// не содержит (BLOCKER в `QUESTIONS.md`). Проверяется то, что существует: бюджет окна
/// исчерпывается → `MorphFailed` → откат на прежний байндинг, сессия при этом жива.
#[test]
fn rotation_loss_on_both_channels_falls_back_to_buffer_path() {
    let mut driver = RotationDriver::new(session(K_SESSION), MemBinding::new(BindingCaps::QUIC));
    let streams: Vec<StreamId> = [FlowId(10), FlowId(11)]
        .iter()
        .map(|flow| driver.session.open_stream(*flow))
        .collect();
    driver.emit(streams[0], b"pre", 0);
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
    assert_eq!(ticket.blob.0.len(), 161, "ticket выдан, но резюма в этом прогоне не будет");

    // (а) Потеря на обоих каналах: запись не доставлена ни одним из них, но сессия жива.
    driver.old.set_loss_every(2);
    let timeout = driver.start_overlap(MemBinding::new(BindingCaps::QUIC).with_loss_every(1), SRTT_MS);
    assert_eq!(timeout, 300);
    let lost = driver.emit(streams[0], b"lost-everywhere", 0);
    assert!(
        !delivered(&driver.old).contains(&(streams[0].0, lost.seq.0)),
        "старый канал потерял запись"
    );
    assert!(
        !delivered(driver.new.as_ref().expect("новый канал")).contains(&(streams[0].0, lost.seq.0)),
        "новый канал потерял ту же запись"
    );
    assert_eq!(
        driver.session.last_seq(),
        lost.seq,
        "frame-слой не теряет состояние: seq уже выдан и в буфере/окне (BLOCKER: буфера ≤ 16 МБ/≤ 5 с в Phase 0 нет)"
    );
    assert_eq!(driver.session.stream_table().len(), 2, "потоки не сброшены");

    // (б) Бюджет окна исчерпан по времени → `MorphFailed` → откат, окно не закрывается ACK'ом.
    assert!(!driver.promote_on_ack(false), "невалидный ACK окно не закрывает");
    let mut exhausted_after = 0;
    for _ in 0..3 {
        if matches!(
            driver.session.duplicate(timeout),
            DuplicateStep::Exhausted
        ) {
            exhausted_after += 1;
        }
    }
    assert_eq!(exhausted_after, 3, "по истечении `T_morph` окно исчерпано (`02 §4`)");
    assert!(
        driver.session.overlap().expect("окно открыто").is_exhausted(),
        "исчерпание — это `MorphFailed`, а не «деградация» (`02 §4`)"
    );
    assert!(
        !driver.session.overlap().expect("окно открыто").is_closed(),
        "без валидного ACK окно не закрывается: FSM идёт ребром Rollback"
    );

    // 4. Откат не является разрывом сессии: `K_session`, потоки и `seq` сохраняются.
    let after_rollback = driver.emit_after_rotation(streams[1], b"after-rollback");
    assert!(after_rollback.seq > lost.seq);
    assert_eq!(driver.session.stream_table().len(), 2);
    assert_eq!(driver.session.ratchet_restarts(), 0, "откат не трогает ключи");

    // 3/5. Quarantine и граница измерения: `T_quar` = 5 мин, метрика — frame-слой.
    assert_eq!(T_QUARANTINE_MS, 300_000, "канал в quarantine на 5 минут (`02 §4`)");
    assert_eq!(timeout, t_morph_ms(SRTT_MS));
}
