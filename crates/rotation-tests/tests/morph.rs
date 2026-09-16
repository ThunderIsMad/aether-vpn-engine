//! Морф обложки mid-session: QUIC-байндинг → mock-Reality. Это **не** ротация IP.
//!
//! Источник: `design/02-protocols.md` §2.1 (QUIC-байндинг), §2.2 (Reality/TCP и его
//! задокументированный HOL-tradeoff), §4 (overlap-window при морфе, таблица параметров),
//! §1 («сессия живёт, пока жив `(K_session, stream_table, seq)`»).
//!
//! Граница: меняется **байндинг**, а не узел и не `egress IP`. Поэтому тест не требует того,
//! что относится к ротации (тикет, PoP, `eph_node`/`sig_node`, re-key) — и наоборот:
//! ротация не должна ломать морф.

mod harness;

use harness::*;

/// **Сценарий 7 (ТЗ): морф QUIC → mock-Reality mid-session — frame-сессия жива, стримы не сброшены.**
#[test]
fn morph_quic_to_mock_reality_keeps_frame_session_alive() {
    let mut driver = RotationDriver::new(session(K_SESSION), MemBinding::new(BindingCaps::QUIC));
    let streams: Vec<StreamId> = [FlowId(10), FlowId(11), FlowId(12)]
        .iter()
        .map(|flow| driver.session.open_stream(*flow))
        .collect();
    let mut records = Vec::new();
    for stream in &streams {
        records.push(driver.emit(*stream, b"pre-morph", 0));
    }
    let seq_before = driver.session.last_seq();
    assert_eq!(driver.old.supports(), BindingCaps::QUIC, "стартовая обложка — QUIC");
    assert!(driver.old.supports().no_hol, "QUIC: no-HOL бесплатно (`01 §6`)");

    // 7. Морф на length-prefixed mock-Reality: HOL есть, QUIC-over-TCP не используется.
    let timeout = driver.start_overlap(MemBinding::new(BindingCaps::REALITY_TCP), SRTT_MS);
    assert_eq!(timeout, 300, "T_morph = 2 × SRTT, внутри клипа `[200 ms, 2 s]`");
    let reality = driver
        .new
        .as_ref()
        .expect("новая обложка подключена")
        .supports();
    assert!(
        !reality.no_hol,
        "HOL на Reality/TCP — задокументированный tradeoff (`02 §2.2`)"
    );
    assert!(
        !reality.datagram,
        "Reality/TCP не сохраняет датаграммную семантику"
    );

    // 2. Ни один прикладной поток не сброшен: те же `stream_id`, та же FIN-семантика, `seq` идёт.
    let mut during = Vec::new();
    for stream in &streams {
        during.push(driver.emit(*stream, b"during-morph", 0));
    }
    assert_eq!(driver.duplicated, 3, "окно дублирует записи на обе обложки (`02 §4`)");
    for (record, stream) in during.iter().zip(streams.iter()) {
        assert_eq!(record.stream_id, *stream, "`stream_id` не сбрасывается");
        assert_eq!(record.kind, RecordType::Data, "тип записи не меняется");
        assert_eq!(record.flags, 0, "FIN-семантика сохраняется");
    }
    assert!(during[2].seq > seq_before, "стримы продолжают нумерацию (`02 §1`)");

    // 1. Морф не трогает ключи: `K_session` жив, ratchet не перезапускается, потоков столько же.
    assert_eq!(driver.session.ratchet_restarts(), 0, "морф — не ротация узла");
    assert_eq!(driver.session.stream_table().len(), 3);
    assert_eq!(driver.session.session_id(), SessionId(SID));

    // 3. Условие закрытия окна — **валидный** ACK по новой обложке; старый байндинг гасится после.
    assert!(!driver.promote_on_ack(false), "невалидный ACK окно не закрывает");
    assert!(!driver.session.overlap().expect("окно").is_closed());
    assert!(driver.promote_on_ack(true), "валидный ACK закрывает окно");
    assert!(driver.session.overlap().expect("окно").is_closed());
    let on_new = delivered(driver.new.as_ref().expect("новая обложка"));

    // 4. Параметры окна и исчерпание → `MorphFailed` → ребро отката на предыдущий байндинг.
    let clipped = driver.start_overlap(MemBinding::new(BindingCaps::REALITY_TCP), 5_000);
    assert_eq!(clipped, 2_000, "клип сверху 2 s (`02 §4`)");
    assert_eq!(
        driver.session.duplicate(clipped),
        DuplicateStep::Exhausted,
        "исчерпание `T_morph` — `MorphFailed`"
    );
    assert!(driver.session.overlap().expect("окно").is_exhausted());
    assert_eq!(T_QUARANTINE_MS, 300_000, "обложка в quarantine на `T_quar` = 5 мин (`02 §4`)");
    assert!(
        !driver.promote_on_ack(false),
        "исчерпанное окно закрывает только валидный ACK, иначе — rollback"
    );

    // 5. Оба пути отказа ведут к FSM: синхронный `BindingError` и асинхронный `on_failure`.
    let mut broken = MemBinding::new(BindingCaps::REALITY_TCP);
    let record = driver.session.seal_record(streams[0], b"after-morph");
    assert_eq!(broken.send(&record), Ok(()));
    broken.mark_closed();
    assert_eq!(
        broken.send(&record),
        Err(BindingError::TransportDown),
        "синхронный отказ — `BindingError` (`03`, контракт `CoverBinding`)"
    );
    assert_eq!(
        broken.on_failure(),
        Some(BindingFailure::Closed),
        "асинхронный отказ доходит до FSM тем же путём (`02 §4`)"
    );
    let mut probed = MemBinding::new(BindingCaps::REALITY_TCP);
    probed.inject_failure(BindingFailure::Probed);
    assert_eq!(probed.on_failure(), Some(BindingFailure::Probed));

    // 6. Reality/TCP не теряет записи в журнале: порядок обеспечивает `seq` frame-слоя,
    //    а не транспорт (HOL — цена статики, `02 §2.2`).
    records.extend(during.iter().cloned());
    let on_old = delivered(&driver.old);
    assert_eq!(
        records_set(&records),
        on_old,
        "старая обложка донесла все записи до ACK"
    );
    let journal: Vec<u64> = driver.old.journal().iter().map(|(_, seq)| *seq).collect();
    assert!(
        journal.windows(2).all(|pair| pair[0] <= pair[1]),
        "порядок журнала монотонен по `seq`"
    );
    assert_eq!(
        on_new.len(),
        during.len(),
        "новая обложка получила все дубли окна"
    );
}
