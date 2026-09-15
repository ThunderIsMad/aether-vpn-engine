//! Морф обложки mid-session: QUIC-байндинг → mock-Reality. Это **не** ротация IP.
//!
//! Источник: `design/02-protocols.md` §2.1 (QUIC-байндинг), §2.2 (Reality/TCP и его
//! задокументированный HOL-tradeoff), §4 (overlap-window при морфе, таблица параметров),
//! §1 («сессия живёт, пока жив `(K_session, stream_table, seq)`»).
//!
//! Граница: меняется **байндинг**, а не узел и не `egress IP`. Поэтому тест не имеет права
//! требовать того, что относится к ротации (тикет, PoP, `eph_node`/`sig_node`, re-key) — и
//! наоборот: ротация не должна ломать морф.
//!
//! Тело — `todo!()` под `#[ignore]`.
//!
//! **Покрытие ТЗ:** сценарий 7 (морф обложки mid-session; это не ротация IP) →
//! `morph_quic_to_mock_reality_keeps_frame_session_alive`.

/// **Сценарий 7 (ТЗ): морф QUIC → mock-Reality mid-session — frame-сессия жива, стримы не сброшены.**
///
/// Источник: `02 §4` (механизм морфа и таблица окна), `§2.1`, `§2.2`, `§1`.
///
/// Assert'ы:
/// 1. Морф = смена активного байндинга в TransportMux (`§4`); `K_session`, `seq`, `stream_table`
///    **не меняются** — это не ротация узла (`§1`).
/// 2. Ни один прикладной поток не сбрасывается: `stream_id` и FIN-семантика (flags) сохраняются,
///    стримы продолжают нумерацию (`§1`).
/// 3. Overlap-window: дублирование records на старый+новый байндинги до **валидного ACK по новому**
///    (`§4`, строка «Условие закрытия»); старый байндинг гасится после ACK.
/// 4. Параметры окна: `T_morph` = 2 × SRTT, клип [200 ms, 2 s]; бюджет `N ≤ 4096` записей **или**
///    `T_morph` — что раньше; исчерпание → `MorphFailed` → ребро отката на предыдущий байндинг,
///    обложка в quarantine `T_quar` = 5 мин (`§4`, таблица).
/// 5. Синхронный отказ `send()` → `BindingError` → FSM, обложка в quarantine; асинхронный
///    `on_failure()` → тот же путь rollback/quarantine (`§4`, строки 6–7; контракт `CoverBinding`
///    в `03-components` совпадает с `transport-mux`).
/// 6. Reality/TCP даёт HOL-блокировку — задокументированный tradeoff (`§2.2`): тест не требует
///    отсутствия HOL, он требует, чтобы записи **не терялись** и порядок обеспечивался `seq`
///    frame-слоя, а не транспортом.
/// 7. QUIC-over-TCP не используется (`§2.2`) — mock-Reality несёт length-prefixed frames, не QUIC.
#[test]
#[ignore = "контракт Phase 0: тело намеренно todo!() — тест начнёт проходить вместе с реализацией"]
fn morph_quic_to_mock_reality_keeps_frame_session_alive() {
    // Моки: MockQuic и MockReality — две реализации `CoverBinding` (trait objects), in-memory.
    // MockReality несёт length-prefixed frames (`§2.2`) и умеет отдать `BindingError`/`on_failure`
    // для проверки rollback-веток FSM.
    todo!("Phase 0: смена байндинга QUIC→mock-Reality mid-session; сессия и стримы живы (02 §2.2/§4)")
}