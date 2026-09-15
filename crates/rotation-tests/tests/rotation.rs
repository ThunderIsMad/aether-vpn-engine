//! Ротация egress-узла N1 → N2: happy path, continuity, forward secrecy, ретрай после потери ACK.
//!
//! Утверждения взяты из `design/02-protocols.md` §1, §3.3, §3.5, §3.6, §3.7, §3.9 и
//! `design/05-roadmap.md` Phase 0 → «Интеграционный тест ротации» (главный риск проекта).
//!
//! Моки: два in-memory байндинга (реализации трейта `CoverBinding`, `transport-mux`) со
//! счётчиками отправленных записей и журналом `(sid, seq)`; узлы — моки `TicketMint`
//! (`ticket-mint`) со своим флотским `TFK_epoch`. Сети нет.
//!
//! Граница измерения: frame-слой, не payload-соединения (`05-roadmap`). Разрыв прикладных
//! TCP/QUIC сменой source IP — ожидаемый эффект Phase 0, не регресс.
//!
//! Тела — `todo!()` под `#[ignore]`: реализует `impl-phase-driver`, критерии — из assert'ов ниже.
//! **Покрытие ТЗ:** сценарий 1 (happy path) — `rotation_happy_path_three_streams_no_loss`;
//! его re-key/PQ-FS-часть — `rotation_forward_secrecy_old_k_session_cannot_open_new_records`;
//! дополнительно (из `02 §3.6`) — `rotation_retry_after_lost_ack_new_nonce_same_ticket_accepted_once`.

/// **Сценарий 1 (главный тест Phase 0): happy path ротации — 3 потока, N1 → N2 по ticket, 0 потерь.**
///
/// Источник: `02 §3.3` (RESUME/RESUME_ACK, make-before-break), `§3.5` (окно дедупа), `§3.9`
/// («Duplicate-окно при ротации ≈ 1 RTT дублированного трафика — bounded»), `05-roadmap` Phase 0.
///
/// Assert'ы:
/// 1. Открыты 3 прикладных потока (`§1`: `stream_id` ↔ один app flow); в каждом есть запись до ротации.
/// 2. `RESUME` несёт `last_seq`, `window_lo/hi`, `eph_client`, `client_nonce`, `sig_client`, где
///    `sig_client` покрывает `"aether-resume-v3" ‖ sha256(ticket_blob) ‖ last_seq ‖ window_lo ‖
///    window_hi ‖ eph_client ‖ client_nonce` (`§3.3`).
/// 3. N2 разворачивает `ticket_blob` флотским `TFK_epoch` и проверяет `sig_client` по
///    `client_auth_pub` из ticket — PoP пройден (`§3.3`, `§3.8`).
/// 4. Ноль потерянных записей на обоих каналах: до валидного `RESUME_ACK` записи
///    `seq >= continuity_point` дублируются на N1 и N2; N1 гасится только после ACK (`§3.3`, `§3.8`).
/// 5. `continuity_point` монотонен и равен границе дублированного окна; повтор `seq` внутри окна
///    его не двигает (`§3.5`). Нумерация `seq` продолжается — сессия не соединение (`§1`).
/// 6. Окно закрылось в бюджет: `T_morph` = 2 × SRTT, клип [200 ms, 2 s] **и** `N ≤ 4096` —
///    что раньше (`§4`); дубли отсекаются дедупом `(sid, seq)` (`§3.5`).
/// 7. Post-rotation re-key: `ss_rotate = DH(eph_client_priv, eph_node_pub)` (32 B),
///    `K_session' = HKDF-Expand(HKDF-Extract(salt = session_id, ikm = ss_rotate ‖ K_session),
///    "aether v3 rotate", 32)`; ratchet `K_record` перезапущен от `K_session'` (`§3.3`).
#[test]
#[ignore = "контракт Phase 0: тело намеренно todo!() — тест начнёт проходить вместе с реализацией"]
fn rotation_happy_path_three_streams_no_loss() {
    // Мок-байндинги N1/N2 со счётчиками и журналом (sid, seq); узел N2 стартует без состояния
    // сессии — только TFK_epoch и мок TicketMint (02 §3.3, §3.5: «состояния, переживающего
    // ротацию, у узла нет»).
    todo!("Phase 0: 3 потока, N1→N2 по ticket, 0 потерь на обоих каналах, seq continuity (02 §3.3/§3.5/§3.9)")
}

/// **Сценарий 1, re-key-часть (ТЗ): forward secrecy после ротации — старый `K_session` не открывает новые records.**
///
/// Источник: `02 §3.3` (post-rotation re-key), `§3.8` (инвариант «Пост-ротационный трафик читает
/// только новый узел»), `§3.9` (компрометация `K_session` у N1 → трафик до ротации).
///
/// Assert'ы:
/// 1. Записи после ротации зашифрованы ключом ratchet от `K_session'`, а не от старого
///    `K_session` (`§3.3`: «ratchet `K_record` перезапускается от `K_session'`»).
/// 2. N1, знающий только `K_session`, не может вывести `ss_rotate = DH(eph_client_priv,
///    eph_node_pub)`, поэтому `K_session'` ему недоступен (`§3.3`).
/// 3. Попытка открыть пост-ротационную запись старым `K_record`/`K_session` даёт AEAD-отказ
///    (`OpenFailed` из `crypto-core`), а не панику (`§1`: `XChaCha20-Poly1305(K_record, nonce =
///    seq(8B) ‖ sid(16B))`).
/// 4. Подмена `eph_node` (попытка N1 сохранить чтение) отклоняется: `sig_node` обязательна и
///    покрывает `"aether-resume-ack-v3" ‖ sha256(transcript_client) ‖ continuity_point ‖
///    window_lo ‖ window_hi ‖ eph_node` (`§3.3`).
/// 5. Записи, отправленные **до** ротации, старым ключом открываются — проверка, что тест
///    ловит именно ротацию, а не сломанный AEAD (`§3.9`: до ротации трафик у N1 и должен читаться).
#[test]
#[ignore = "контракт Phase 0: тело намеренно todo!() — тест начнёт проходить вместе с реализацией"]
fn rotation_forward_secrecy_old_k_session_cannot_open_new_records() {
    // Крипто здесь — реальное (crypto-core), не мок: смысл проверки в том, что вывод ключа
    // через ss_rotate недоступен владельцу только K_session. Байндинги — моки.
    todo!("Phase 0: K_session' недостижим из K_session без ss_rotate; старый ключ не открывает новые records (02 §3.3/§3.8)")
}

/// **Доп. (`02 §3.6`): потеря `RESUME_ACK` → ретрай с новым nonce, тот же ticket принимается один раз.**
///
/// Источник: `02 §3.6` (ретрай), `§3.7` (таймаут `T_ack`), `§3.8` (make-before-break).
///
/// Assert'ы:
/// 1. ACK не пришёл → срабатывает `T_ack` = 2 × SRTT, клип [200 ms, 2 s]; владелец таймера —
///    FrameSession (`§3.7`, `§4`).
/// 2. Ретрай идёт с **новым `client_nonce` и новым `eph_client`, тем же ticket** (`§3.6`).
/// 3. Ретраев не более двух, затем откат на старый канал (`§3.7`).
/// 4. Узел принимает этот ticket **один раз** (`§3.6`); второй приём того же ticket на том же
///    узле — `RESUME_NAK replay`. Ключ consumed-set — `epoch_id ‖ sha256(ticket_blob)`, то есть
///    replay детектится по ticket, а не по nonce (`§3.6`).
/// 5. `K_session'` выводится от `eph_client` **успешной** попытки (последней, на которую пришёл
///    валидный ACK) (`§3.3`).
/// 6. Сессия не рвётся: старый канал жив до валидного ACK (`§3.8`); вторая сессия не создаётся —
///    глобального exactly-once нет, но at-most-once на узел держится (`§3.5`, `§3.8`).
#[test]
#[ignore = "контракт Phase 0: тело намеренно todo!() — тест начнёт проходить вместе с реализацией"]
fn rotation_retry_after_lost_ack_new_nonce_same_ticket_accepted_once() {
    // Мок байндинга N2 глотает первый RESUME_ACK (имитация потери); второй — доставляется.
    todo!("Phase 0: потеря ACK → T_ack → ретрай с новым nonce/eph, ticket принят один раз (02 §3.6/§3.7)")
}