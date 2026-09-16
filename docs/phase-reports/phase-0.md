# Phase 0 — отчёт о реализации (`impl-phase-driver`, 2026-09-16)

Прогон по `design/05-roadmap.md` → Phase 0, порядок модулей задан ТЗ прогона:
`crypto-core` → `frame-session` → `ticket-mint` → `key-coordinator` → `transport-mux`
(только QUIC) → `session-store` → снятие `#[ignore]` с реализованных тестов →
`crates/rotation-tests` (сценарии 1–6 + морф).

**Статус: реализовано и проверено на CI; Exit Phase 0 ещё не достигнут** — две причины,
обе вынесены в `QUESTIONS.md` (BLOCKER + остатки), а не «дописаны в доке»:

1. **Буфер фолбэка (≤ 16 МБ или ≤ 5 с) не реализован.** В `03-components.md` такого типа нет;
   в Phase 0 его нет и в коде. Сценарий 6b и «узел упал между RESUME и ACK» проверяются
   в той части, которая существует (сессия жива, дубли окна, `MorphFailed` → откат), а
   бюджет буфера — BLOCKER: нужен выбор дизайна, где буфер живёт.
2. **`device-adapter` (Linux TUN) и `policy-engine` — всё ещё заглушки скаффолда**,
   их контрактные тесты остались под `#[ignore]`: они не входят в путь ротации и в порядок
   этого прогона.

## Что shipped

| Модуль | Что реализовано | Тесты |
|---|---|---|
| `crypto-core` | гибридный `noise_hybrid_ik` (clatter 2.3.0, PQClean-бэкенд), `K_session`/`K_resume`/re-key/ratchet, `XChaCha20-Poly1305` seal/open, Ed25519/X25519 примитивы | 3 (KAT+interop ML-KEM-768, IK 1 RTT с замером, seal/open) |
| `frame-session` | layout `type‖seq‖stream_id‖flags‖len‖ct` с AAD-заголовком, nonce `seq‖sid`, цепочка `K_record[n]`, окно дедупа 4096 (bitmap 512 B), окно морфа `T_morph`/`N ≤ 4096`, `on_resume_ack`/`on_resume_nak` | 4 |
| `ticket-mint` | mint (AEAD тикета, 161 B), `unwrap` с эпохой/`exp`, PoP по `client_auth_pub` + привязка к `sha256(ticket_blob)`, consumed-set эпохи, вердикты `Accept`/`bad_pop`/`replay`/`epoch`/`expired` | 3 |
| `key-coordinator` | `request_ticket` (mint у узла), `RESUME` с PoP-подписью и свежим `eph_client`, проверка `sig_node`, `post_rotation_rekey` через `DH(eph_client, eph_node)`, потолок попыток | 4 |
| `transport-mux` | QUIC-байндинг (quinn) с caps no-HOL/datagram, кадрирование `len(4B)‖record`, ограниченная очередь (backpressure → `WouldBlock`), оба отказных пути (`BindingError`, `BindingFailure`), `MemBinding` как мок для тестов | 4 |
| `session-store` | владелец `client_identity`/`client_static` priv, at-rest через трейт `SecureStore` (in-memory backend в Phase 0), tickets только in-memory, дескриптор сессии, `Corrupt` на неполный набор секретов | 3 |
| `rotation-tests` | harness (адаптер `crypto-core` → `frame-session`, мок узла поверх `ticket-mint`, мок сети с потерей ACK/недоступностью, драйвер ротации с окном перекрытия) + 11 сценариев: happy path, forward secrecy, потеря ACK/ретрай, `epoch`, украденный ticket, replay, битые подписи, гонка двух ACK, падение узла, потеря на одном канале, потеря на обоих, морф QUIC→mock-Reality | 11 (сняты `#[ignore]`) |

`morph-controller`, Reality, MASQUE, App Mirage не создавались — по ТЗ прогона.

## Команды тестов

```bash
cargo test --workspace --all-targets      # 32 теста: 21 юнит + 11 интеграционных
cargo clippy --workspace --all-targets -- -D warnings
python scripts/validate_skills.py         # 7 skill(s), 0 error(s), 0 warning(s)
```

Остались под `#[ignore]` (см. BLOCKER выше): `policy-engine` (2), `device-adapter` (2).

## Главное, что дал прогон

- **Главный риск проекта проверен на frame-слое:** ротация N1 → N2 по ticket не теряет
  ни одной записи на обоих каналах, `continuity_point` монотонен и совпадает с границей
  дублированного окна, старый узел не читает пост-ротационный трафик (свежий DH),
  дубли укладываются в `T_morph = 2 × SRTT` и `N ≤ 4096`.
- **PoP — не декларация:** узел принимает `RESUME` только с подписью по `client_auth_pub`
  из ticket; украденный ticket без приватного `client_identity` получает `bad_pop` и
  **не консумируется** (легитимный клиент после этой попытки резюмируется тем же билетом).
- **Consumed-set — на узле, не на флоте:** два разных узла одной эпохи действительно
  принимают один ticket (гонка возможна), обоих ACK валидны, применяется ровно один —
  то есть «крана» решается не валидностью, а порядком (как и записано в `02 §3.6`).

## Отклонения от `design/` (все — записью в `QUESTIONS.md`, спека не правилась)

| # | Что | Где |
|---|---|---|
| Q9 | `seq` добавлен в заголовок записи: без него дедуп по `(sid, seq)` невозможен | `02 §1` |
| Q10 | `K_session` выводится из handshake-hash, а не из конкатенации секретов: clatter их не отдаёт | `02 §5` |
| Q11 | `Handshake::initiate` не может возвращать `K_session` в IK до `msg2` | интерфейс |
| Q12 | `noise_hybrid_ik` **есть**, но msg1/msg2 = 3568/3424 B против 1264/1136 в `§5` (2.9×) | `02 §5` |
| Q14 | предел итераций цепочки (2²⁰) — наша защита, спека его не задаёт | `02 §1` |
| Q15 | AAD записи (заголовок без `len`) спека не задаёт | `02 §1` |
| Q16 | пины `hkdf`/`sha2`, фича `getrandom` у `ml-kem` | `DEPENDENCIES.md` |
| Q17 | `Continuity` в `key-coordinator` не несёт `sig_node`, поэтому frame-слой не может применить ACK без повторного разбора ответа | `03`, «Контракты» |
| Q18 | `MAX_RESUME_RETRIES = 2` даёт **одну** повторную попытку, а `§3.7` говорит «не более двух ретраев»: реализация строже спеки | `02 §3.7` |
| Q19 | Nonce `RESUME`/`RESUME_ACK` спека не задаёт вовсе; взят `client_nonce ‖ метка направления`, nonce стоит в открытом виде (иначе он оказался бы внутри того, что им же вскрывается) | `02 §3.3` |

## Чего прогон не проверил (честно)

- **Сеть.** quinn-байндинг компилируется и проверен на caps/отказных путях/кадрировании,
  но **не гонялся по сокету**: в CI нет runtime и нет пира. Async-писатель
  (`take_pending()` → `SendStream` по `stream_id`) — Phase 0.5.
- **OS secure store.** Реализован трейт `SecureStore` и эталонный in-memory backend;
  keyring/DPAPI/Keychain/libsecret — Phase 1 (`zeroize` — там же).
- **Payload-соединения.** Как и записано в `05-roadmap`: тест меряет frame-слой; разрыв
  прикладных TCP/QUIC сменой egress IP — ожидаемый эффект Phase 0, не регресс.
- **Метод проверки.** В среде агента нет Rust-тулчейна: каждый модуль принимался по
  зелёному прогону CI (`cargo test --workspace --all-targets` + `clippy -D warnings`).
  Прогоны `d04d206` (первый зелёный) и `95bcce4` (после интеграционных тестов) — в Actions.
