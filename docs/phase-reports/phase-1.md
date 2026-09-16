# Phase 1 — кусок 1: padded cover binding (2026-09-16)

Граница куска: только обложка. MASQUE, Reality, App Mirage, morph-controller, живой TUN
ioctl, буфер 16 МБ — **не начинались**. K_session (chaining key, Q10), Clatter, размеры
handshake, rotation-tests сценарии 1–6 — не тронуты.

## Что shipped

| Крейт | Что внутри | Тесты |
|---|---|---|
| `cover-ss2022` (новый) | `SsPaddedBinding: CoverBinding` + `encode_cover_frame`/`decode_cover_frame`; `DPI_PROFILE_SS_PADDED = 0x04`; ограниченная `Outbox` — backpressure как у остальных байндингов | 6 |
| `crypto-core` (дополнение) | `LABEL_COVER`, `KCover`, `derive_cover_key(sid, K_session)`, публичный `hkdf_sha256`. Ключ обложки — отдельный слой: компрометация обложки не вскрывает `K_record`/`K_resume` | без новых тестов (проверяется через cover-ss2022) |
| `phase0-path` (тест) | Склейка: мок-пакет → `Engine` → `FrameSession::seal_record` → **`SsPaddedBinding`** (не `MemBinding`) → `decode_cover_frame` → зеркало сессии вскрывает исходные байты | +1 |

Формат кадра: `len(4B BE) ‖ nonce(24B) ‖ XChaCha20-Poly1305(record.encode() ‖ pad)`,
AAD — префикс длины. Паддинг — внутри шифротекста (длина скрыта, кадр аутентифицирован
целиком), бюджет `N` байт на record включается `with_padding(N)`; `seq` записи не меняется —
duplicate-окно `(sid, seq)` узла не затронуто (проверено тестом).

## Честное имя: почему не «SS-2022 interop»

Внешних тест-векторов shadowsocks-2022 (wire-поля, salt/derivation, EigenState) у проекта
нет — по правилу ТЗ клейм не выдаётся: тип называется **`SsPaddedBinding`**, формат —
«Aether padded cover», в `03` §4 и `05-roadmap` это зафиксировано. Чекбокс interop остался
`[ ]` до появления векторов (отдельная запись леджера `crate-feasibility`).

## Честный caps

`caps()` отдаёт `no_hol: false, datagram: false` — кадры едут через упорядоченный канал
stream-класса, застрявший кадр блокирует последующие (тот же tradeoff, что Reality/TCP,
`02 §2.2`), даже если физический канал когда-нибудь будет UDP-подобным. Проверено
отдельным тестом `caps_stream_class_not_no_hol`.

## Тесты (все зелёные в CI `8d976d9`)

- roundtrip encode/decode своего кадра (budget 0/16/1024), чужой ключ → `OpenFailed`;
- padding-границы: при budget=0 ровно минимум (`len+nonce+record.encode()+tag`), при
  budget=200 длина ∈ [min, min+200], паддинг реально применялся, `seq` не тронут;
- битые кадры: обрезанный заголовок/несовпадение `len` → `BadLength`, порча шифротекста
  → `OpenFailed` (без паник);
- отказные пути: закрытый канал → синхронный `TransportDown` + асинхронный `Closed` ровно
  один раз; инжектированный `Probed` доходит до FSM; `WouldBlock` при переполнении очереди;
- caps stream-класса;
- интеграция `phase0-path`: policy → frame-session → cover-кадр → вскрытие → исходный пакет.

**Прогон:** 50 passed / 0 failed / 0 ignored по workspace (было 41, +6 cover-ss2022,
+1 phase0-path, +2 ранее), clippy `-D warnings` — 0 предупреждений.

## Что прогон вскрыл

- Минимум длины кадра в тесте был посчитан руками (108) и не включал 5 байт заголовка
  записи; факт — 113. Ожидание переписано от `record.encode().len()` — тест больше не
  завязан на varint-длины.
- Три красных CI до зелёного: unused import, unqualified константа в тесте,
  clippy `unnecessary_cast`. Все — по логам rust-job, не локально (тулчейна в среде нет).

## Чего кусок не делает (честно)

- **Сети нет**: байндинг пишет cover-кадры в очередь (`Outbox`), async-писатель в реальный
  сокет — следующий шаг Phase 1 (там же принимающая сторона).
- **SS-2022 interop** — `[ ]`, см. выше.
- Padding-политика (какой бюджет выбирать, когда повышать/снижать) — решение
  morph-controller (Phase 2), здесь только механизм с флагом.
