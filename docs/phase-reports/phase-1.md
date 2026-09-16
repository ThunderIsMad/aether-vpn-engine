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

---

# Phase 1 — кусок 2: MASQUE CONNECT-UDP, каркас (2026-09-16)

Граница куска: формат капсул + байндинг-каркас. h3-сессия, RFC 9220 Extended CONNECT по сети,
SETTINGS_H3_DATAGRAM, приёмная сторона, Reality, App Mirage, morph — **не начинались**.
SsPaddedBinding, K_session, Clatter, rotation-tests, живой TUN — не тронуты. Новых внешних
зависимостей нет: `quinn`/`h3` остаются workspace-пинами, в Cargo.toml крейта их нет;
`masque-go`/`quic-go` — reference-only (DEPENDENCIES.md), не зависимости.

## Что shipped

| Крейт | Что внутри | Тесты |
|---|---|---|
| `cover-masque` (новый) | `MasqueBinding: CoverBinding` (каркас) + `encode/decode_datagram_capsule`, `encode/decode_udp_proxying_payload`, `encode/decode_varint` (с 2⁶²−1 гардом), `ConnectUdpRequest` (описание запроса + заголовки); `DPI_PROFILE_MASQUE = 0x03` (реэкспорт из transport-mux) | 11 |
| `phase0-path` (тест) | Склейка: мок-пакет → `Engine` → `FrameSession::seal_record` → **`MasqueBinding`** → вскрытие капсулы → зеркало сессии → исходные байты | +1 |

Формат кадра байндинга: DATAGRAM-капсула `type(0x00) ‖ len(varint) ‖ value` (RFC 9297 §4),
внутри — UDP Proxying payload `Context ID(0) ‖ record.encode()` (RFC 9298 §5, лимит 65527).
Обложка не шифрует второй раз: в капсулу кладётся уже sealed record.

## Честное имя: каркас, не RFC-клиент

Реализовано и проверено в CI — только то, что проверяемо без сети: форматы (капсула, payload,
varint по примерам RFC 9000 §16, включая 4- и 8-байтовые кодировки), форма запроса Extended
CONNECT (`:method = CONNECT`, `:protocol = connect-udp`, непустые scheme/path/authority,
порт 1..=65535, RFC 9298 §3.4/Figure 5). Не реализовано: HTTP/3-сессия, exchange
SETTINGS_H3_DATAGRAM, чтение ответа узла, приёмная сторона. В CI нет ни сети, ни рантайма —
капсула сегодня это кадр в `Outbox`, а не QUIC DATAGRAM frame. Поэтому в `05-roadmap`
чекбокс «RFC 9298 interop» остаётся `[ ]`, а строка Phase 1 отмечена `[x]` только как
«каркас» — с явно выделенным интероп-остатком.

## Честный caps

`caps()` отдаёт `no_hol: false, datagram: false` — записи едут через упорядоченный `Outbox`,
никакой мультиплексации QUIC streams нет; no-HOL/datagram заявятся только реальным h3-клиентом
(`02 §2.3`). Проверено тестом `caps_skeleton_not_rfc_client`.

## Тесты (все зелёные в CI `ca6c3a5`)

- varint: примеры RFC 9000 §16 байт в байт (0/1/63/15293/494878333/151288809941952654),
  минимальность кодировки, обрезанные входы → `None`, roundtrip 2⁶²−1, маскирование
  старших битов у 8-байтовых (маркер длины — не значение);
- roundtrip капсулы: запись пакуется и вскрывается байт в байт; layout-тест: тип `0x00`,
  len(varint), Context ID 0 перед payload;
- битые кадры без паник: пустой/обрезанный заголовок, `len` ≠ телу, чужой capsule type,
  Context ID ≠ 0, payload > 65527, корректная капсула с не-записью внутри → `BadRecord`;
- граница лимита: 65527 проходит, 65528 — `PayloadTooLong`; `send` записи с payload > 65527 —
  синхронный `BindingError::Unsupported` (RFC 9298 §5 «MUST NOT send»), в очередь не попадает;
- запрос Extended CONNECT: заголовки по Figure 5, пять malformed-вариантов отвергаются
  (`MalformedRequest`);
- caps stream-класса; отказные пути (`TransportDown` + `Closed` ровно один раз, инжектированный
  `Probed`); очередь: порядок сохранён, переполнение — `WouldBlock`;
- интеграция `phase0-path`: policy → frame-session → MASQUE-капсула → вскрытие → исходный пакет.

**Прогон:** 62 passed / 0 failed / 0 ignored по workspace (было 50, +11 cover-masque,
+1 phase0-path), clippy `-D warnings` — 0 предупреждений (CI `ca6c3a5`). Один красный CI
до зелёного: транскрипция последнего байта 8-байтового varint-примера в тесте
(`0x8C` вместо `0x8E`, RFC 9000 §16) — ошибка ожидания, не кодировщика; по логу rust-job.

## Чего кусок не делает (честно)

- **RFC 9298 interop** — `[ ]`: живой CONNECT-UDP к пиру, собственный h3-клиент на quinn,
  приёмная сторона — следующий шаг Phase 1; `masque-go`/`h3-masque` — reference-only
  (не зависимости, `DEPENDENCIES.md`).
- **caps no_hol/datagram** — до h3-клиента не заявляются.
- Выбор URI Template и его валидация по §2 (level 3, ASCII, без Reserved Expansion) —
  дело h3-клиента; `ConnectUdpRequest` сегодня принимает готовый `:path`.
