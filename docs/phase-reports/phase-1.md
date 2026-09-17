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

---

# Phase 1 — кусок 3: Reality/TCP, каркас (2026-09-17)

Граница куска: обложка-каркас + перенос boring в прод. App Mirage, morph-controller,
приёмная сторона, сплайс живого сокета сайта-мишени — **не начинались** (Phase 2/3).
K_session (chaining key, Q10), Clatter, rotation-tests, живой TUN — не тронуты.
SsPaddedBinding/MasqueBinding — не тронуты.

## Что shipped

| Крейт/файл | Что внутри | Тесты |
|---|---|---|
| `cover-reality` (новый) | `RealityBinding: CoverBinding` (каркас) + `encode/decode_reality_frame`, `classify_first_record` (верdict Authenticated/Fallback), `build_client_hello_tls` (boring-коннектор под `TargetSite`), `FallbackReply`, `TargetSite` (SNI параметризован; placeholder — не боевой домен); `DPI_PROFILE_REALITY_TCP = 0x05` (реэкспорт из transport-mux) | 10 + 2 ignored |
| `Cargo.toml` (workspace) | `boring = "4.22.0"` — **первая прод-зависимость boring**, owner `cover-reality`, TTL 180 дней (перепроверка до 2027-03-16) | — |
| `scripts/local-env.sh` | Дополнен boring-блоком: NASM 2.16.03 в PATH, `LIBCLANG_PATH` (PyPI-колесо), `BINDGEN_EXTRA_CLANG_ARGS=-target x86_64-pc-windows-gnu…`, `CMAKE_GENERATOR=Ninja` — раньше это был `boring-probe-env.sh` только для пробы; также фикс: sysroot-путь больше не через внешний `tr` (busybox-tr из w64devkit в PATH ломал `C:\→C:CUsers`) | — |
| `.github/workflows/ci.yml` | rust-job: `apt-get install cmake libclang-dev` — boring-sys теперь собирается в обязательном прогоне (на Linux NASM не нужен — ASM_NASM только для Windows) | — |
| `phase0-path` (тест) | Склейка пакета → сессия → Reality-обёртка → вскрытие | +1 |

Формат кадра: `len(4B BE) ‖ nonce(24B) ‖ XChaCha20-Poly1305(record.encode())`,
AAD — заявленный префикс длины (единственные байты, выводимые принимающим до вскрытия —
иначе round-trip несверяем). Ключ — `derive_cover_key(sid, K_session)`, отдельный слой.

## Механизм active-probe resistance (какой именно реализован)

Различение происходит **внутри TLS-канала**, первым кадром после handshake:
`classify_first_record(cover, site, frame)` проверяет AEAD-тег на `K_cover`.
Неаутентифицированное соединение (валидный ClientHello, но чужой ключ / порча /
мусор вместо аутентификатора) получает `FallbackReply` — снимок ответа сайта-мишени
(в проде из конфига подписки; в тестах — детерминированная заглушка) — а **не** ошибку,
RST или иной маркер, характерный только для Reality. Все причины неаутентичности
схлопываются в один наблюдаемый результат. Один пробный запрос не даёт наблюдателю
способа отличить «Reality-нода» от «просто сайт X».

## Честные границы клейма

- **Не DPI-resistant в смысле живого трафика.** Независимый DPI-инструмент не запускался;
  активные пробы извне не снимались. Проверено: юнит-тесты структуры (layout, auth,
  caps, contract) + пробы линковки/живого handshake boring+rustls на Windows/GNU и
  Linux CI (`reality-boring-probe.md`). Это клейм «механизм реализован и юнит-проверен»,
  не клейм «обход DPI подтверждён» — открытый вопрос в QUESTIONS.md (Q22).
- **Не Reality/VLESS-interop.** Совместимость с xray-core не заявляется и не проверялась;
  xray-core остаётся reference-only.
- Чекбокс верхнего уровня в `05-roadmap` остаётся `[ ]`: закрыт только подпункт
  «каркас реализован».

## Честный caps

`caps()` отдаёт `no_hol: false, datagram: false` — TCP-класс с HOL по построению
(`02 §2.2` tradeoff, не дефект: морф-контроллер использует Reality только при явной
блокировке QUIC-путей и уходит с него при первой возможности). `dpi_profile = 0x05`.
Проверено тестом `caps_stream_class_not_no_hol`.

## Тесты (все зелёные локально на Windows/GNU)

- layout: `len ‖ nonce ‖ AEAD`, энтропия ровно под nonce, воспроизводимость при том же
  nonce, отличие при другом (probabilistic AEAD), AAD-схема;
- roundtrip обёртки; чужой ключ / порча / обрез / враньё в длине / пустой кадр — все
  → один и тот же фолбэк (probe_resistance_all_failures_look_alike);
- аутентифицированный кадр → `Authenticated(record)`;
- boring-коннектор под сайт-мишень собирается (SNI/ALPN/пин; сам cert — RSA-2048,
  построенный boring'ом; sign последним — находка пробы №4);
- контракт байндинга: `TransportDown` + `Closed` ровно один раз, инжектированный
  `Probed` один раз; backpressure — `WouldBlock`, точная арифметика кадра (57 B при
  payload 8);
- caps; SNI параметризован (два сайта → разные фолбэки);
- 2 ignored до живого пира: пассивный пробник получает байт-в-байт ответ сайта-мишени;
  аутентифицированный клиент проходит на Aether-протокол.

**Прогон:** cover-reality 10 passed / 0 failed / 2 ignored; workspace — см. CI-ран
коммита. clippy `--workspace --all-targets -D warnings` — 0 предупреждений.

## Чего кусок не делает (честно)

- **Сети нет**: TLS-канал не разворачивается в рантайме, async-писателя нет; handshake
  проверен только в живой пробе вне репо. Игнор-тесты ждут живого Reality-пира —
  interop-чекбокс не закрывается без реального внешнего пира.
- **Приёмная сторона** (сервер: классификация первого кадра, сплайс фолбэка, проксирование
  аутентифицированного канала) — следующий кусок; `classify_first_record` — только
  механизм различения, не сервер.
- **Fallback-сплайс живого сокета** сайта-мишени: `FallbackReply` сейчас — статический
  снимок; живое перенаправление на реальный сайт — вопрос живого peer-теста.
- **Active-probe от независимого DPI-инструмента** не прогонялся (Q22 в QUESTIONS.md).

---

# Phase 1 — кусок 3b: живой сплайс, peek-before-decrypt (b132-2, 2026-09-17)

Граница куска: архитектурное решение Q22 + механизм гейта/релея. Приёмная сторона
(серверный рантайм: boring-коллбеки, tokio-сплайс, терминировка Accept-пути), живой
peer-тест, DPI-пробы — **не начинались**. Решение по Q23 (сертификат Accept-пути)
принято НЕ молча — зафиксировано открытым напряжением в QUESTIONS.md.

## Архитектурное напряжение и решение (явно, не молча)

**Напряжение (b132):** классификация внутри TLS-канала означала, что сервер терминирует
TLS с пробником ДО решения о фолбэке. В такой модели «живой сплайс» вырождается в
сложный статический снимок — сервер уже знает контент. Настоящий Reality решает иначе.

**Решение (b132-2):** peek-before-decrypt + живой сплайс.
- Слой 1 — гейт `gate_decision` по ОТКРЫТОМУ ClientHello (до любых TLS-ключей).
  Аутентификатор: 24 B HMAC-SHA256 (`crypto_core::probe_tag`, ключ `K_probe` —
  отдельный слой `LABEL_PROBE`) над ClientHello с нулённым местом тега + окно слотов
  времени (анти-replay, диапазон t-1..=t+1, Q21-класс). Носитель тега — TLS-расширение
  `session_ticket` (RFC 5077, opaque-поле): равномерно-случайный вид, неотличим от
  шума и от билетов настоящего клиента сайта — это и есть «что отличает Aether-клиента
  в открытом ClientHello».
- `Relay` → `relay_to_target`: TCP к сайту-мишени, сырые байты в обе стороны без
  интерпретации. Пробник разговаривает с НАСТОЯЩИМ сайтом — настоящий сертификат,
  handshake, данные; сервер ничего не расшифровывает. Источник неотличимости.
- `Reject` (байты не ClientHello) → тихое закрытие — как перегруженный сайт.
- Слой 2 (после Accept): первая запись на `K_cover`; не прошла → тихое закрытие.
- Статический снимок `FallbackReply` удалён. `TargetSite` больше не носит fallback-байтов.

## Что shipped

| Крейт/файл | Что внутри |
|---|---|
| `crypto-core` | `KProbe`, `derive_probe_key` (LABEL_PROBE), `probe_tag` (HMAC-SHA256, окно в теге), Debug-redacted; hmac 0.13 — новый workspace-пин (DEPENDENCIES.md, TTL 180 дней) |
| `cover-reality` | `gate_decision` (Accept/Relay/Reject), `client_authenticator` (клиентская сторона гейта), `gate_slot`, `RelaySpec`, `RelayOutcome`, `relay_to_target` (raw TCP-сплайс, fail-safe), `FirstRecordVerdict::Rejected` (тихое закрытие после гейта), рефактор `TargetSite` |
| тесты | 2 юнита гейта (валидный тег в окне → Accept; чужой ключ/нет тега → Relay; не-CH → Reject; тег покрывает все байты CH), 1 юнит crypto-core (HMAC-контракт, домен ≠ LABEL_COVER); 2 ignored (loopback-сплайс, живой peer) |

## Чего кусок не делает (честно)

- **Серверного рантайма нет**: `gate_decision` — чистая функция; привязка к сокетам
  (boring-коллбек на `session_ticket`, вырезание тега из CH, tokio-версия сплайса) —
  приёмная сторона. Синхронный сплайс в `relay_to_target` — контрактный каркас
  (проверяемый юнитами/loopback), не прод-икв.
- **Q23 открыт** (см. QUESTIONS.md): каким сертификатом сервер отвечает на Accept-пути.
  Настоящий Reality крадёт/ретранслирует handshake сайта-мишени; альтернативы — свой
  домен или ECH. Решение — за архитектурным ревью, ДО приёмной стороны.
- **Никаких живых проверок DPI**: юниты + loopback-ignored. Interop-чекбокс `[ ]`.

---

# Phase 1 — кусок 4: MASQUE live interop, собственный h3-клиент (2026-09-18)

Граница куска: клиентская сторона RFC 9298 + двусторонний лабораторный прогон.
Прод-приёмник (узел с UDP-проксированием), no-HOL клейм, morph — не начинались.
Reality, SsPaddedBinding, K_session, rotation-tests — не тронуты.

## Что shipped

| Крейт/файл | Что внутри | Тесты |
|---|---|---|
| `cover-masque::h3_live` (новый модуль) | `MasqueH3Client::connect_udp` (h3-сессия → Extended CONNECT-UDP → 2xx → датаграммы), `drain_binding` (вычерпывание `Outbox` каркаса в HTTP/3 DATAGRAM), `split` (драйвер ↔ `DatagramHalf` с send+read), `drive_until_closed`, `caps` (datagram: true, no_hol: false), `MasqueH3Error` (4 ветки без слияния) | 3 |
| `e2e-harness::masque_lab` (новый модуль, фича `e2e`) | живой h3 CONNECT-UDP эхо-сервер (`h3::server` + h3-datagram) и двусторонний тест: прод-`MasqueBinding` + прод-`MasqueH3Client` ↔ сервер, 3 капсулы туда-обратно через реальный quinn | 1 |
| `quic_lab` (фикс) | лабораторные сертификаты: цепочка CA→leaf вместо CA-как-leaf (латентный дефект, найден живым handshake — см. ниже); `LabCert.ca_cert_der`, сервер отдаёт цепочку, клиенты пинят CA | +1 проверка цепочки |
| `Cargo.toml` / `DEPENDENCIES.md` | `h3-quinn 0.0.10[datagram]`, `h3-datagram 0.0.2`, `http 1`, `bytes 1` — workspace-пины; таблица фактов спайка с исходниками (h3-datagram Quarter Stream ID, `SendRequest::Drop`, драйвер-`poll_close`); TTL 180 дней | — |

## Почему caps живут отдельно от каркаса (честность клейма)

Каркас (кусок 2) отдаёт `no_hol: false, datagram: false`; live-слой — `no_hol: false,
datagram: true`. Оба честные: каркас пишет капсулы в очередь (stream-класс), live-слой
шлёт их QUIC DATAGRAM'ами (unreliable), но no-HOL-клейм требует приёмника, который
проксирует UDP без ожидания порядка — его ещё нет, клейм не заявляется. При интеграции
FSM морфа выбор байндинга идёт по `caps` живого объекта: каркас больше не «врёт»,
live-слой не «хвастает».

## Находки живого прогона (не по документации — по падениям)

1. **`SendRequest::Drop` закрывает h3-соединение** (h3 0.0.8, client/connection.rs:250:
   «Connection closed by client», H3_NO_ERROR): `connect_udp`, отдавая сессию без
   handle'а, ронял соединение сразу после возврата. Фикс: handle живёт в клиенте/
   половине сессии. Это контракт API, который нельзя увидеть без сети — зафиксирован
   тестом и в DEPENDENCIES.md.
2. **Драйвер — не Future**: клиентское соединение требует ручного `poll_close`
   (двигает контрольные стримы, читает SETTINGS пира). В лаборатории — `tokio::spawn
   (drive_until_closed)`; прод-интеграция будет держать драйвер рядом с обменом.
3. **Латентный дефект лабораторных сертификатов**: `self_signed_cert()` строил
   `CA:true`-сертификат и отдавал его же в роль leaf — webpki на реальном handshake
   отвергает (`CaUsedAsEndEntity`, error 46). Старые тесты этого не видели: они не
   делали handshake с верификацией. Тот же класс находки, что в boring-пробе
   (находка №3); фикс — цепочка CA→leaf, клиенты пинят CA, сервер отдаёт цепочку.
   Ручной e2e-прогон ротации (`scripts/e2e-manual.sh`) перегнан на новой цепочке —
   зелёный (K_session/re-key хеши сторон совпали, seq 0..9 без дубликатов).
4. **HTTP Datagrams в h3 нет** — факт спайка до кода: SETTINGS-флаги есть, API нет;
   их даёт `h3-datagram` (см. таблицу фактов в DEPENDENCIES.md). Клейм «RFC 9297»
   остался бы AIR без этой пары.

## Тесты (все зелёные локально, Windows/GNU, rustc 1.98.1)

- `cover-masque`: 14 passed (11 каркас + 3 live: extended-CONNECT-запрос несёт
  `capsule-protocol: ?1`, псевдо-поля не дублируются в обычные заголовки, форма caps);
- `e2e-harness --all-features`: 17 passed, включая живой двусторонний
  `masque_rfc9298_live_roundtrip` (реальный quinn + h3 + датаграммы, байт в байт);
- workspace `cargo test --all-targets`: **102 passed / 0 failed / 2 ignored**;
- clippy `-D warnings` по workspace и по e2e-фиче — чисто.

## Чего кусок не делает (честно)

- **Прод-приёмника нет**: сервер лаборатории — эхо, не UDP-прокси; интеграция с
  frame-зеркалом узла, пулом сокетов и policy — следующий кусок. Interop с внешним
  MASQUE-пиром (masque-go) не гонялся — чекбокс переформулирован: интероп-пара
  наш собственный клиент ↔ наш сервер по RFC, внешние пивы — отдельно.
- **no-HOL не заявляется**: `caps.no_hol = false` до приёмной стороны с
  UDP-проксированием (см. выше).
- **CI не гоняет live-тест по сети** (как и раньше): UDP-loopback в rust-job не
  запускается, прогон живёт в фиче `e2e` (локально/по запросу) — CI собирает и
  линтит его, не исполняет.
