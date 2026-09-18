# DEPENDENCIES — feasibility прогон (первый, реальный)

**Дата прогона:** 2026-09-16 · **Скилл:** `crate-feasibility` · **Источник:** `design/03-components.md` (v2)
**Леджер:** `.agents/skills/crate-feasibility/SKILL.md`, факты F1–F13 (сегодня подтверждены, F5 опровергнут)

Проверка шла против crates.io / docs.rs / GitHub issues, а не «по названиям». Ниже —
что подтвердилось, что опровергнуто и где заявленная альтернатива не является drop-in.

## Что меняет дизайн

1. **F5 опровергнут: rustls умеет клиентский ECH.** `rustls::client::EchConfig` существует,
   есть пример `ech-client.rs`; объявлено experimental с 06.2024, серверный ECH — открытый
   issue #1980. Верна только половина про quinn: quinn ECH-путь не выставляет.
   **Вывод дизайна сохраняется** (ECH остаётся в Phase 4), но обоснование другое: не «rustls
   не поддерживает», а «сквозной ECH через quinn недоступен, серверная половина не готова».
   Формулировку в `03-components.md` и CHANGES-audit п. 8 стоит обновить — иначе она читается
   как устаревший факт.
2. **«noise-protocol + ml-kem» — не композиция, а форк.** В `noise-protocol` трейты только
   `DH`, `Cipher`, `Hash`; токенов `ekem`/`skem` нет вообще. Запасной путь из дизайна
   требует расширения паттерн-языка, а не соединения двух крейтов. Оценку «либо clatter,
   либо noise-protocol+ml-kem» надо переписать как «clatter, либо форк noise-protocol».
3. **BBR в quinn хуже, чем заявлено.** Не просто experimental, а «highly experimental and
   not currently maintained… substantially behind the upstream BBR» (issue #2156). Perf-фичу
   нельзя держать даже в отложенных клеймах.
4. **Клейм «uTLS-эквивалента в Rust нет» частично опровергнут.** Есть `impersonate-rs`
   (01.2026, HTTP-уровень) и профили JA3/JA4. Но TLS-слойного uTLS-эквивалента
   (программируемый ClientHello) действительно нет — `boring` даёт контроль, но это
   BoringSSL-биндинги, а не uTLS. Вывод «Reality — самый дорогой cover» держится; причина
   уточняется.
5. **Решение «свой MASQUE-клиент ~1–2k LOC» подтверждено фактом:** готового quinn-based
   клиента RFC 9298 нет — единственный готовый (`h3-masque`) построен на MsQuic.

## Таблица

| dependency | claimed feature | actual status | drop-in alternative | effort if none | проверен | TTL |
|---|---|---|---|---|---|---|
| `quinn` | QUIC-транспорт, ядро | **EXISTS**, дефолт CC — cubic | — | — | 2026-09-16 | 90 дней |
| `quinn` BBR | perf-фича «BBRv3» → «BBR» | **EXPERIMENTAL + не сопровождается**, отстаёт от upstream BBR (issue #2156) | нет; снять из клеймов, cubic + замер в Phase 0.5 | 0 (фича не нужна MVP) | 2026-09-16 | 90 дней |
| `quinn` resumption / 0-RTT / migration | восстановление сессии, миграция | **не проверено** — отложено в Phase 0.5 самим дизайном | — | спайк 1–2 дня (уже в roadmap) | 2026-09-16 | 90 дней |
| `h3` | HTTP/3 для MASQUE CONNECT-UDP | **EXISTS** | — | — | 2026-09-16 | 180 дней |
| CONNECT-UDP клиент | «свой на quinn+h3, ~1–2k LOC» | готового quinn-based нет; `h3-masque` — на MsQuic | свой клиент (как и планировалось) | ~1–2k LOC (оценка вперёд не проверяема) | 2026-09-16 | 180 дней |
| `clatter` | PQNoise с ML-KEM-768 | **EXISTS**, поддерживает MLKEM512/768/1024 + HQC. Оговорки: без формального аудита; собственное именование PQ-примитивов → interop не гарантирован; нет SEEC; опущены pattern parsing, Curve448, deferred/fallback patterns, PSK validity rule | — | принять + свои interop-тесты против эталона | 2026-09-16 | 180 дней |
| `noise-protocol` | база для NoisePQC++ | **EXISTS, но DH-only** — трейты DH/Cipher/Hash, KEM-токенов нет | — | форк: расширение паттерн-языка и KEM-трейт | 2026-09-16 | 180 дней |
| `ml-kem` (RustCrypto) | ML-KEM-768 | **EXISTS**, FIPS 203 | `kyberlib` (аудит против KyberSlash) | — | 2026-09-16 | 180 дней |
| `snow` | отвергнут дизайном | **CONFIRMED отвергнут**: только Kyber1024 round-3, закрытый `KemChoice` enum | `clatter` | — | 2026-09-16 | 180 дней |
| `chacha20poly1305`, `x25519-dalek` | AEAD + DH | EXISTS (стандарт RustCrypto); **в этом прогоне детально не перепроверялись** | — | пиннинг версий в Phase 0 | не проверялось | задать в Phase 0 |
| `boring` | Reality-обложка, контроль ClientHello | **ПРОД-ЗАВИСИМОСТЬ с b132** (`cover-reality`), версия пина 4.22 (4.x stable; 5.0.0-alpha.1 не берём). Риск двух libcrypto в одном дереве (конфликт символов с rustls/ring) снят пробами на обеих платформах: линковка чистая, живой TLS-handshake обоих стеков в одном процессе без ошибок (`docs/phase-reports/reality-boring-probe.md`, шаги 1–6, Linux CI run 35224800408) | xray-core как Go-sidecar (запасной путь, не реализовался) | — | 2026-09-16 (аудит) / 2026-09-17 (прод) | 180 дней |
| `xray-core` | reference для Reality | EXISTS, **не зависимость** | — | — | 2026-09-16 | ∞ |
| `masque-go`, `quic-go` | reference-only | **CONFIRMED**: Go; `masque-go` реализует RFC 9298 | — | — | 2026-09-16 | ∞ |
| `ort` | ONNX Runtime для классификатора | **EXISTS**, но 2.0 — release candidate (2.0.0-rc.13); multiversioning ONNX Runtime 1.17–1.24 | TFLite | — | 2026-09-16 | 90 дней |
| TFLite | альтернатива для on-device ML | **не проверялось** в этом прогоне | `ort` | — | — | задать в Phase 2 |
| keyring / DPAPI / Keychain / libsecret | секьюрное хранилище | **не проверялось** в этом прогоне | — | — | — | задать в Phase 0 |
| «uTLS-эквивалента в Rust нет» | обоснование цены Reality | **ЧАСТИЧНО ОПРОВЕРГНУТО**: `impersonate-rs` (01.2026, HTTP-уровень), профили JA3/JA4; TLS-слойного эквивалента нет | — | уточнить формулировку в `03-components.md` | 2026-09-16 | 90 дней |

## RESEARCH-GRADE

Ни одна строка не получила статус RESEARCH-GRADE в этом прогоне: у всех либо EXISTS, либо
есть drop-in, либо дизайн уже сам вынес вопрос в спайк. Ближе всего к этому порогу
`noise-protocol` как замена clatter — там нет готового пути, только форк.

## До Phase 0

1. `MorphController`/`Classifier` на `ort` держать на 2.0-rc с планом отката на 1.x —
   rc-версия в крипто-ядре недопустима, но классификатор к ядру не относится.
2. ~~Перед добавлением `boring` проверить сборку рядом с rustls~~ **ВЫПОЛНЕНО**
   (2026-09-17): конфликт символов libcrypto не материализовался — пробы линковки и живого
   handshake на Windows/GNU + Linux CI (`reality-boring-probe.md`); `boring` 4.22 добавлен
   прод-зависимостью (`cover-reality`).
3. Пункты 1–3 из «Что меняет дизайн» — это правки текста `03-components.md`, а не кода.

## Что не проверялось

`chacha20poly1305`, `x25519-dalek`, `keyring`/DPAPI/Keychain/libsecret, TFLite. Они не несут
специфичных для дизайна клеймов (кроме выбора хранилища), поэтому версии фиксируются на
скаффолде, а не здесь. В леджере их нет — фактов о них я не заводил.

---

## Phase 0.5 — спайк стека (2026-09-16)

Фичи, проверенные по docs.rs и исходникам тегов (не по памяти). Итоговая таблица с действиями —
`docs/phase-reports/phase-0.5.md`.

| Фича | Статус | Источник |
|---|---|---|
| `clatter::handshakepattern::noise_hybrid_ik()` | **ЕСТЬ**: `-> Skem, E, ES, S, SS / <- Ekem, Skem, E, EE, SE`; в msg2 `Skem` — инкапсуляция к **статическому** KEM-ключу узла | исходник `handshakepattern.rs` (jmlepisto/clatter), Phase 0 Q12 |
| KEM-бэкенд clatter | **ОДИН** — `use-pqclean-ml-kem`; `use-rust-crypto-ml-kem` не тянется ни в одном крейте (транзитивный `ml-kem 0.2.1` не собирается) | Q8; набор зафиксирован в `Cargo.toml` |
| quinn TLS session resumption | **ЕСТЬ** (rustls session storage в `ClientConfig`, автовозобновление при повторном подключении к тому же server name) | docs quinn 0.11.12 (`Connecting::into_0rtt` — «attempts to resume a previous TLS session») |
| quinn 0-RTT early data | **ЕСТЬ**: `Connecting::into_0rtt() -> Result<(Connection, ZeroRttAccepted), Self>`; replay-оговорка библиотеки «vulnerable to replay attacks… never invoke non-idempotent operations» | docs quinn 0.11.12, `Connecting` |
| quinn connection migration | **ЧАСТИЧНО**: серверная — есть, `ServerConfig::migration` default `true` (NAT-rebinding + смена адреса клиента, `migrate()` в `quinn-proto/src/connection/mod.rs`); активная клиентская миграция публичным API 0.11.12 не предоставляется — только `Endpoint::rebind()` (весь endpoint, не соединение) | исходник тега quinn-0.11.12 (`config/mod.rs:244`, `connection/mod.rs:3066`) |
| quinn BBR | **ЭКСПЕРИМЕНТАЛЬНО и не сопровождается**: `congestion::Bbr` — «Experimental! Use at your own risk»; дефолт — `Cubic` | docs quinn 0.11.12 `congestion` |
| Outer PQ (`__rustls-post-quantum-test` / `rustls/prefer-post-quantum`) | **НЕ ВКЛЮЧАТЬ**: тестовая `__`-фича (гейтит только один тест, требует `rustls-aws-lc-rs`); наружу как транспортная фича не выставляется — outer остаётся классический TLS 1.3 | `quinn/Cargo.toml:52` тега quinn-0.11.12; Q7 закрыт |

---

## Phase 0 pins (2026-09-16 · TTL 90d → перепроверка до 2026-12-15)

Версии сняты с crates.io (`max_stable_version`) в день скаффолда. Это **отдельная проверка**,
чем прогон выше: там выяснялось, годится ли крейт для дизайна, здесь фиксируется резолв.
Команда перепроверки для любой строки:

```bash
curl -s https://crates.io/api/v1/crates/<name> \
  | python -c "import json,sys; print(json.load(sys.stdin)['crate']['max_stable_version'])"
```

| Крейт | Версия | Опубликована | Где используется | Заметка |
|---|---|---|---|---|
| `quinn` | 0.11.12 | 2026-09-14 | `transport-mux` (QUIC-байндинг) | версии два дня от роду: если CI красный, первым делом смотреть её, а не наш код |
| `clatter` | 2.3.0 | 2026-08-30 | `crypto-core` (Noise_IK) | default features тянут **и** `use-pqclean-ml-kem`, **и** `use-rust-crypto-ml-kem`; выбор набора — решение Phase 0.5 |
| `ml-kem` | 0.3.2 | 2026-05-10 | `crypto-core` (KAT FIPS 203) | RustCrypto; в clatter то же самое может прийти транзитивно — версию сверить в `Cargo.lock` |
| `chacha20poly1305` | 0.11.0 | 2026-08-05 | `crypto-core` (XChaCha20-Poly1305) | |
| `x25519-dalek` | 3.0.0 | 2026-07-06 | `crypto-core` (статики, DH) | мажор 3.0; clatter может по-прежнему звать 2.x — две копии в дереве допустимы, но это надо увидеть в `Cargo.lock` |
| `ed25519-dalek` | 3.0.0 | 2026-07-06 | `crypto-core` (PoP `sig_client`, `sig_node`) | мажор 3.0 |
| `h3` | 0.0.8 | 2025-05-06 | Phase 1 (MASQUE CONNECT-UDP) | pre-1.0; в Phase 0 не используется, только запинена. Кусок 2 (2026-09-16): каркас `cover-masque` форматы капсул реализовал без h3 — пин остаётся на будущее (h3-клиент), новая мажорная версия не тянулась |
| `h3-quinn` | 0.0.10 | 2026-09-18 | `cover-masque` (live-слой MASQUE), `e2e-harness` (сервер) | фича `datagram` тянет `h3-datagram`; quinn-требование 0.11.7 (default-features=false) совместимо с пином 0.11.12 — в `Cargo.lock` одна копия quinn |
| `h3-datagram` | 0.0.2 | 2026-09-18 | `cover-masque` (live-слой MASQUE) | RFC 9297 поверх h3: сам h3 0.0.8 API датаграмм не имеет (SETTINGS отдаёт, encode/decode — нет); Quarter Stream ID кодирует h3-datagram (`datagram.rs`) |
| `http` | 1.5.0 | 2026-09-18 | `cover-masque` (Extended CONNECT-запрос) | уже в дереве через h3; пин явный ради типа `http::Request` |
| `bytes` | 1.12.1 | 2026-09-18 | `cover-masque` (Buf для датаграмм) | уже в дереве через h3/quinn; пин явный |

### Phase 1: MASQUE live interop (2026-09-18, кусок 4) — факты, снятые с исходников

Пины `h3`-стека вошли в дело (кусок 4); перед письмом кода факты сверены с исходниками
публикуемых версий (не по памяти, по правилу `crate-feasibility`):

| Факт | Источник | Следствие |
|---|---|---|
| Extended CONNECT кодируется: `Method::CONNECT` + ext `Protocol::CONNECT_UDP` → `:protocol: connect-udp` | h3 0.0.8 `src/proto/headers.rs:377` (поле `Protocol` берётся из `Request::extensions`) | свой h3-клиент возможен без форка |
| Сервер отдаёт принятый `:protocol` назад: `req.extensions_mut().insert(protocol)` | h3 0.0.8 `src/server/request.rs:249` | сервер лаборатории распознаёт connect-udp без ручного парсинга |
| `SETTINGS H3_DATAGRAM (0x33)` + `SETTINGS_ENABLE_CONNECT_PROTOCOL` отдают builder'ы обеих сторон | h3 0.0.8 `client/builder.rs:103,109`, `server/builder.rs:102,116`, `config.rs:127,121` | обмен SETTINGS — включением двух флагов |
| HTTP Datagrams в самом h3 НЕ реализованы (только webtransport-комментарии и `Code::H3_DATAGRAM_ERROR`) | grep `datagram` по src/ h3 0.0.8 | без h3-datagram клейм «RFC 9297» был бы AIR |
| h3-datagram кодирует Quarter Stream ID (RFC 9297 §4): `varint(stream_id/4)` + payload, decode умножает на 4 | h3-datagram 0.0.2 `src/datagram.rs:33-100` | датаграммы привязаны к request-стриму штатно |
| h3-quinn даёт адаптер трейтов h3-datagram над `quinn::Connection::send_datagram/read_datagram` | h3-quinn 0.0.10 `src/datagram.rs` (фича `datagram`) | транспорт — наш пин quinn 0.11.12, второй QUIC-стек не тянется |
| Дерево: ровно одна копия `h3 0.0.8`/`quinn 0.11.12`/`tokio 1.53`; новый крипто-провайдер не подтянулся | `cargo tree -i rustls` до/после | пины Phase 0 не задеты |
| **`SendRequest::Drop` закрывает h3-соединение** («Connection closed by client», H3_NO_ERROR) | h3 0.0.8 `src/client/connection.rs:250-266` | handle обязан жить, пока жива сессия — поймано живым прогоном, поле `_request_sender` в `MasqueH3Client`/`DatagramHalf` |
| Клиентский драйвер — не `Future`: надо поллить `Connection::poll_close` (двигает контрольные стримы) | h3 0.0.8 `src/client/connection.rs:397` | `drive_until_closed` + `tokio::spawn` в лаборатории |
| Тесты h3 0.0.8 держат пары концов через `tokio::join!`/`poll_close` | h3 0.0.8 `src/tests/request.rs:37,54` | форма нашего e2e-теста |

TTL перепроверки — 180 дней (pre-1.0, активная разработка): **до 2027-03-17**.
При бампе h3: перечитать факты выше по новой версии (surface менялся между 0.0.4→0.0.8),
прогнать `masque_lab` — это и есть interop-гейт.

Пины продублированы в `Cargo.toml` → `[workspace.dependencies]`: не «два места на память»,
а так, что расхождение видно при первом же diff.

**Факт 2026-09-17 (`Cargo.lock` в репо, закрытие U-05):** lockfile сгенерирован
(`cargo generate-lockfile`, 190 пакетов) и закоммичен; `.gitignore` его никогда не трогал.
Lockfile показал ровно то, чего Q8 хотела «увидеть в `Cargo.lock`»: `clatter 2.3.0` транзитивно
тянет старое поколение — `x25519-dalek 2.0.1`, `chacha20poly1305 0.10.1`, `ml-kem 0.2.1` — рядом
с нашими прямыми пинами 3.0.0/0.11.0/0.3.2 (двойные копии dalek в дереве — теперь факт с SHA,
а не предположение). Правило: обновление `Cargo.lock` едёт в том же коммите, что и пины
в `Cargo.toml`, — иначе lockfile перестаёт быть воспроизведением.

### Наблюдение при съёме версий — проверить в Phase 0.5

В фичах `quinn` 0.11.12 есть `__rustls-post-quantum-test`, раскрывающаяся в
`rustls/prefer-post-quantum`. Если этот путь работает, **outer** TLS-handshake может быть
PQ-гибридным — это меняет клейм `design/03-components.md` §8 («Outer транспорт: стандартный
QUIC/TLS 1.3 — классический (не PQ), транспортная роль»). Ничего не утверждаю: имя фичи
с префиксом `__` выглядит тестовым, и проверять её надо спайком, а не по названию.
Вопрос вынесен в `QUESTIONS.md` Q7.

### Чего этот раздел не делает

Не пересматривает вердикты F1–F13: пины — про резолв, а не про пригодность крейта.
И не утверждает пригодность за пределами CI: на момент съёма локального тулчейна не было,
первым настоящим `cargo test` был CI на push; позже на машине прогона (Windows/GNU)
локальный тулчейн был настроен и версионирован — см. «Local Rust toolchain (Windows/GNU)»
ниже.

---

## E2E-лаборатория (2026-09-16, Phase 1)

Зависимости `crates/e2e-harness` (ручной прогон, фича `e2e`, `publish = false`) —
**не прод-пины**: прод-крейты их не тянут, дуга Phase 0 не расширяется. Подробности —
`docs/phase-reports/e2e-manual.md`.

| Крейт | Версия | Роль в лаборатории | Заметка |
|---|---|---|---|
| `quinn` | 0.11.12 (workspace-пин) | живой QUIC в бинах | тот же пин, что у `transport-mux`; новой версии нет |
| `tokio` | 1 | рантайм бинов и wire-слоя | неопционально в крейте (wire.rs компилируется всегда); прод-крейты async не используют |
| `rustls` | 0.23, default-features = false, features = `[ring, std, tls12]` | TLS QUIC-лаборатории | фича `ring` — тот же криптобэкенд, что у прод-пинов; провайдер задаётся явно (`rustls::crypto::ring::default_provider`) |
| `rcgen` | 0.13, features = `[ring, pem]` | самоподписанный сертификат узла на лету | Ed25519-ключ; SAN `localhost` + `127.0.0.1` |
| `rcgen` (workspace, Q23) | 0.13, features = `[ring, pem]` | скелет сертификата Accept-пути Reality (`build_reality_cert`) | Ed25519-скелет; CN обязателен, SAN не ставится; поле подписи перезаписывается per-handshake |

TTL перепроверки — вместе с Phase 0 pins (до 2026-12-15): снять `max_stable_version`
той же командой, при мажорном апгрейде rustls/rcgen перечитать API лаборатории
(`builder_with_provider` менялся между 0.22 и 0.23).

---

## Прод-зависимости, добавленные реализацией (2026-09-16, закрытие аудита)

| Крейт | Версия | Кто тянет | Зачем | TTL |
|---|---|---|---|---|
| `getrandom` | 0.3 | `ticket-mint`, `cover-ss2022`, `cover-reality` (workspace-пин, F-10) | случайный 24 B nonce тикета: AEAD обязан быть probabilistic (аудит: детерминированный `sha256(plain)`-nonce); прод-nonce/padding обложек (F-01: xorshift-счётчик был прод-дефектом). API — `getrandom::fill`, системный CSPRNG, explicit-fail | 180 дней |
| `hmac` | 0.13 | `crypto-core` (b132-2) | `probe_tag` — HMAC-SHA256-аутентификация открытого ClientHello в гейте Reality-обложки (peek-before-decrypt, Q22): решение до TLS-ключей, поэтому тег — HMAC (детерминированный, без nonce), не AEAD. Общий корень RustCrypto-стека, digest 0.11 — поколение с hkdf/sha2 | 180 дней |

Прямая зависимость осознанная: тянуть весь `crypto-core` (clatter + PQClean) в узловой
крейт ради 32 байт случайности — неоправданная связанность; `getrandom` — общий корень
RNG-стека RustCrypto, уже в дереве через `ed25519-dalek`/`chacha20poly1305`.

**Три версии `getrandom` в Cargo.lock (F-10, аудит 3):** `0.3.4` — наш workspace-пин
(выше); `0.2.17` — транзит `ring 0.17` (через `quinn`); `0.4.3` — транзит
`crypto-common 0.2` (через `crypto`-поколение RustCrypto) и `jobserver 0.1`
(build-dep `cc`/`cmake` для `boring-sys`). Обе «лишние» — чужие semver-требования,
не задокументировать отдельно нечем: отследены `cargo tree -i getrandom@…` 2026-09-18;
это нормальное состояние lockfile, а не дрейф пинов.

**TODO (не блокирует, отдельная задача):** внедрить `cargo-audit`/`cargo-deny` для
автоматического контроля advisory по lockfile. Сейчас уязвимости отслеживаются вручную
при TTL-перепроверках; внедрение требует выбора полемики (deny list, лицензии) и
отдельного прогона — не делалось в рамках фикса F-11.

---

## Local Rust toolchain (Windows/GNU) (2026-09-17)

Локальная машина прогона — Windows с тулчейном `stable-x86_64-pc-windows-gnu` (rustup).
Прод-пины с C-кодом (`clatter` → PQClean; `quinn` → `rustls`, фича `ring`) требуют
нативного компилятора: cc-rs ищет `gcc.exe` в PATH и молча падает на build-script'ах
`ring`/`pqcrypto-internals`, если его нет. Найденное воспроизводимое окружение
версионируется в репо:

| Компонент | Что | Где |
|---|---|---|
| C-компилятор | [w64devkit](https://github.com/skeeto/w64devkit/releases) (портативный mingw-w64; на машине прогона — GCC 16.2.0), распаковать в `~/w64devkit` | не в системном PATH по умолчанию |
| Заглушка PQClean | `tools/pq-shim/features.h` — `__GNUC_PREREQ`, которого нет в mingw `features.h`; попадает в сборку через `CFLAGS=-I` | версионируется в репо, рядом с пином `clatter`, от которого зависит |
| Линкер | self-contained `x86_64-w64-mingw32-gcc.exe` из rustup-тулчейна (`lib/rustlib/.../bin/self-contained/`); gcc из w64devkit линкером rustc не годится — без `-lgcc_eh` (`ld: cannot find -lgcc_eh`) | идёт с тулчейном |

Настройка одним шагом — `scripts/local-env.sh` (explicit-fail: любой отсутствующий
компонент — понятная ошибка с подсказкой, не тихая деградация):

```bash
source scripts/local-env.sh
cargo test --workspace --all-targets        # как CI: 85 passed / 0 failed (2026-09-17, HEAD)
cargo test -p e2e-harness --all-features    # шаг best-effort из ci.yml: 15 lib + 1 bin
```

Переопределения до source: `W64DEVKIT_HOME` (дефолт `~/w64devkit`),
`PQ_SHIM_DIR` (дефолт `tools/pq-shim` в репо), `BORING_TOOLS_DIR` (дефолт
`~/Desktop/boring-probe/tools` — портативные NASM 2.16.03 и libclang из пробы).

### Пин компилятора: версия vs host (F-11, перевыпуск 2026-09-18)

`rust-toolchain.toml` пинит **только версию** (`1.98.1`). Первый выпуск F-11 писал туда
полный триплет `1.98.1-x86_64-pc-windows-gnu`: для Windows это верно, для Linux CI — нет.

- rustup запрещает target-tuple в `channel` toolchain-файла по построению:
  `src/config.rs`, `find_override_config` — «Do not permit architecture/os selection in
  channels as these are host specific and toolchain files are portable» →
  `error: target tuple in channel name '<channel>'`. Исключение — ровно такой тулчейн уже
  установлен на машине (PR #2141), поэтому локально на Windows-машине прогона (где
  `1.98.1-x86_64-pc-windows-gnu` установлен) файл «работал» и дефект не всплывал.
- Замер на реальном ubuntu-раннере (проба `ci-probe-results`, run 35308742887): со старым
  значением `rustup show` → «active toolchain: no active toolchain», `rustc -vV` →
  `error: target tuple in channel name '1.98.1-x86_64-pc-windows-gnu'`. До установки
  чужого компилятора дело не доходит: имя отбраковывается на разборе файла, обязательный
  rust-job красный с первой же rustup-команды. (Гейт `--force-non-host` относится к
  CLI-путям `rustup toolchain install`/`--toolchain`, а не к toolchain-файлу.)

Устроено теперь так: версия одна на обе платформы, host добавляет тот, кому он известен.
`scripts/local-env.sh` читает версию из того же файла и экспортирует
`RUSTUP_TOOLCHAIN=1.98.1-x86_64-pc-windows-gnu` (env-переменная приоритетнее toolchain-файла);
CI не экспортирует ничего — host-less канал резолвится в host раннера
(`1.98.1-x86_64-unknown-linux-gnu` — подтверждено на раннере: «active because: overridden
by '…/rust-toolchain.toml'», release 1.98.1), а шаг «Verify toolchain pin (linux)» печатает
резолвнутый тулчейн и падает, если триплет вернётся в файл или версия не совпадёт с пином.

### boring-sys на Windows/GNU (2026-09-17, b132)

С `boring` 4.22 прод-зависимостью (`cover-reality`) `local-env.sh` дополнительно
настраивает то, что нужно boring-sys на этой платформе (полный рецепт —
`reality-boring-probe.md`): `CMAKE_GENERATOR=Ninja` (MSYS Makefiles ломается о busybox-sh
из w64devkit), портативный NASM 2.16.03 в PATH (CMakeLists BoringSSL требует ASM_NASM
на Windows x86_64), `LIBCLANG_PATH` на PyPI-колесо libclang + `BINDGEN_EXTRA_CLANG_ARGS`
с `-target x86_64-pc-windows-gnu` (без `-target` clang парсит mingw-заголовки как MSVC
и падает на `__MINGW_NOTHROW`). На Linux CI ничего этого не нужно, кроме
`cmake` + `libclang-dev` (apt) — NASM там не требуется (см. шаг 6 пробы).

**Почему это важно (урок 2026-09-17):** прогон без этого окружения не даёт «ошибку:
нет компилятора», а собирает только крейты без crypto-транзитива — в отчёте 23 passed
из 85 при нулевой диагностированной причине. Правильное число (85 + 16) получается
только с настроенным окружением. Расхождение локальных 88 уникальных тестов
с 91 в CI-отчёте (`e2e-manual.md`) — состав окружений: на раннере шаг под фичей `e2e`
протащил в счёт 3 теста `quic_lab` (реальный bind UDP), которые локально не входят
в основной workspace-прогон.
