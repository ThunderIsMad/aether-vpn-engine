# Aether — дорожная карта реализации (v2)

Изменения v2: ротация стала проверяемой в Phase 0 (ticket-механизм описан в `02-protocols §3`);
добавлен Phase 0.5 — верификационный спайк фич стека (BBR/0-RTT/migration в quinn);
обложки переупорядочены по реализуемости (SS-2022 и MASQUE — чистый Rust первыми,
Reality — последним, как самый дорогой).

## Phase 0 — Фундамент: frame-сессия + PQ + ротация (MVP)

- [x] `frame-session`: record-протокол, stream_table, ratchet, duplicate-window. Юнит-тесты на моках байндингов.
- [x] `crypto-core`: Noise_IK + `X25519MLKEM768` (Clatter; noise-protocol — только через форк), `XChaCha20-Poly1305`. KAT-векторы FIPS 203.
- [ ] `key-coordinator`: mint/unwrap tickets, epoch keys, post-rotation re-key.
      ⇐ **частично:** клиентская половина (PoP, `RESUME`, re-key) и `mint`/`unwrap`
      (`ticket-mint`) реализованы и проверены; раздача epoch keys — манифест подписки,
      а не крейт (владелец `TFK_epoch` — узел, `02 §3.1`).
- [ ] `transport-mux`: QUIC-байндинг (quinn), дефолт cubic.
      ⇐ **частично:** кадрирование, caps (no-HOL/datagram), ограниченная очередь и оба
      отказных пути реализованы; async-писатель в `SendStream` и сетевой прогон — Phase 0.5.
- [x] **Интеграционный тест ротации** (главный риск проекта): сессия с 3 потоками, ротация
      N1→N2 по ticket, проверка: ни одна запись не потеряна на обоих каналах, continuity по seq,
      старый узел не читает пост-ротационный трафик (свежий DH),
      duplicate-window ≤ `T_morph` (2×SRTT, клип [200 ms, 2 s]) и `N ≤ 4096`.
      Отдельно — прогон с потерей на одном канале и прогон с потерей на обоих (фолбэк-путь).
      **Граница теста:** измеряется frame-слой, не payload-соединения; разрыв прикладных TCP
      при смене egress IP — ожидаемый эффект, не регресс.
- [x] **Негативные тесты ротации:** украденный ticket без валидной `sig_client` → `RESUME_NAK bad_pop`;
      повтор того же ticket → `RESUME_NAK replay`; подмена `eph_node` без `sig_node` → канал не подтверждён;
      узел упал между RESUME и ACK → откат на старый канал без разрыва сессии.
      ⇐ «узел упал» проверен в части, которая существует: ротация остаётся на overlap-window,
      сессия жива после отказа старого канала; фолбэк-буфер — вне Phase 0 (см. Exit выше),
      поэтому пункт закрыт без него, а не с ним.
- [x] `session-store` + `device-adapter` (Linux TUN первым) + `policy-engine` (fake-ip).
      ⇐ закрыто на границе Phase 0: `session-store` — at-rest через трейт `SecureStore` (in-memory
      backend; OS keyring — Phase 1); `policy-engine` — matcher exact-domain + CIDR, `Route/Direct/Block`,
      стабильный fake-ip-пул (0 ignored-тестов); `device-adapter` — контракт `open → read → write → close`
      на **in-memory стабе** с платформенным гейтом (`UnsupportedPlatform` на не-Linux, unit-тесты
      без устройства зелёные). Реального `/dev/net/tun` и ioctl(TUNSETIFF) здесь нет — ручная
      интеграция с живым TUN вынесена в Phase 1 (см. `phase-0.md` → «remainder: policy + tun stub»).
      Склейка пути — крейт `phase0-path`: packet → policy → `FrameSession` → seal → `CoverBinding`
      (5 интеграционных тестов на `MemBinding`, без сети и TUN).
- **Exit:** PQ-безопасный, rotation-safe **на frame-слое** однохоповый туннель (payload-соединения — риск выше). Это уже закрывает SnowVPN-баг —
      но теперь с доказательством, а не заявлением.
      **Граница exit (записано явно): фолбэк-буфер payload при мёртвых обоих каналах — НЕ
      входит в Phase 0.** Ротация доказана на overlap-window (дубли до валидного ACK,
      `MorphFailed` → откат, quarantine) и исчерпание бюджета — провал ротации, а не
      деградация. Бюджет «≤ 16 МБ или ≤ 5 с» в Phase 0 не реализован и не считается
      достигнутым: это Phase 1 (буфер — отдельный механизм, владение см. `QUESTIONS.md`).

## Phase 0.5 — Верификационный спайк стека (1–2 дня, до Phase 1)

- [x] quinn: TLS session resumption — **есть**; 0-RTT early data — **есть** (`into_0rtt`, replay-оговорка
      библиотеки совпадает с `02 §7`); connection migration — **серверная только** (активной клиентской
      в API 0.11.12 нет); BBR — экспериментальный и не сопровождается, дефолт cubic. Отчёт:
      `docs/phase-reports/phase-0.5.md` (метод: docs + исходники тегов; сетевого прогона в CI не было).
- [x] RustCrypto `ml-kem` + **Clatter**: гибрид собран и протестирован в Phase 0 (KAT + двунаправленный
      interop PQClean ⇄ RustCrypto, `crypto-core`); единственный готовый путь — `noise-protocol`
      KEM-токенов не имеет (форк), KEM-бэкенд — только `pqclean` (см. DEPENDENCIES.md → «Phase 0.5»).
- [x] `noise_hybrid_IK_*` в `handshakepattern` — **есть** (`noise_hybrid_ik()`, токены
      `-> Skem, E, ES, S, SS / <- Ekem, Skem, E, EE, SE`); порядок записан в `02 §5`, семантика
      `Skem` в msg2 (статик-KEM узла) — с HNDL-оговоркой (Q12, отчёт спайка). Пересмотр на KK не требуется.
- Отложено **вне бюджета спайка**: форк `noise-protocol` под токены `ekem`/`skem` + KEM-трейт —
      только если Clatter не устроит по аудиту или interop. Цена: расширение паттерн-языка и
      поддержка форка, а не часы; решение принимается после результата спайка, а не в нём.
- [x] Результаты зафиксированы в DEPENDENCIES.md → «Phase 0.5» и `docs/phase-reports/phase-0.5.md`:
      фича → статус → клейм → действие; ложные ✅ сняты (`00` матрица).
- **Правило:** если фича не поддерживается — она исключается из клеймов Phase 1, а не «планируется».
      Применено: активная клиентская миграция исключена из клеймов (✅ снят), outer-PQ фича не включена.

## Phase 1 — Обложки (статическая библиотека)

Порядок по возрастанию стоимости:

- [x] SS-2022/padded байндинг — чистый Rust, простой, базовый fallback.
      ⇐ **padded-часть закрыта** (`cover-ss2022::SsPaddedBinding`, CI `8d976d9`): собственный
      AEAD-слой + padding-бюджет, stream-класс caps (no-HOL нет, `02 §2.2`), склейка с
      `phase0-path` проверена. Отчёт: `docs/phase-reports/phase-1.md` (кусок 1).
- [ ] **SS-2022 interop** (wire-совместимость с реальным shadowsocks-2022) — [ ] до появления
      внешних тест-векторов; сейчас формат называется «Aether padded cover» (`03` §4).
- [ ] MASQUE CONNECT-UDP (RFC 9298) — минимальный клиент на quinn+h3 (оценка, уточняется в Phase 1); masque-go как reference.
- [ ] Reality/VLESS — последний: либо Go-sidecar с xray-core, либо `boring` с контролем ClientHello.
      uTLS-эквивалента в Rust нет — это самый дорогой пункт Phase 1.
- [ ] Ручной выбор обложки в UI; измерить pass-rate каждой на тестовой сети.
- [ ] Собственный бенчмарк производительности (закрывает ГИПОТЕЗУ из 04-advantages).
- **Exit:** оператор выбирает обложку; PQ + stateless + (теперь) измеренные цифры.

## Phase 2 — Liquid Tunnel (онлайн-морфинг) — research-grade

- [ ] On-device классификатор (ONNX, класс 2506.11319): probe/block rate, RST-паттерны, length-distribution.
- [ ] FSM (`02 §4`): классификатор → выбор байндинга → смена с overlap-window без разрыва сессии.
- [ ] Self-test: локальный прогон публичной DPI-модели для оценки обложек офлайн.
- [ ] Валидация на тестбеде (класс shabz0077/traffic-evasion): false-negative (блок) и
      false-positive (лишний морф) rates; тюнинг порогов.
- **Exit:** демонстрируемый онлайн-морфинг против скриптованного цензора.

## Phase 3 — App Mirage + Mesh — research-grade

- [ ] CoverEngine: FlowPaint-класс генератор, rate-limited.
- [ ] Federated Egress Mesh: 2–3 хопа, per-hop гибрид, ротация звена цепочки (каркас в `02 §3.4`; статус — research-grade).
- [ ] TelemetryGuard (opt-in) для улучшения классификатора по полевым исходам.

## Phase 4 — Харднинг и шип

- [ ] Фаззинг Noise_IK + QUIC + байндингов; constant-time аудит.
- [ ] Battery/CPU бюджет для on-device ML; адаптивный размер модели.
- [ ] ECH/OHTTP (когда станут сквозными через quinn или появится серверная поддержка), CID-ротация, политика 0-RTT replay.
- [ ] Multipath QUIC; платформенные GUI.

## Риски и митигации (обновлено)

| Риск | Митигация |
|------|-----------|
| Ticket-механизм не взлетает (тест Phase 0 красный) | фолбэк: ротация = graceful reconnect с буфером frame-слоя (деградация, не провал). Буфер ≤ 16 МБ или ≤ 5 с — дальше это провал ротации, а не деградация |
| Компрометация epoch-ключа вскрывает сессии эпохи | короткие эпохи, per-fleet keys, post-rotation re-key |
| quinn: активная клиентская migration отсутствует (серверная есть), 0-RTT есть с replay-оговоркой | **спайком снято** (Phase 0.5): миграция исключена из клеймов; 0-RTT — только идемпотентный контроль (`02 §7`); патчи по образцу Warrenguard — только если фаза потребует |
| Classifier false-negative → блок | консервативные пороги; фолбэк на сильнейшую статичную обложку |
| Classifier false-positive → батарея | rate-limit морфов; App Mirage off по умолчанию |
| Reality слишком дорог в Rust | Go-sidecar или boring; не блокирует остальные обложки |
| Replay/гонка ticket при ротации | PoP-подпись клиента + consumed-set эпохи (`02 §3.3`, `02 §3.6`) |
| Узел не аутентифицируется клиенту | Noise_IK со статическими ключами узлов из манифеста подписки (`02 §5`) |
| consumed-set теряется при рестарте узла | принято сознательно; короткие эпохи + `exp` (`02 §3.6`) |
| Крана двух узлов на один ticket | разрешается на клиенте: первый валидный ACK, второй в quarantine (`02 §3.6`) |
| PQ handshake trips middleboxes | едет на control-стриме поверх установленного QUIC, не в Initial — проблемы нет |
| On-device ML тяжёл для слабых телефонов | HW-Aware NAS модель; lazy load. Цель: < 20 МБ модели, < 50 мс инференс, < 3% батареи/час — уточняется в Phase 2 |
| Ротация меняет egress IP → рвутся прикладные TCP/QUIC | принять как известный эффект Phase 0; per-flow pinning (старые потоки на N1 до FIN) — решение Phase 1 |

## Первый рекомендованный deliverable

Phase 0 + Phase 0.5 + Phase 1 (без Reality, если дорого): PQ-safe, stateless,
rotation-safe (frame-слой) туннель с измеренным бенчмарком и минимум двумя обложками.
Research-grade части (Phase 2–3) — отдельным треком после стабильного ядра.
