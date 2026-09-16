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
      ⇐ «узел упал» проверен в части, которая существует: буфер фолбэка ≤ 16 МБ / ≤ 5 с не
      реализован — BLOCKER в `QUESTIONS.md`.
- [ ] `session-store` + `device-adapter` (Linux TUN первым) + `policy-engine` (fake-ip).
      ⇐ **частично:** `session-store` реализован (at-rest через трейт `SecureStore`, in-memory
      backend в Phase 0); `device-adapter` и `policy-engine` — заглушки скаффолда,
      их контрактные тесты остались под `#[ignore]`.
- **Exit:** PQ-безопасный, rotation-safe **на frame-слое** однохоповый туннель (payload-соединения — риск выше). Это уже закрывает SnowVPN-баг —
      но теперь с доказательством, а не заявлением.
      ⇐ **не достигнут:** см. `docs/phase-reports/phase-0.md` — буфер фолбэка (BLOCKER),
      `device-adapter`/`policy-engine`, сетевой прогон QUIC-байндинга и OS secure store.

## Phase 0.5 — Верификационный спайк стека (1–2 дня, до Phase 1)

- [ ] quinn: что реально поддерживает — TLS session resumption? 0-RTT early data? connection migration? BBR (экспериментальный) vs cubic на lossy-линке?
- [ ] RustCrypto `ml-kem` + **Clatter**: собрать и протестировать гибрид NoisePQC++-паттерна
      (единственный готовый путь — `noise-protocol` KEM-токенов не имеет, см. DEPENDENCIES.md).
- [ ] Проверить, есть ли `noise_hybrid_IK_*` в `handshakepattern`; если нет — собрать IK утилитами
      модуля. Зафиксировать порядок токенов и транскрипт хендшейка (`02 §5`). Иначе паттерн пересматривается на KK.
- Отложено **вне бюджета спайка**: форк `noise-protocol` под токены `ekem`/`skem` + KEM-трейт —
      только если Clatter не устроит по аудиту или interop. Цена: расширение паттерн-языка и
      поддержка форка, а не часы; решение принимается после результата спайка, а не в нём.
- [ ] Зафиксировать результаты в DEPENDENCIES.md: фича → статус → workaround → решение.
- **Правило:** если фича не поддерживается — она исключается из клеймов Phase 1, а не «планируется».

## Phase 1 — Обложки (статическая библиотека)

Порядок по возрастанию стоимости:

- [ ] SS-2022/padded байндинг — чистый Rust, простой, базовый fallback.
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
| quinn не поддерживает migration/0-RTT | Phase 0.5 заранее; клеймы урезаются, патчи по образцу Warrenguard (они патчили quinn под BBR) |
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
