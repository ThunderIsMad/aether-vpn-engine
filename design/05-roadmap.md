# Aether — дорожная карта реализации (v2)

Изменения v2: ротация стала проверяемой в Phase 0 (ticket-механизм описан в `02-protocols §3`);
добавлен Phase 0.5 — верификационный спайк фич стека (BBR/0-RTT/migration в quinn);
обложки переупорядочены по реализуемости (SS-2022 и MASQUE — чистый Rust первыми,
Reality — последним, как самый дорогой).

## Phase 0 — Фундамент: frame-сессия + PQ + ротация (MVP)

- [ ] `frame-session`: record-протокол, stream_table, ratchet, duplicate-window. Юнит-тесты на моках байндингов.
- [ ] `crypto-core`: Noise_IK + `X25519MLKEM768` (Clatter; noise-protocol — только через форк), `XChaCha20-Poly1305`. KAT-векторы FIPS 203.
- [ ] `key-coordinator`: mint/unwrap tickets, epoch keys, post-rotation re-key.
- [ ] `transport-mux`: QUIC-байндинг (quinn), дефолт cubic.
- [ ] **Интеграционный тест ротации** (главный риск проекта): сессия с 3 потоками, ротация
      N1→N2 по ticket, проверка: 0 потерянных записей, continuity по seq, старый узел не читает
      пост-ротационный трафик (свежий DH), duplicate-window ≤ 1 RTT.
- [ ] **Негативные тесты ротации:** украденный ticket без валидной `sig_client` → `RESUME_NAK bad_pop`;
      повтор того же ticket → `RESUME_NAK replay`; подмена `eph_node` без `sig_node` → канал не подтверждён;
      узел упал между RESUME и ACK → откат на старый канал без разрыва сессии.
- [ ] `session-store` + `device-adapter` (Linux TUN первым) + `policy-engine` (fake-ip).
- **Exit:** PQ-безопасный, rotation-safe однохоповый туннель. Это уже закрывает SnowVPN-баг —
      но теперь с доказательством, а не заявлением.

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
| Ticket-механизм не взлетает (тест Phase 0 красный) | фолбэк: ротация = graceful reconnect с буфером frame-слоя (деградация, не провал) |
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
| On-device ML тяжёл для слабых телефонов | HW-Aware NAS модель; lazy load |

## Первый рекомендованный deliverable

Phase 0 + Phase 0.5 + Phase 1 (без Reality, если дорого): PQ-safe, stateless,
rotation-safe туннель с измеренным бенчмарком и минимум двумя обложками.
Research-grade части (Phase 2–3) — отдельным треком после стабильного ядра.
