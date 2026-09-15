# CHANGES — аудит v2: что и почему исправлено

Аудит проводился против внешних источников (FIPS 203, статус крейтов quinn/snow/clatter,
прецеденты типа Warrenguard). Формат: пункт → что было → что стало → обоснование.

## Исправления архитектуры

| # | Что было (v1) | Что стало (v2) | Почему |
|---|---------------|----------------|--------|
| 1 | «Inner QUIC переживает морфинг и ротацию» | **FrameSession** — cover-agnostic record-протокол; байндинги (QUIC/MASQUE/Reality/SS-2022) подключаются к нему | QUIC-over-TCP (Reality-обложка) даёт HOL и ломает datagram-семантику; сессия обязана жить в транспортно-независимом слое |
| 2 | Ротация: «клиент переотправляет session-id, сессия продолжается» | Протокол до уровня сообщений: **ticket-based resumption** (паттерн TLS session tickets, RFC 8446 §2.2), fleet epoch keys, make-before-break, post-rotation re-key | Механизм «как узел без состояния получает ключ» отсутствовал — главный AIR-пункт v1 |
| 3 | «0-RTT instant reconnect» | Честно: **reconnect ≈ 1 RTT** (outer resumption + RESUME frame); 0-RTT early data — только идемпотентный контроль, при поддержке стека | Noise-XX не имеет 0-RTT resumption; QUIC 0-RTT — свойство TLS handshake, не сессии |
| 4 | «KEM share едет в QUIC Initial» | Noise-XX handshake едет **на control-стриме поверх установленного QUIC** | Initial-датаграмма ограничена ~1200 B; 1216 B share туда не влезает. На стриме — влезает, проблемы нет |
| 5 | «BBRv3» | BBR в quinn — **экспериментальный** (BBRv1-класс), дефолт cubic, BBR за флагом с бенчмарком | Статус quinn congestion: «Experimental! Use at your own risk» |
| 6 | `snow` для Noise+PQ | **Clatter** (PQNoise, ML-KEM-768) или `noise-protocol` + RustCrypto `ml-kem` | snow поддерживает только Kyber1024 round-3, ML-KEM-768 туда не вставить |
| 7 | `masque-go` как имплементация | Понижен до **reference**; MASQUE-клиент — свой минимальный Rust поверх quinn+h3 | masque-go — Go; ядро Rust, смешение стеков не нужно |
| 8 | ECH как часть дизайна Phase 1 | **Перенесён в Phase 4** с условием «когда появится в Rust-стеке» | quinn/rustls не поддерживают ECH |
| 9 | «30–50% быстрее TCP-VPN» подано как факт | Статус **ГИПОТЕЗА**: выведено из QPEP (>2×, 2020, PEP-контекст); свой бенчмарк — exit-критерий Phase 1 | Экстраполяция измерений другого контекста |
| 10 | Reality-обложка без оговорок | HOL на Reality-байндинге задокументирован как tradeoff; FSM переключает на QUIC-байндинг при первой возможности | TCP-байндинг принципиально не даёт no-HOL |

## Отзыв флага аудита (честность)

В первом аудите я пометил байтовые размеры handshake (клиент 1184 B / сервер 1088 B) как
ошибку. **При детальной сверке с FIPS 203 и research/04 отзываю**: в TLS-стиле
X25519MLKEM768 клиент действительно шлёт encapsulation key (1184 B), сервер —
ciphertext (1088 B). Ошибки в v1 по этому пункту не было.

## Новые модули (03-components)

- `frame-session` — record-протокол, носитель сессии (критический путь).
- `key-coordinator` — epoch keys + mint/unwrap tickets + post-rotation re-key.

## Новые фазы/тесты (05-roadmap)

- Интеграционный тест ротации перенесён в **Phase 0** (главный риск должен проверяться первым).
- **Phase 0.5** — верификационный спайк: quinn resumption/0-RTT/migration/BBR, сборка
  ml-kem+noise-прототипа. Правило: неподдерживаемая фича исключается из клеймов, а не «планируется».
- Обложки Phase 1 переупорядочены по стоимости: SS-2022 → MASQUE → Reality.

## Что не изменилось

- research/* — без структурных изменений; единственная правка-примечание: «carried in QUIC
  Initial» в 04-pq-crypto и 02-current-articles читать как «на control-стриме поверх QUIC».
- Крипто-примитивы (X25519MLKEM768, Noise-XX, XChaCha20-Poly1305) — подтверждены как корректный выбор.
- Направление (морфинг против ML-DPI, stateless egress, QUIC-субстрат) — подтверждено аудитом.

## Скиллы (v2)

Обновлены под новый контекст: `crate-feasibility` (вшиты верифицированные факты стека,
позднее доведены до леджера F1–F6 с TTL и маркером STALE), `anti-air-audit` (добавлены
правила про транспортно-независимую сессию и state-transfer механизмы), `phase0-scaffold`
(порядок сборки frame-session → transports → morph).
Добавлены: `impl-phase-driver` (оркестрация фазы end-to-end с тестовыми exit-критериями)
и `rotation-test-writer` (тесты главного риска: ротация, морфинг, forward secrecy, replay).
