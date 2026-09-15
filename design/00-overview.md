# Aether — обзор (v2, исправленный)

> **One-liner:** *Aether* — постквантовый, rotation-safe VPN-кор с адаптивной сменой обложки (Liquid Tunnel). Сессия живёт в frame-слое на клиенте и переживает и смену обложки, и ротацию egress-узла; ключи — гибридные `X25519MLKEM768`, транспорт — QUIC-нативный.

Codename архитектуры: **Liquid Tunnel**.

---

## Важные изменения v2 (результат аудита)

1. **Добавлен Frame-слой (Session protocol)** — «сессия» больше не привязана к inner QUIC.
   QUIC-in-TCP (обложка Reality) невозможен без HOL-проблем, поэтому сессия — это
   cover-агностичный record-протокол, который биндится к разным транспортам (см. `02-protocols §1`).
2. **Ротация egress конкретизирована** — ticket-based resumption по образцу TLS session tickets
   (RFC 8446 §2.2): у узлов нет состояния, переживающего ротацию (на время сессии —
   in-memory окно дедупликации и consumed-set эпохи), клиент несёт ticket, завернутый под
   fleet-epoch ключом. Make-before-break, forward secrecy через post-rotation re-key со **свежим DH**
   (`02-protocols §3.3`). Резюм требует proof-of-possession клиента: украденный ticket сессии не даёт.
3. **0-RTT переосмыслен.** Noise_IK не даёт 0-RTT resumption; честная семантика: reconnect ≈ 1 RTT
   (outer resumption + ticket resume), 0-RTT early data — только для идемпотентного контроля
   и только если стек поддерживает.
4. **Стек исправлен:** `snow` не поддерживает ML-KEM-768 → Clatter (PQNoise) — единственный
   готовый путь (`noise-protocol` + RustCrypto `ml-kem` — только через форк); BBR в quinn —
   экспериментальный и не сопровождается (не «BBRv3»); `masque-go` — Go, это reference, а не
   зависимость; ECH сквозь quinn недоступен (в rustls клиентский ECH есть) → перенесён в Phase 4.
5. **Отозван флаг аудита про 1184/1088 байт** — размеры в handshake корректны в TLS-стиле
   (клиент шлёт encapsulation key 1184 B, сервер — ciphertext 1088 B, FIPS 203). Ошибки не было.

## Шесть столпов

| # | Столп | Что делает | Статус после аудита | Источник |
|---|-------|------------|---------------------|----------|
| 1 | **Liquid Tunnel** | On-device классификатор следит за uplink и морфит внешнюю обложку | research-grade; механизм морфа описан (`02 §4`) | 05, 2509.23522 |
| 2 | **Stateless Egress Core** | Сессия = ticket у клиента; у узлов нет состояния, переживающего ротацию; ротация make-before-break с PoP клиента | спроектирован до полей (`02 §3`), требует Phase 0 теста | 01 §3/§9 |
| 3 | **Hybrid PQ crypto** | `X25519MLKEM768` (Noise_IK, стиль NoisePQC++) на control; `XChaCha20-Poly1305` на данные | реализуемо (Clatter); наличие гибрида IK — Phase 0.5 | 04, 2608.00954 |
| 4 | **Federated Egress Mesh** | 1–3 хопа, per-hop handshake, chain rotation | Phase 3, research-grade; каркас в `02 §3.4` | 01 §6, 06 |
| 5 | **App Mirage** | Декой-трафик под TLS-отпечаток популярных приложений | research-grade (FlowPaint) | 05, 2606.22717 |
| 6 | **QUIC-native transport** | QUIC-байндинг frame-слоя: streams, migration, no-HOL | реализуемо (quinn) | 06, 2002.05091 |

## Сравнение с существующими движками

| Capability | WireGuard | mihomo (SnowVPN) | Tor | WARP | **Aether** |
|------------|-----------|------------------|-----|------|------------|
| Anti-DPI | нет | Reality (статично) | obfs4 | MASQUE | адаптивно (после Phase 2) |
| Live morphing | – | – | – | – | Phase 2, research-grade |
| PQ crypto | ✗ | ✗ | research | ✗ | ✅ hybrid (обе плоскости сессии) |
| Egress rotation safe | n/a | ✗ (рвёт сессии) | частично | n/a | ✅ при подтверждении Phase 0 тестом |
| Multi-hop low latency | ✗ | ✗ (1 hop) | ✗ медленно | ✗ | Phase 3 |
| App-fingerprint cover | ✗ | ✗ | ✗ | ✗ | Phase 3, research-grade |
| 0-RTT / migration / no-HOL | ✗/✗/✗ | partial | ✗ | ✅/✅/✅ | resumption ≈1 RTT / ✅ / ✅ (QUIC-байндинг) |
| Stateless server | ✗ | ✗ | partial | ✗ | ✅ нет состояния, переживающего ротацию (ticket-based) |

## Review checklist (обновлён)

- [x] Каждый novelty-claim трассируется в `../research/*`.
- [x] Hybrid only, не pure PQ (04).
- [x] Ротация: механизм описан до полей сообщений (`02 §3`) — TLS-ticket + PoP + свежий DH.
- [x] Handshake: паттерн назван корректно (Noise_IK с предраспределённым статиком узла), а не XX (`02 §5`).
- [x] Дедуп: клейм снижен до «идемпотентный дедуп по (sid, seq), at-most-once на выходе» (`02 §3.5`).
- [x] Морфинг: механизм описан до overlap-window и границ оверхеда (`02 §4`).
- [x] Крипто конкретна: `X25519MLKEM768` + Noise_IK + `XChaCha20-Poly1305`; байты сверены с FIPS 203.
- [ ] **Открыто:** реализуемость 0-RTT early data в quinn — верификационный спайк (Phase 0.5).
- [ ] **Открыто:** наличие гибридного `noise_hybrid_IK_*` в Clatter и порядок токенов — Phase 0.5 (`02 §5`).
- [ ] **Открыто:** consumed-set теряется при рестарте узла — принято сознательно и смягчено короткими эпохами (`02 §3.6`).
- [ ] **Открыто:** ECH сквозь quinn недоступен (клиентский ECH в rustls есть, серверный — открыт) — отложено в Phase 4, до этого полагаемся на MASQUE/Reality.
- [ ] **Открыто:** Reality-обложка поверх TCP даёт HOL на frame-слое — задокументированный tradeoff (`02 §2.2`).

> **Честные ограничения:** это дизайн, не код. Критический путь — Phase 0 тест ротации
> (ticket resume + continuity) и Phase 0.5 верификация фич quinn. Столпы 1 и 5 — research-grade
> и требуют живого DPI-тестбеда до продакшена.
