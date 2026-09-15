# Aether — обзор (v2, исправленный)

> **One-liner:** *Aether* — постквантовый, rotation-safe VPN-кор с адаптивной сменой обложки (Liquid Tunnel). Сессия живёт в frame-слое на клиенте и переживает и смену обложки, и ротацию egress-узла; ключи — гибридные `X25519MLKEM768`, транспорт — QUIC-нативный.

Codename архитектуры: **Liquid Tunnel**.

---

## Важные изменения v2 (результат аудита)

1. **Добавлен Frame-слой (Session protocol)** — «сессия» больше не привязана к inner QUIC.
   QUIC-in-TCP (обложка Reality) невозможен без HOL-проблем, поэтому сессия — это
   cover-агностичный record-протокол, который биндится к разным транспортам (см. `02-protocols §1`).
2. **Ротация egress конкретизирована** — ticket-based resumption по образцу TLS session tickets
   (RFC 8446 §2.2): узлы не хранят per-session state, клиент несёт ticket, завернутый под
   fleet-epoch ключом. Make-before-break, forward secrecy через post-rotation re-key
   (`02-protocols §3`).
3. **0-RTT переосмыслен.** Noise-XX не даёт 0-RTT; честная семантика: reconnect ≈ 1 RTT
   (outer resumption + ticket resume), 0-RTT early data — только для идемпотентного контроля
   и только если стек поддерживает.
4. **Стек исправлен:** `snow` не поддерживает ML-KEM-768 → Clatter (PQNoise) или
   `noise-protocol` + RustCrypto `ml-kem`; BBR в quinn — экспериментальный (не «BBRv3»);
   `masque-go` — Go, это reference, а не зависимость; ECH в quinn/rustls отсутствует →
   перенесён в Phase 4.
5. **Отозван флаг аудита про 1184/1088 байт** — размеры в handshake корректны в TLS-стиле
   (клиент шлёт encapsulation key 1184 B, сервер — ciphertext 1088 B, FIPS 203). Ошибки не было.

## Шесть столпов

| # | Столп | Что делает | Статус после аудита | Источник |
|---|-------|------------|---------------------|----------|
| 1 | **Liquid Tunnel** | On-device классификатор следит за uplink и морфит внешнюю обложку | research-grade; механизм морфа описан (`02 §5`) | 05, 2509.23522 |
| 2 | **Stateless Egress Core** | Сессия = ticket у клиента; узлы stateless; ротация make-before-break | спроектирован (`02 §3`), требует Phase 0 теста | 01 §3/§9 |
| 3 | **Hybrid PQ crypto** | `X25519MLKEM768` (Noise-XX, стиль NoisePQC++) на control; `XChaCha20-Poly1305` на данные | реализуемо (Clatter / ml-kem) | 04, 2608.00954 |
| 4 | **Federated Egress Mesh** | 1–3 хопа, per-hop handshake, chain rotation | спроектирован (`02 §3.4`) | 01 §6, 06 |
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
| Stateless server | ✗ | ✗ | partial | ✗ | ✅ (ticket-based) |

## Review checklist (обновлён)

- [x] Каждый novelty-claim трассируется в `../research/*`.
- [x] Hybrid only, не pure PQ (04).
- [x] Ротация: механизм описан до уровня сообщений (`02 §3`) — TLS-ticket паттерн.
- [x] Морфинг: механизм описан до overlap-window и границ оверхеда (`02 §5`).
- [x] Крипто конкретна: `X25519MLKEM768` + Noise-XX + `XChaCha20-Poly1305`; байты сверены с FIPS 203.
- [ ] **Открыто:** реализуемость 0-RTT early data в quinn — верификационный спайк (Phase 0.5).
- [ ] **Открыто:** ECH в Rust-стеке отсутствует — отложено в Phase 4, до этого полагаемся на MASQUE/Reality.
- [ ] **Открыто:** Reality-обложка поверх TCP даёт HOL на frame-слое — задокументированный tradeoff (`02 §2.2`).

> **Честные ограничения:** это дизайн, не код. Критический путь — Phase 0 тест ротации
> (ticket resume + continuity) и Phase 0.5 верификация фич quinn. Столпы 1 и 5 — research-grade
> и требуют живого DPI-тестбеда до продакшена.
