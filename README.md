# VPN Engine Research & Design — `vpn/` (v2)

**Цель:** исследовать сетевые технологии и VPN, проанализировать современные архитектуры
и существующие решения, спроектировать концепт современного VPN-движка с уникальной
архитектурой — и сохранить исследование + описание проекта здесь.

**Имя концепта: `Aether`** — adversarial-aware, self-morphing, stateless-egress,
post-quantum VPN core. Архитектурный коднейм: **Liquid Tunnel**.

> **Статус v2:** доки прошли аудит («не воздух ли») и переработаны. Ключевые правки:
> добавлен frame-слой как носитель сессии, ротация описана до протокольного уровня
> (ticket-based, make-before-break), стек зависимостей верифицирован, клеймы о
> производительности разделены на ИЗМЕРЕНО / ГИПОТЕЗА / ПРОЕКТНО. См. `CHANGES-audit.md`.

---

## Карта папок

```
vpn/
├── README.md                  # этот файл — индекс + оркестрация
├── CHANGES-audit.md           # что и почему исправлено в v2
├── research/                  # исследовательские материалы (без изменений, кроме пометок)
│   ├── 00-index.md … 06-quic-transport.md
└── design/                    # описание проекта (v2)
    ├── 00-overview.md         # Aether на одном экране + честные ограничения
    ├── 01-architecture.md     # слои + потоки + последовательность ротации
    ├── 02-protocols.md        # frame-протокол, ротация, handshake, FSM морфинга
    ├── 03-components.md       # модули + верифицированный стек крейтов
    ├── 04-advantages.md       # цифры со статусами ИЗМЕРЕНО/ГИПОТЕЗА/ПРОЕКТНО
    └── 05-roadmap.md          # фазы 0–4 + Phase 0.5 (спайк верификации стека)
```

## Шесть столпов (кратко)

1. **Liquid Tunnel** — on-device ML-классификатор определяет, какой DPI-моделью пользуется
   цензор, и морфит wire-format в реальном времени (research-grade, Phase 2).
2. **Stateless Egress Core** — состояние сессии у клиента; узлы восстанавливают её из
   ticket (паттерн TLS session tickets) с proof-of-possession клиента; ротация make-before-break
   (тест — Phase 0).
3. **Hybrid PQ** — `X25519MLKEM768` через Noise_IK на control-стриме; `XChaCha20-Poly1305`
   на данные; HNDL-safe для записей сессии.
4. **Federated Egress Mesh** — 1–3 хопа с per-hop гибридом и ротацией звеньев.
5. **App Mirage** — декой-трафик под TLS-отпечаток популярных приложений (research-grade).
6. **QUIC-native transport** — QUIC-байндинг frame-слоя; MASQUE/Reality/SS-2022 —
   альтернативные байндинги (обложки).

## Оркестрация агентами (v2 — конвейер скиллов)

Работа над проектом ведётся скиллами Freebuff в строгом порядке — каждый следующий шаг
получает на вход только вывод предыдущего (экономия контекста без потери качества):

```
crate-feasibility → anti-air-audit → mechanism-drilldown (по WEAK/AIR пунктам)
→ claim-traceability → phase0-scaffold → [Phase 0.5 спайк] → impl-phase-driver (по фазам)
```

| Скилл | Роль | Модель |
|-------|------|--------|
| `crate-feasibility` | сверка стека с реальностью | дешёвая |
| `anti-air-audit` | GROUNDED/WEAK/AIR по каждому клейму | дорогая |
| `mechanism-drilldown` | дожим «как именно» до спецификации | дорогая |
| `claim-traceability` | цифры к источникам, ловля усилений | дешёвая |
| `phase0-scaffold` | Rust-воркспейс из 03-components | средняя |
| `impl-phase-driver` | проведение фазы roadmap end-to-end | дорогая |
| `rotation-test-writer` | интеграционные тесты ротации (гл. риск) | средняя |

Полные исходники скиллов — в `aether-freebuff-skills-v2.md` (снапшот; живой источник — `.agents/skills/`).

**Правила бюджета:** механические проверки — дешёвой моделью; рассуждения — дорогой.
Скиллы подгружаются on-demand; кастомные субагенты — только для независимых фоновых задач
с минимальными `toolNames`, `includeMessageHistory: false`.
