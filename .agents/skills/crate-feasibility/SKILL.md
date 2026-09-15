---
name: crate-feasibility
description: Verify that every dependency named in a design doc exists and supports the claimed feature. Use before committing to an implementation plan.
metadata:
  category: review
---

# Crate Feasibility Check

## Instructions

1. Extract every named dependency + attributed feature.
2. Check the Verified Facts Ledger FIRST. Any fact older than its TTL: run its
   re-check command before relying on it; update the date if confirmed, mark
   FALSIFIED with evidence if not. Facts with TTL ∞ need no re-check. Append new
   facts with date + TTL + re-check command. Precedents (section below the ledger)
   are exempt from TTL and date inheritance.
3. Output: dependency | claimed feature | actual status | drop-in alternative |
   effort if none. Include check date AND TTL for every row. A row whose fact
   has expired TTL is INVALID until re-checked: either run the re-check or mark
   the row STALE — never silently rely on an expired fact.
4. No alternative exists → mark RESEARCH-GRADE, never "planned".
5. Write results to DEPENDENCIES.md.

## Verified Facts Ledger

| # | Факт | Проверен | TTL | Как перепроверить |
|---|------|----------|-----|-------------------|
| F1 | quinn's BBR — experimental (BBRv1-класс, не BBRv3); дефолт CC — cubic | 2026-09-16 | 90 дней | docs.rs/quinn-proto → модуль congestion, баннер "Experimental" |
| F2 | snow поддерживает только Kyber1024 round-3; ML-KEM-768 не вставить | 2026-09-16 | 180 дней | crates.io/crates/snow + crypto.stackexchange.com q/119930 |
| F3 | ML-KEM-768: pk=1184 B, ct=1088 B, ss=32 B | 2026-09-16 | ∞ | NIST FIPS 203, Table 3 (nvlpubs.nist.gov) |
| F4 | masque-go / quic-go — Go; для Rust-ядра только reference | 2026-09-16 | ∞ | pkg.go.dev / github.com/quic-go — язык репозитория |
| F5 | quinn / rustls не поддерживают ECH | 2026-09-16 | 90 дней | поиск issues "ECH" в репо rustls — статус open/closed |
| F6 | clatter — pure-Rust PQNoise с ML-KEM-768 | 2026-09-16 | 180 дней | github.com/jmlepisto/clatter README, feature flags |

Ledger rules: строки не удаляются — помечаются superseded; каждое использование
факта леджера в выводе наследует его дату и TTL; строки из Precedents (P*) —
только контекст, даты не наследуют и в таблицу вывода не попадают. При обнаружении
факта с истёкшим TTL без перепроверки — строка в самом леджере помечается STALE до
момента re-check; STALE в леджере и STALE в выводе — один и тот же маркер. Колонка
статуса — это ячейка «Проверен»: отдельная колонка не вводится, маркер пишется
рядом с датой (2026-09-16 · STALE).

## Precedents (не подлежат TTL и наследованию дат)

- P1: Warrenguard (Rust VPN over QUIC) патчил quinn под BBR (r/rust, 2026-08) —
  показывает, что perf-фичи quinn могут требовать патчей; использовать как ориентир
  для Phase 0.5, не как факт о текущем API.
