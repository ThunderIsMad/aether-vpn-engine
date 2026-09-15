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
| F1 | quinn's BBR — experimental (BBRv1-класс, не BBRv3), к тому же НЕ сопровождается; дефолт CC — cubic | 2026-09-16 | 90 дней | docs.rs/quinn-proto → модуль congestion, баннер "Experimental" + quinn issue #2156 |
| F2 | snow поддерживает только Kyber1024 round-3 (закрытый KemChoice enum); ML-KEM-768 не вставить | 2026-09-16 | 180 дней | crates.io/crates/snow + crypto.stackexchange.com q/119930 |
| F3 | ML-KEM-768: pk=1184 B, ct=1088 B, ss=32 B | 2026-09-16 | ∞ | NIST FIPS 203, Table 3 (nvlpubs.nist.gov) |
| F4 | masque-go / quic-go — Go; для Rust-ядра только reference | 2026-09-16 | ∞ | pkg.go.dev / github.com/quic-go — язык репозитория |
| F5 | quinn / rustls НЕ поддерживают ECH | 2026-09-16 · FALSIFIED | 90 дней | опровергнут 2026-09-16: см. F7/F8 — верно только для quinn, клиентский ECH в rustls есть |
| F6 | clatter — pure-Rust PQNoise с ML-KEM-768 | 2026-09-16 | 180 дней | github.com/jmlepisto/clatter README — поддержка MLKEM768 явная; см. оговорки F6a |
| F6a | clatter: без формального аудита; собственное именование PQ-примитивов → interop не гарантирован; нет SEEC; опущены pattern parsing, Curve448, deferred/fallback patterns, PSK validity rule | 2026-09-16 | 180 дней | README clatter, разделы "Warning", "Differences to PQNoise paper", omissions |
| F7 | клиентский ECH в rustls ЕСТЬ (experimental, `rustls::client::EchConfig` + пример ech-client.rs); серверный — открыт | 2026-09-16 | 90 дней | docs.rs/rustls/latest/rustls/client/struct.EchConfig.html + rustls issue #1980 |
| F8 | quinn не выставляет ECH-путь (issue #2024 — про доступ к ClientHello, не про ECH) | 2026-09-16 | 90 дней | поиск issues "ECH" в quinn-rs/quinn, обзор congestion/tls API |
| F9 | `noise-protocol` абстрактный: трейты только DH/Cipher/Hash, KEM-токенов (ekem/skem) нет → «noise-protocol + ml-kem» не композиция, а форк | 2026-09-16 | 180 дней | docs.rs/noise-protocol — список трейтов и модулей |
| F10 | нет готового quinn-based клиента RFC 9298: `h3-masque` построен на MsQuic | 2026-09-16 | 180 дней | crates.io/crates/h3-masque — описание зависимостей |
| F11 | `boring` (cloudflare/boring) существует: 4.x stable, 5.0.0-alpha.1; контроль ClientHello подтверждён; риск конфликта символов libcrypto рядом с rustls/ring | 2026-09-16 | 180 дней | crates.io/crates/boring + сообщения о двух libcrypto в одном дереве |
| F12 | `ort` 2.0 — всё ещё release candidate (2.0.0-rc.13); multiversioning ONNX Runtime 1.17–1.24 | 2026-09-16 | 90 дней | ort.pyke.io (версия) + github.com/pykeio/ort/releases |
| F13 | «uTLS-эквивалента в Rust нет» — частично опровергнуто: есть `impersonate-rs` (01.2026, HTTP-уровень) и профили JA3/JA4; TLS-слойного uTLS-эквивалента действительно нет | 2026-09-16 | 90 дней | lib.rs/crates/impersonate-rs + crates.io/crates/boring |

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
