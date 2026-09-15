# Freebuff Skills для проекта Aether (v2)

> **⚠️ СНАПШОТ v2 (2026-09-16).** Живой источник истины по скиллам — `.agents/skills/`;
> леджер фактов — `.agents/skills/crate-feasibility/SKILL.md` (F5/ECH опровергнут 2026-09-16).
> НЕ регенерировать скиллы из этого файла без сверки с леджером.

Скиллы лежат в `.agents/skills/<name>/SKILL.md`, имя каталога = `name`.
Вызов: `/skill:<name>` или автоматически по релевантности.
v2: обновлён `crate-feasibility` (вшиты верифицированные факты), добавлены
`impl-phase-driver` (оркестрация фаз) и `rotation-test-writer` (главный риск проекта).

---

## 1. crate-feasibility — сверка стека с реальностью (дешёвая модель)

`.agents/skills/crate-feasibility/SKILL.md`

```markdown
---
name: crate-feasibility
description: Verify that every dependency named in a design doc exists and supports the claimed feature. Use before committing to an implementation plan.
metadata:
  category: review
---

# Crate Feasibility Check

## Instructions

1. Extract every named dependency + attributed feature.
2. Verify via crates.io / docs.rs / RFC text. Verified facts to apply (re-check current):
   - quinn's BBR is EXPERIMENTAL (BBRv1-class) — not "BBRv3". Default is cubic.
   - `snow` supports only Kyber1024 round-3 — NOT FIPS-203 ML-KEM-768. For PQNoise use
     `clatter`, or combine `noise-protocol` + RustCrypto `ml-kem`.
   - `masque-go` / `quic-go` are Go — reference only for a Rust core.
   - quinn/rustls have NO ECH support (as of check date).
   - ML-KEM-768: pk=1184 B, ct=1088 B, ss=32 B (FIPS 203 Table 3).
   - Precedent: Warrenguard (Rust VPN over QUIC) needed custom quinn patches for BBR.
3. Output: dependency | claimed feature | actual status | drop-in alternative | effort if none.
4. No alternative exists → mark RESEARCH-GRADE, never "planned".
5. Write results to DEPENDENCIES.md.
```

## 2. anti-air-audit — GROUNDED/WEAK/AIR (дорогая модель)

`.agents/skills/anti-air-audit/SKILL.md`

```markdown
---
name: anti-air-audit
description: Audit design docs for hand-waved claims. Flags mechanisms described only at "what" level without a concrete "how". Use when reviewing architecture or protocol documents.
metadata:
  category: review
---

# Anti-Air Audit

## Instructions

Classify every claim: GROUNDED (concrete primitive/size/RFC/crate + full mechanism) |
WEAK (right ingredients, execution path unspecified) | AIR (outcome asserted, no mechanism).

Rules:
1. For every protocol step: what bytes are sent, who holds which key before/after,
   what state exists per side, what happens on failure/timeout.
2. For every dependency: stated version + confirmed feature match (run crate-feasibility facts).
3. For every performance figure: measurement context (HW, RTT, loss); flag cross-decade or
   cross-workload extrapolations.
4. For cross-server continuity claims (rotation, migration, failover): require the
   state-transfer mechanism (shared DB / consistent hashing / client-driven re-key /
   encrypted ticket). "No reset" without one = AIR.
5. For session-survival claims across transports: require the layer that owns the session
   to be independent of the transport. "Inner connection survives" without a
   transport-agnostic session layer = AIR.
6. Output: table claim | verdict | missing | concrete fix. Audit only — no fixes in this pass.
```

## 3. mechanism-drilldown — дожим одного механизма (дорогая модель)

`.agents/skills/mechanism-drilldown/SKILL.md`

```markdown
---
name: mechanism-drilldown
description: Deep-dive a single mechanism into an executable specification — message formats, key ownership, state layout, failure paths. Use when a review flagged a mechanism as WEAK or AIR.
metadata:
  category: design
---

# Mechanism Drilldown

## Instructions

For one mechanism produce:
1. Wire format: every message as a field table (field, size in bytes, who sets it).
2. Key/state table per party: before / during / after.
3. Sequence with error branches (timeout, wrong key, node down mid-switch).
4. Invariants + how each is enforced.
5. Compromis analysis: what breaks if any single key/party is compromised.
6. Prior art check: cite RFC/paper/project if someone solved this (e.g. TLS session
   tickets for stateless resumption, RFC 8446 §2.2).
If not specifiable to this level: declare RESEARCH-GRADE explicitly.
```

## 4. claim-traceability — цифры к источникам (дешёвая модель)

`.agents/skills/claim-traceability/SKILL.md`

```markdown
---
name: claim-traceability
description: Verify every quantitative and novelty claim in design docs traces to a cited source that actually says what is claimed. Final pass before publishing.
metadata:
  category: review
---

# Claim Traceability

## Instructions

1. Scan design/*.md for numbers, percentages, "first/unparalleled/novel" claims, RFC/FIPS numbers.
2. Locate cited source in research/*.md; verify it supports the claim AS STATED.
3. Flag upgrades: "2x in scenario X" presented as "30-50% everywhere".
4. Verify crypto parameters against primary standards, not blog summaries.
5. Label each claim ИЗМЕРЕНО (measured) / ГИПОТЕЗА (extrapolated) / ПРОЕКТНО (by design).
6. Novelty claim with no source mapping → flag for rewrite or removal.
```

## 5. phase0-scaffold — каркас из спеки (средняя модель)

`.agents/skills/phase0-scaffold/SKILL.md`

```markdown
---
name: phase0-scaffold
description: Generate a Rust workspace skeleton from 03-components.md — crates, trait files, stubs, failing contract tests. Use when starting implementation of a phase.
metadata:
  category: codegen
---

# Phase 0 Scaffold

## Instructions

1. Read 03-components.md (v2) + the target phase in 05-roadmap.md.
2. Generate Cargo workspace, one crate per module. Order matters:
   frame-session + crypto-core first (transport-independent, mock-testable);
   transport-mux next; morph-controller last.
3. Per crate: lib.rs with the spec's trait signatures, doc comments from In/Out/Deps,
   #[test] encoding the module contract that fails with todo!().
4. DEPENDENCIES.md: crate choices pinned, with feasibility status from crate-feasibility.
5. QUESTIONS.md: open design questions discovered — usually match WEAK/AIR audit items.
```

## 6. rotation-test-writer — тесты ротации, главный риск (средняя модель)

`.agents/skills/rotation-test-writer/SKILL.md`

```markdown
---
name: rotation-test-writer
description: Generate integration tests for session continuity across egress-node rotation, cover morphing, and key compromise scenarios. Use after implementing frame-session, key-coordinator, transport-mux.
metadata:
  category: testing
---

# Rotation & Continuity Tests

## Instructions

Generate integration tests against the spec in design/02-protocols.md:
1. Happy path: 3 streams, rotate N1->N2 by ticket; assert 0 lost records, seq continuity,
   duplicate-window closes within 1 RTT budget.
2. Epoch mismatch: N2 lacks the epoch key -> RESUME_NAK -> fallback full re-handshake,
   old channel still alive (make-before-break).
3. Forward secrecy: after post-rotation re-key, records are NOT decryptable with old
   K_session.
4. Morph path: switch QUIC binding -> Reality-mock binding mid-session; assert the
   frame session survives, no stream reset.
5. Node-down mid-rotation: teardown of N1 before RESUME_ACK; assert buffered records
   re-delivered via N2.
6. Replay: duplicate RESUME with same ticket is idempotent.
Tests use mock CoverBindings (trait objects), no real network in CI.
```

## 7. impl-phase-driver — оркестрация фазы end-to-end (дорогая модель)

`.agents/skills/impl-phase-driver/SKILL.md`

```markdown
---
name: impl-phase-driver
description: Drive one roadmap phase end-to-end — read the phase, scaffold, implement module by module, run tests, update roadmap checkboxes, write a phase report. Use when starting a new phase from 05-roadmap.md.
metadata:
  category: orchestration
---

# Implementation Phase Driver

## Instructions

For a given phase (e.g. "Phase 0"):
1. Read 05-roadmap.md phase items + 03-components.md module specs for those items.
2. If the workspace doesn't exist: run phase0-scaffold logic first.
3. Implement one module per iteration. After each module:
   a. cargo test (module contract must pass);
   b. cargo clippy -- -D warnings;
   c. commit with conventional message referencing the roadmap item.
4. Integration tests per rotation-test-writer when the phase includes session/rotation work.
5. Exit criteria check: every roadmap checkbox of the phase verified by a test or command,
   not by assertion. If an exit criterion cannot be met, STOP and write a BLOCKER note
   into QUESTIONS.md instead of silently weakening it.
6. Update 05-roadmap.md checkboxes [x] and append a phase report to docs/phase-reports/:
   what shipped, test evidence (commands + pass counts), deviations from spec and why,
   open questions.
7. Never modify design/02-protocols.md invariants during implementation without writing
   the proposed change to QUESTIONS.md first and flagging it as needing re-audit.
```

---

## Конвейер и экономия

```
crate-feasibility (cheap) → anti-air-audit (smart) → mechanism-drilldown (smart, только WEAK/AIR)
→ claim-traceability (cheap) → phase0-scaffold → [Phase 0.5] → impl-phase-driver по фазам
   └─ rotation-test-writer внутри фаз с сессионной логикой
```

1. Узкий интерфейс между шагами: следующий шаг читает только вывод предыдущего, не весь корпус.
2. Механика — дешёвой модели, рассуждения — дорогой. Скилл on-demand дешевле субагента.
3. Субагенты (если нужны для параллельных независимых проверок): минимальные toolNames,
   `includeMessageHistory: false`, `spawnableAgents: []`.
4. Каждый чекбокс roadmap закрывается тестом или командой, не формулировкой.
```
