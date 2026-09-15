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
