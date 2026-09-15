---
name: phase0-scaffold
description: Generate a Rust workspace skeleton from design/03-components.md — crates, trait files, stubs, failing contract tests. Use when starting implementation of a phase.
metadata:
  category: codegen
---

# Phase 0 Scaffold

## Instructions

1. Read design/03-components.md (v2) + the target phase in design/05-roadmap.md.
2. Generate Cargo workspace, one crate per module. Order matters:
   frame-session + crypto-core first (transport-independent, mock-testable);
   transport-mux next; morph-controller last.
3. Per crate: lib.rs with the spec's trait signatures, doc comments from In/Out/Deps,
   #[test] encoding the module contract that fails with todo!().
4. DEPENDENCIES.md: crate choices pinned, with feasibility status from crate-feasibility.
5. QUESTIONS.md: open design questions discovered — usually match WEAK/AIR audit items.
