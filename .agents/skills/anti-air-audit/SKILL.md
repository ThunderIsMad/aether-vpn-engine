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
