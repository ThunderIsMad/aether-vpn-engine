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
