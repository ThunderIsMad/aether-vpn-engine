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
