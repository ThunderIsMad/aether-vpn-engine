# Post‑Quantum Cryptography research (for the VPN engine)

## Why PQ at all
- **Harvest‑Now‑Decrypt‑Later (HNDL):** an adversary records today's VPN traffic and decrypts it once
  a CRQC (cryptographically relevant quantum computer) exists. Classical ECDH (X25519/Curve25519) falls
  to Shor's algorithm. → a *modern* engine must be PQ‑safe from day one.

## The algorithm: ML‑KEM‑768 (FIPS 203)
- Standardized Aug 2024 as **ML‑KEM** (ex CRYSTALS‑Kyber), lattice‑based (MLWE). 768 = security level
  ~AES‑192 equivalent. Conservative, widely reviewed, hardware‑accelerated paths exist.

## The pattern: hybrid, not pure PQ
- **Consensus (2025‑26):** run classical **X25519** + **ML‑KEM‑768** together; concatenate secrets.
  Secure as long as *either* survives. Pure‑PQ is explicitly *not* yet recommended (lattice crypto only
  studied since 2022; brittle middleboxes choke on the larger handshake).
- Named group **`X25519MLKEM768`** (draft‑ietf‑tls‑ecdhe‑mlkem). Client share ≈ 1216 B, server ≈
  1120 B (see 02 §2). BSI + NIST IR 8547 endorse hybrid "through the 2030s."

## Where it goes in `Aether`
- **Control channel (Noise‑XX):** carry the hybrid in the Noise XX handshake. NoisePQC++ (2608.00954)
  proves Noise + ML‑KEM + hybrid works with *minimal overhead* and supports all patterns → `Aether`
  uses **Noise_XX with `X25519MLKEM768`** for the live control/key‑establishment channel.
- **Data plane:** once the hybrid establishes keys, use **XChaCha20‑Poly1305** (AEAD) for bulk. (Wide
  nonce, no nonce‑reuse footgun, fast in software — better than AES‑GCM on devices without AES‑NI.)
- **Crypto‑agility:** the KEM is a named, swappable parameter (per 2609.07849 — no single party gates
  PQ). If ML‑KEM is weakened, drop to X25519‑only or upgrade to ML‑KEM‑1024 without a protocol break.

## Performance budget (from real benchmarks)
| Cost | Magnitude | Mitigation in `Aether` |
|------|-----------|------------------------|
| Handshake size | +~1.2 KB (client) | carried in QUIC Initial (no TCP MSS split); fragmented if needed |
| Handshake latency | +12–78 ms (typ. 15–45) | amortized by 0‑RTT + session resumption |
| Bandwidth | +10–20% | negligible vs proxy overhead |
| CPU | +15–40% | ML‑KEM is cheap; HW accel optional |
| Memory (key mgmt) | +25–60% | client‑side only; small constant per session |

## Signature / auth
- Node auth: hybrid cert chain or Noise static‑key (X25519 + Dilithium‑less for now; Dilithium optional
  later). Subscription UUID + per‑session ephemeral key = client identity (stateless).

## References
- FIPS 203 (ML‑KEM), Aug 2024.
- draft‑ietf‑tls‑ecdhe‑mlkem (X25519MLKEM768).
- postquantumsecurity.org X25519+MLKEM768 (2026) — 02 §2.
- cyberpath.net PQ VPN 11 tested (2025) — 02 §1.
- NoisePQC++ 2608.00954 — 03.
