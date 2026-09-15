# Academic Papers (arxiv) — abstracts + relevance

Retrieved via the arxiv API (cs.NI / cs.CR), Aug–Sep 2026 sweep. Each entry: what it says and why it
matters for `Aether`.

## 2608.00954 — NoisePQC++: A Unified NIST‑Compliant PQC and Hybrid‑PQC Implementation of the Noise Protocol
- **Authors:** N. Ahmed, A. Gangopadhyay, L. Zhang · **Date:** 2 Aug 2026 · IEEE QCE 2026.
- **Abstract (paraphrased):** Extends the Noise Protocol Framework (used by WireGuard, WhatsApp) with
  NIST‑standardized ML‑KEM alongside classical ECDH, giving full‑PQ, hybrid ECDH+PQC handshakes, and
  support for all 57 classical Noise patterns + 13 PQ + hybrids. Evaluation: minimal overhead normally,
  acceptable under stress, strong quantum resistance.
- **Relevance:** ⭐ **Direct blueprint.** `Aether`'s control channel uses **Noise‑XX hybrid
  (X25519 + ML‑KEM‑768)** exactly as NoisePQC++ demonstrates. Proves the overhead is negligible.

## 2002.05091 — QPEP: A QUIC‑Based Approach to Encrypted Performance Enhancing Proxies
- **Authors:** J. Pavur, M. Strohmeier, V. Lenders, I. Martinovic · **Date:** 12 Feb 2020.
- **Abstract:** Open‑source encrypted‑by‑default PEP built on QUIC, adoptable without the ISP. Vs
  unencrypted PEP: **−30% page‑load time** + over‑the‑air privacy. Vs traditional customer VPN
  encryption: **>2× faster page loads**.
- **Relevance:** Quantitative evidence that **QUIC tunneling beats TCP VPNs** on latency — underpins
  `Aether`'s "30–50% faster than TCP VPN" performance claim and its QUIC‑native transport choice.

## 2509.23522 — Network Traffic Classification Using Self‑Supervised Learning and Confident Learning
- **Authors:** E. Eslami, W. Hamouda · **Date:** 27 Sep 2025.
- **Abstract:** Self‑Supervised Learning (autoencoders / Tabular Contrastive) generates pseudo‑labels
  from unlabeled flows; Confident Learning refines them. Tested on ISCX VPN‑nonVPN, UCDavis‑QUIC.
  **Beats SOTA** while needing little labeled data.
- **Relevance:** Shows ML DPI now classifies **encrypted AND QUIC** traffic accurately with little
  supervision. This is the threat `Aether`'s Liquid Tunnel must defeat → morphing must outrun a
  self‑supervised classifier. (See also 2506.11319 for on‑device feasibility.)

## 2401.06657 — How Resilient is QUIC to Security and Privacy Attacks? (v3, Jul 2025)
- **Authors:** Sengupta, Dey, Ferlin‑Reiter, Ghosh, Bajpai.
- **Abstract:** Systematizes QUIC attacks — esp. during connection setup and via traffic analysis —
  and reviews IETF mitigations (ECH, OHTTP, MASQUE). Flags PQC handshake expansion & metadata leakage
  as new risks; calls for **adaptive privacy mechanisms**.
- **Relevance:** The "adaptive privacy" call‑out validates `Aether`'s design thesis. Also a checklist
  of QUIC leaks to defend: Connection‑ID correlation, migration privacy, 0‑RTT replay, PQC handshake
  bloat. `Aether`'s TransportMux + TelemetryGuard address these.

## 2506.11319 — Hardware‑Aware NAS for Encrypted Traffic Classification on Resource‑Constrained Devices
- **Date:** 12 Jun 2025.
- **Abstract:** Neural‑architecture‑search tailored to run encrypted‑traffic classification on
  weak/edge devices.
- **Relevance:** Proves a **tiny on‑device DPI classifier is feasible** — exactly what Liquid Tunnel's
  MorphController needs to run client‑side without burning battery. Sizes the classifier model budget.

## 2609.07849 — Nothing Breaks: No Single Peer Can Soundly Gate Post‑Quantum Delivery
- **Date:** 7 Sep 2026. · **Relevance:** PQ deployment/governance — argues no single party should be
  able to block PQ rollout. Informs `Aether`'s crypto‑agility (ability to drop/upgrade KEMs without a
  protocol break).

## 2608.02147 — Measuring Post‑Quantum TLS Deployment Across UK Internet Sectors
- **Date:** 3 Aug 2026. · **Relevance:** Real‑world PQ TLS adoption is still low/uneven → `Aether`
  should not assume the *egress* supports PQ; hybrid + client‑held state keeps it safe regardless.

## 2301.01124 — Recent Trends on Privacy‑Preserving Technologies under Standardization at the IETF
- **Date:** 3 Jan 2023. · **Relevance:** Context for ECH / OHTTP / MASQUE as the standardized privacy
  toolkit `Aether` leans on.

## 2102.07527 — Beyond QUIC v1: A First Look at Recent Transport Layer IETF Standardization
- **Date:** 15 Feb 2021. · **Relevance:** QUIC evolution (DPLPMTUD, multipath, ACK frequency) —
  roadmap items `Aether` can adopt (multipath QUIC = even better migration/handoff).

## 1605.04044 — Network Traffic Obfuscation and Automated Internet Censorship
- **Date:** 13 May 2016. · **Relevance:** Foundational survey of obfuscation (format‑transforming
  encryption, decoy routing, morphing). The intellectual ancestry of App Mirage + Liquid Tunnel.

## Bonus (web, not arxiv)
- **FlowPaint** arXiv 2606.22717 (Jun 2026) — generative‑diffusion censorship evasion (see 02‑current‑
  articles §6). Feeds App Mirage's cover‑synthesis idea.
