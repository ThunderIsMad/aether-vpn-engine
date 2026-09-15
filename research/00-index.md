# Research Index — questions, sources, findings

This file is the map for the whole `research/` dossier. Every design claim in `../design/*` should
trace back to a source listed here.

## Research questions

1. **What do modern VPN / proxy engines actually look like internally?** (WireGuard, OpenVPN,
   mihomo/Clash.Meta, VLESS+Reality, Shadowsocks, Tor, Cloudflare WARP/MASQUE, SnowVPN)
2. **What is the current state of transport for censorship‑resistant tunneling?** (QUIC, MASQUE
   CONNECT‑UDP RFC 9298, Connect‑IP RFC 9484, 0‑RTT, connection migration, BBR)
3. **What is the post‑quantum (PQ) readiness of VPN crypto?** (ML‑KEM‑768 / FIPS 203, X25519MLKEM768
   hybrid, Noise + PQ, deployment reality)
4. **How does the DPI / obfuscation arms race look in 2025‑2026?** (ML traffic classification,
   generative‑diffusion obfuscation, active probing, Reality, uTLS)
5. **What architectural gaps exist that a *new* engine could fill?** → the `Aether` concept.

## Source map

### Web / vendor / RFC (detail in `02-current-articles.md`, `04`, `05`, `06`)
| Source | Type | Used for |
|--------|------|----------|
| cyberpath.net — "Post Quantum VPN: 11 Solutions Tested" (2025) | vendor benchmark | PQ VPN overhead, production readiness |
| postquantumsecurity.org — "X25519 to X25519+MLKEM768" (Mar 2026) | deep‑dive | hybrid KEM mechanics, sizes, drafts |
| blog.honus.top / XTLS Xray discussions / cyber‑vpn.net / hao.kim — VLESS+Reality guides (2025‑26) | community/operator | Reality current status, active‑probe resistance |
| RFC 9298 (MASQUE CONNECT‑UDP), RFC 9484 (Connect‑IP) | standard | camouflage transport |
| quic‑go/masque‑go, Cloudflare WARP MASQUE, usque (WARP reimpl) | OSS / vendor | MASQUE deployment reality |
| QuickQ / Tencent / Zhihu QUIC articles (2025‑26) | blog | 0‑RTT, no‑HOL, BBR |
| myrahmoun/VPN_Obfuscation_Project (RL), shabz0077/traffic‑evasion, FlowPaint (arXiv 2606.22717) | OSS / paper | adaptive obfuscation, generative evasion |
| SciDirect HINT (2025), MET‑LLM (2026) | paper | ML DPI that defeats HTTPS tunnels |

### Academic (arxiv) — detail + abstracts in `03-academic-papers.md`
| arXiv ID | Title | Relevance |
|----------|-------|-----------|
| 2608.00954 | NoisePQC++: NIST‑compliant PQC/Hybrid Noise | **Direct**: PQ control channel blueprint |
| 2002.05091 | QPEP: QUIC‑based encrypted PEP | QUIC tunneling perf evidence |
| 2509.23522 | Self‑Supervised + Confident Learning traffic classification | DPI arms race → motivates morphing |
| 2401.06657 | How Resilient is QUIC to Attacks? | QUIC privacy leaks + mitigations |
| 2506.11319 | HW‑Aware NAS for encrypted traffic classification on constrained devices | on‑device classifier feasibility |
| 2609.07849 | Nothing Breaks: No Single Peer Can Gate PQ Delivery | PQ deployment/governance |
| 2608.02147 | Measuring PQ TLS Deployment Across UK Sectors | PQ deployment reality |
| 2301.01124 | Privacy‑Preserving Tech under IETF Standardization | ECH/OHTTP/MASQUE context |
| 2102.07527 | Beyond QUIC v1 | QUIC evolution (DPLPMTUD, etc.) |
| 1605.04044 | Network Traffic Obfuscation & Automated Censorship | foundational obfuscation survey |

## Headline findings (the spine of the design)

- **Transport:** QUIC (RFC 9000) is the right substrate — 0‑RTT, migration, multiplexed streams,
  no HOL. MASQUE CONNECT‑UDP gives a standards‑based camouflage that already passes enterprise
  proxies (Cloudflare WARP ships it).
- **Crypto:** hybrid `X25519 + ML‑KEM‑768` is the consensus 2025‑26 direction (FIPS 203 + draft‑
  ietf‑tls‑ecdhe‑mlkem). Pure‑PQ is not yet recommended; hybrid protects against HNDL. Noise‑XX can
  carry the hybrid cleanly (NoisePQC++ proves it, minimal overhead).
- **Bypass:** the censor side is now ML‑driven (self‑supervised + confident learning beats SOTA at
  classifying encrypted/QUIC traffic). Static obfuscation (fixed Reality, fixed uTLS) is a losing
  game → **the novel bet is a client that detects the censor's classifier and morphs**.
- **Reliability gap:** hub‑and‑spoke engines (SnowVPN/mihomo) break long TLS when the egress IP
  rotates. A **stateless egress core** (session state at client) removes that failure mode.
- **Privacy gap:** most engines log or hold session state server‑side; stateless + PQ + ECH closes
  it.

→ These gaps are exactly what `Aether` (design/00) is built to fill.
