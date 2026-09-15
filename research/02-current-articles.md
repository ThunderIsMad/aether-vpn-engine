# Current Articles — notes & links (2025‑2026)

Web‑sourced material complementing the arxiv dossier (`03-academic-papers.md`). Links are kept so
claims are traceable.

## 1. Post‑Quantum VPN: 11 Solutions Tested (cyberpath.net, 2025)
- 6‑month enterprise eval of 11 PQ VPN products; top‑5 named: Quantum Guard Enterprise, CryptoShield
  Quantum, SecureLink PQC, QuantumNet Pro, FutureVPN Quantum.
- **Mechanism in use:** CRYSTALS‑Kyber (now ML‑KEM) **+ classical RSA/ECDH** KEM, CRYSTALS‑DILITHIUM
  signatures, hybrid TLS 1.2/1.3, algorithm‑negotiation. Warning: several products did "simple
  algorithm substitution" instead of true hybrid → should be avoided.
- **Overhead (benchmarked):** initial handshake +12–78 ms (typ. 15–45 ms); sustained latency <2 ms;
  bandwidth +10–20%; CPU +15–40%; memory +25–60% for key mgmt; throughput holds with HW crypto accel
  (+15–30%).
- **Takeaway:** hybrid PQ VPNs are production‑viable *for enterprises*; the dominant pattern is
  Kyber/ECDH hybrid, not pure PQ. → `Aether` uses the same hybrid principle but on the Noise control
  channel and with X25519 (not RSA) to keep handshake small.

## 2. X25519 → X25519+MLKEM768 (postquantumsecurity.org, Mar 2026)
- **Mechanics:** runs X25519 ECDH and ML‑KEM‑768 KEM **in parallel**, concatenates the two shared
  secrets into the TLS 1.3 key schedule. Attacker must break *both*.
- **Sizes:** client key share = 1184 (ML‑KEM pk) + 32 (X25519) = **1216 B** (38× the 32‑B X25519
  alone); server share = 1088 + 32 = 1120 B; shared secret 64 B.
- **Standards:** FIPS 203 (ML‑KEM‑768, Aug 2024, ex‑Kyber); **draft‑ietf‑tls‑ecdhe‑mlkem** defines
  named group `X25519MLKEM768`; BSI TR‑02102‑1 + NIST IR 8547 recommend hybrid as transitional best
  practice "through the 2030s."
- **Why hybrid, not pure PQ:** lattice crypto only studied since 2022; hybrid = belt‑and‑suspenders
  against HNDL (Harvest‑Now‑Decrypt‑Later) and any future ML‑KEM weakness. Main cost is **handshake
  size / brittle middleboxes**, not CPU.
- **Takeaway:** the canonical hybrid group for `Aether`'s control channel. The 1.2 KB share is fine
  inside QUIC (no TCP MSS issue) — another reason to prefer QUIC over TCP.

## 3. VLESS + Reality status (2025‑2026 operator guides)
- honus.top (Jul 2025): older WS/TLS paths now "precisely identified" → moved to VLESS+Reality as
  "most stable." Confirms Reality is the current community gold standard for evasion.
- XTLS Xray discussion #5384 (Dec 2025): notes clients still catching up to `vless+vision+xhttp+
  reality`; fragmented client support is a real ops risk → argues for a *single, well‑tested core*
  (i.e., not bolting Reality onto a half‑supported client).
- cyber‑vpn.net (Mar 2026) / hao.kim (Jul 2026): Reality "revolutionary" but success depends on a
  *trustworthy, naturally cert‑rotating target*; pure passive fingerprinting fails, active probing
  mostly fails. → validates Reality as a Liquid Tunnel morph state, with the caveat that the target
  must be curated.

## 4. MASQUE / WARP deployment
- RFC 9298 (MASQUE CONNECT‑UDP) + RFC 9484 (Connect‑IP) are the standards. quic‑go/masque‑go is a
  working RFC 9298 impl on QUIC. Apple exposes `NetworkProxyConfiguration` (MASQUE) in Device
  Management (2026) → platforms are standardizing on it.
- Cloudflare WARP ships MASQUE in production (blogs 51cto, csdn, macin.top 2024‑2026): fixes "stuck
  connecting / random disconnects," improves speed/stability via QUIC multiplexing. `usque` is an OSS
  reimplementation of WARP's MASQUE (Connect‑IP) mode.
- **Takeaway:** MASQUE is the *enterprise‑acceptable* camouflage — censors that whitelist QUIC/HTTP3
  let it through. `Aether` uses it as a morph state and as the default corporate‑network mode.

## 5. QUIC 0‑RTT / multiplexing / BBR (2025‑2026)
- Tencent cloud, QuickQ, Zhihu pieces: QUIC carries many independent streams over one connection →
  **no head‑of‑line blocking** (a lost packet blocks only its stream); 0‑RTT resume; connection
  migration (client IP/port change → same connection); BBR congestion control.
- A CN 2025 slide deck "The QUIC Transport Protocol: Design and Internet‑Scale…" notes QUIC already
  rivals/beats parallel TCP for video; "VPN tunnel multiplexing over QUIC + 0‑RTT" (idocdown, Jun
  2026) describes exactly the in‑tunnel stream model `Aether` uses.
- **Takeaway:** QUIC is the transport substrate. 0‑RTT + migration are the lever for `Aether`'s
  "instant reconnect / seamless handoff" reliability claims.

## 6. Adaptive obfuscation / generative evasion (2025‑2026)
- myrahmoun/VPN_Obfuscation_Project (May 2025): a **reinforcement‑learning** environment that learns
  to obfuscate VPN traffic against a DPI — the censor and the obfuscator co‑evolve. This is the
  *research* seed for `Aether`'s Liquid Tunnel (but they train offline; `Aether` classifies the
  censor online and morphs).
- shabz0077/traffic‑evasion (Jan 2026): lab simulating ISP DPI to measure evasion effectiveness.
- **FlowPaint** (arXiv 2606.22717, Jun 2026): *generative diffusion* model produces "one‑prompt
  censorship evasion" traffic — i.e., synthesize cover traffic on demand. → directly informs
  `Aether`'s App Mirage cover‑traffic generator (subset of that idea, app‑fingerprint‑locked).

## 7. ML DPI that defeats encrypted tunnels
- SciDirect HINT (Feb 2025): turns HTTPS‑tunnel detection into a **graph‑node** problem, beating prior
  detectors. MET‑LLM (Mar 2026): LLMs for malicious encrypted‑traffic detection.
- **Takeaway:** the censor is now ML‑grade. Static covers lose. This is the core motivation for the
  Liquid Tunnel's *adaptive* morphing (detect the classifier, change the cover).
