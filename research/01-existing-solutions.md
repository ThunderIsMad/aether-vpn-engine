# Existing Solutions — architectural analysis

A baseline of what ships today, what each is good at, and where it is weak. This is the "analyze
modern architectural approaches and existing solutions" input to the design.

## 1. WireGuard
- **Architecture:** minimal UDP datagram VPN; single `Noise_IK` handshake (Curve25519 + ChaCha20/
  Poly1305 or AES‑GCM); cryptokey routing (public key = tunnel identity + allowed IPs). ~4000 LOC.
- **Strengths:** auditable, fast, silent‑by‑default, great MTU/keepalive model, built into Linux/
  macOS/Windows kernels.
- **Weaknesses:** no built‑in obfuscation (trivially fingerprinted as WireGuard by DPI); no
  dynamic egress/rotation story; no application‑level routing; static keys → poor for subscription
  models; handshake is classical ECDH only (not PQ).
- **Verdict:** best *trusted‑network* VPN; weakest for censorship resistance.

## 2. OpenVPN / IPsec
- **Architecture:** TLS (OpenVPN) or IKEv2 (IPsec) control + CBC/GCM data; TCP or UDP mode.
- **Strengths:** ubiquitous, enterprise‑trusted, configurable.
- **Weaknesses:** TCP‑over‑TCP meltdown under loss; large attack surface (OpenSSL); easy to fingerprint;
  no PQ by default; poor mobile handoff.
- **Verdict:** legacy; not a candidate for a modern engine.

## 3. mihomo / Clash.Meta (the core under SnowVPN)
- **Architecture:** rule‑based proxy core. Inbound `mixed-port` (SOCKS+HTTP), TUN mode; outbound
  protocols **VLESS / Trojan / Shadowsocks‑2022 / VMess**, transports **TLS / WebSocket / gRPC /
  QUIC / H2**, with **VLESS+Reality** (xtls‑rprx‑vision) as the flagship anti‑DPI option. `fake‑ip`
  DNS (198.18.0.0/16), external‑controller API, rule providers.
- **Strengths:** extremely flexible routing; Reality gives genuine TLS‑in‑TLS camouflage that
  survives most DPI; huge protocol/transport menu.
- **Weaknesses (the gaps `Aether` targets):**
  - **Egress rotation breaks sessions** — session state is effectively tied to the egress IP; when
    the subscription rotates the outbound node, long TLS connections stall. (This was the concrete
    SnowVPN bug observed in prior work.)
  - **No post‑quantum crypto** anywhere in the handshake/data plane.
  - **Static camouflage** — Reality/uTLS is fixed per config; once a censor trains a classifier it
    keeps working. No live morphing.
  - **Stateful core** — controller + conn‑track live server‑side; not stateless.
- **Verdict:** the best *current*Anti‑DPI toolkit, but architecturally 2019‑era (hub‑and‑spoke,
  classical crypto, static obfuscation). `Aether` borrows its protocol menu but re‑architects the
  core.

## 4. VLESS + Reality (xtls‑rprx‑vision)
- **Architecture:** VLESS is a lightweight proxy protocol; **Reality** borrows TLS from a *real*
  target site (SNI + certificate) so the proxy looks like ordinary traffic to that site, with no
  cần self‑signed cert. `xtls‑rprx‑vision` splices the real target's TLS record stream into the
  proxy stream (zero‑copy), so payload bytes ride inside legitimate‑looking TLS.
- **Strengths:** currently the strongest *practical* DPI evasion; resistant to passive fingerprinting
  and most active probing (the proxy presents as a normal client to a normal server).
- **Weaknesses:** requires a reachable, trustworthy "target" site; fingerprint can drift if the
  target changes; fixed profile (no morphing); classical crypto; single‑hop.
- **Verdict:** `Aether`'s **Reality cover** is one of the Liquid Tunnel morph states.

## 5. Shadowsocks / Shadowsocks‑2022
- **Architecture:** simple AEAD stream cipher (2022 adds AEAD‑2022, UDP, and a PSK roster).
- **Strengths:** light, fast, widely deployed; 2022 closes many old leaks.
- **Weaknesses:** detectable by ML (fixed cipher + length distribution); no PQ; no camouflage.
- **Verdict:** a cover option, not a core.

## 6. Tor
- **Architecture:** onion routing, 3 hops, TLS between relays, fixed relay set, pluggable transports
  (obfs4, meek) for censorship.
- **Strengths:** strongest anonymity (entry/exit separation), battle‑tested, PQ‑curious research.
- **Weaknesses:** high latency (3 TLS hops + relay congestion), no QUIC, obfs4 is increasingly
  fingerprinted, no PQ in production, no app‑level routing.
- **Verdict:** `Aether`'s **Federated Egress Mesh** borrows the multi‑hop topology but runs it over
  QUIC + PQ for an order‑of‑magnitude latency cut.

## 7. Cloudflare WARP / MASQUE
- **Architecture:** client → Cloudflare edge over **MASQUE CONNECT‑UDP (RFC 9298)** / Connect‑IP
  (RFC 9484) on top of QUIC; the edge does the egress. `usque` is an OSS reimplementation of WARP's
  MASQUE mode.
- **Strengths:** MASQUE is a *standards‑track* camouflage that sails through corporate proxies and
  censors that whitelist QUIC/HTTP3; QUIC gives 0‑RTT + migration; Cloudflare proves it at planet scale.
- **Weaknesses:** centralized (you trust Cloudflare); no PQ; no morphing; not a generic engine.
- **Verdict:** `Aether`'s **MASQUE cover** is a second Liquid Tunnel morph state, and the QUIC
  transport model is the template.

## 8. Outline (Shadowsocks‑based)
- **Architecture:** managed Shadowsocks server + client.
- **Strengths:** dead‑simple deploy for at‑risk users.
- **Weaknesses:** SS fingerprinting; centralized server; no PQ/morphing.
- **Verdict:** inspiration for the subscription/onboarding model only.

## 9. SnowVPN (the user's installed client)
- **Architecture:** **UI skin over mihomo/Clash.Meta** — VLESS/TLS/WS/gRPC, Trojan, SS‑2022;
  fake‑ip 198.18.0.0/16; mixed‑port 7897; empty external‑controller; DPAPI‑stored secrets.
- **Strengths:** friendly UI on top of mihomo's protocol menu.
- **Weaknesses:** **inherits every mihomo gap above**, notably the **egress‑IP rotation bug** that
  drops long TLS when the subscription rotates the outbound node.
- **Verdict:** the concrete pain point that motivated the Stateless Egress Core in `Aether`.

## Synthesis → the gaps an engine can own
| Gap | Who has it | `Aether` answer |
|-----|-----------|-----------------|
| Live, ML‑driven protocol morphing | nobody shipping | **Liquid Tunnel** |
| Stateless egress (rotation‑safe) | nobody | **Stateless Egress Core** |
| PQ on both planes | nobody (research only) | **X25519MLKEM768 + Noise‑XX** |
| Multi‑hop mesh w/ QUIC perf + PQ | nobody | **Federated Egress Mesh** |
| App‑fingerprint cover traffic | nobody | **App Mirage** |
| QUIC‑native, 0‑RTT, migration, no‑HOL | WARP only (centralized) | core transport |
