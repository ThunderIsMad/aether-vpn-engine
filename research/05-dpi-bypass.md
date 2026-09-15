# DPI / obfuscation arms‑race research (the problem Liquid Tunnel solves)

## The censor side is now ML‑grade
- **Self‑supervised + Confident Learning** (2509.23522, 2025) classifies encrypted **and QUIC**
  traffic **better than SOTA** with little labeled data, on ISCX VPN‑nonVPN + UCDavis‑QUIC datasets.
- **Hardware‑Aware NAS** (2506.11319) runs such classifiers on **resource‑constrained / edge**
  devices → censors can run them cheaply, at line rate.
- **HINT** (SciDirect 2025) turns HTTPS‑tunnel detection into a graph problem; **MET‑LLM** (2026)
  applies LLMs to encrypted‑traffic detection.
- **Implication:** passive byte/length fingerprinting is now augmented by *behavioral + ML* detection.
  A fixed cover (fixed Reality, fixed uTLS, fixed SS) is a **sitting duck** once the censor trains.

## The evasion toolbox (what exists)
| Technique | How | Status vs ML DPI |
|-----------|-----|------------------|
| VLESS + Reality (xtls‑rprx‑vision) | borrow a real site's TLS (SNI+cert), zero‑copy splice | Strong vs passive; drifts if target changes; **fixed profile** |
| uTLS / fake ClientHello | mimic a real browser's TLS fingerprint | Good vs JA3‑style; ML catches statistical drift |
| TLS fragmentation / padding | break signatures | Easily learned; breaks some middleboxes |
| MASQUE CONNECT‑UDP (RFC 9298) | look like HTTP/3 proxy traffic | Passes QUIC‑whitelisting censors; **fixed profile** |
| Domain fronting | hide behind CDN | Broken by most CDNs now |
| obfs4 / meek (Tor) | random padding / domain fronting | Increasingly fingerprinted |
| Active‑probe resistance | never respond to unknown probes | Reality has it; essential |
| RL obfuscation (myrahmoun, 2025) | learn to evade a DPI offline | Research only |
| Generative diffusion (FlowPaint 2606.22717) | synthesize evasion traffic on demand | Research only |

## The gap: nobody morphs *online* against the censor's own classifier
- RL/generative work trains **offline** against a *proxy* DPI. In the field the censor's classifier is
  a moving target and differs by region/ISP.
- **`Aether`'s bet (Liquid Tunnel):** put a *tiny* on‑device classifier (2506.11319‑class) on the
  client that watches the *uplink* for signs it is being fingerprinted (probe rate, RST/block
  patterns, latency cliffs), infers *which* cover class still passes, and **hot‑swaps the wire format**
  among a library of covers (Reality / MASQUE / raw‑QUIC+ECH / app‑mimic). The censor's classifier
  becomes the *input* to the morpher. This is the unparalleled part.

## Cover library the morph picks from
1. **Reality** (VLESS + xtls‑rprx‑vision) — best general evasion.
2. **MASQUE CONNECT‑UDP** — best behind corporate/QUIC‑whitelisting networks.
3. **raw QUIC + ECH** — best where HTTP/3 is normal traffic.
4. **App Mirage** — synthesize a cover that mimics a popular app's TLS (YouTube/Netflix/WhatsApp)
   using FlowPaint‑style generation, defeating *statistical* ML DPI (0250.23522 class).
5. **Plain obfuscated** (SS‑2022 / padded) — fallback for low‑security networks.

## Active‑probe resistance (non‑negotiable)
- The morph state + the static core must **never answer** an unauthenticated probe (Reality‑style):
  only a client holding the subscription UUID + session key gets a response. This stops the censor from
  enumerating nodes.

## References
- 2509.23522, 2506.11319, 2401.06657 (03); HINT/MET‑LLM (02 §7); FlowPaint 2606.22717 (03 bonus);
  Reality guides (02 §3); obfs4/meek background (1605.04044, 03).
