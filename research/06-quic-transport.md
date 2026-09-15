# QUIC + MASQUE transport research (the substrate)

## Why QUIC (RFC 9000) and not TCP
- **0‑RTT:** resume a session and send data in the first packet (after a prior handshake). → instant
  reconnect for `Aether`.
- **Connection migration:** client changes IP/port (WiFi→cellular) and the connection survives (new
  path challenge). → seamless handoff, no session drop.
- **Multiplexed streams, no head‑of‑line blocking:** one lost packet blocks only its stream, not all
  traffic. → `Aether` maps each app flow / routed rule to a QUIC stream.
- **BBR congestion control** + pluggable CC → good over lossy mobile links.
- **Built‑in encryption** (TLS 1.3) and a single encrypted handshake.
- **Evidence (QPEP, 2002.05091):** QUIC tunneling was **>2× faster** than traditional customer VPN
  page loads and −30% vs unencrypted PEP. (See 03.)

## MASQUE — standards‑track camouflage (RFC 9298 / 9484)
- **CONNECT‑UDP (RFC 9298):** proxy UDP inside HTTP/3 (QUIC) — i.e., tunnel IP/UDP as if it were a
  normal HTTP/3 proxy session. Censors that whitelist QUIC/HTTP3 let it pass.
- **Connect‑IP (RFC 9484):** proxy full IP packets (the real VPN mode); `usque` reimplements WARP's
  Connect‑IP.
- **quic‑go/masque‑go** is a working RFC 9298 impl → `Aether` can build its MASQUE morph state on it.
- **Apple** exposes MASQUE in DeviceManagement (2026) → native platform hook on macOS/iOS.

## QUIC privacy/security caveats (2401.06657) — what `Aether` must defend
- **Connection‑ID correlation:** fixed CID lets observers link flows; rotate CIDs + encrypt them.
- **Migration privacy:** new‑path validation can leak; use address‑validation tokens carefully.
- **0‑RTT replay:** don't send non‑idempotent control on 0‑RTT; cache‑break for data.
- **PQC handshake expansion:** the ~1.2 KB hybrid share can trip middleboxes → pad/Fragment inside QUIC
  Initial; QUIC has no TCP MSS problem so this is manageable.
- **Metadata leakage:** pair with **ECH** (Encrypted Client Hello) + **OHTTP** where applicable
  (2301.01124, 2401.06657).

## QUIC evolution to adopt (2102.07527, 2401.06657)
- **Multipath QUIC** → even better migration (simultaneous WiFi+cellular).
- **DPLPMTUD** → safe large datagrams for the tunnel.
- **ACK frequency / QUIC datagram** → low‑latency control messages for the Noise channel.

## How `Aether` uses it
- Single **QUIC connection** carries everything: a **Noise‑XX control stream** (hybrid PQ key mgmt +
  live control), and **data streams** (one per routed flow / app). MASQUE CONNECT‑UDP is one *morph
  state* of the outer encapsulation; raw QUIC+ECH another; Reality another. 0‑RTT + migration give the
  reliability story; multiplexing gives the performance story.
