# Aether — архитектура компонентов и потока данных (v2)

## Слоистая архитектура

```mermaid
flowchart TB
  subgraph Device["Client device"]
    APP[Apps / OS routing]
    TUN[DeviceAdapter<br/>TUN / WFP / NetworkExtension]
    POL[PolicyEngine<br/>routing / fake-ip DNS]
    MORPH[MorphController<br/>Liquid Tunnel FSM + on-device DPI classifier]
    FS[FrameSession<br/>cover-agnostic record protocol<br/>stream table + seq + re-key]
    CRYPTO[CryptoCore<br/>Noise-XX hybrid PQ + XChaCha20-Poly1305]
    COVER[CoverEngine<br/>App Mirage decoy synth]
    TM[TransportMux<br/>QUIC / MASQUE / Reality bindings]
    SC[SessionStore<br/>ключed (sub,UUID,sid) + tickets]
    KEYM[KeyCoordinator<br/>fleet epoch keys + ticket mint]
    TG[TelemetryGuard<br/>opt-in метрики]
  end

  APP --> TUN --> POL
  POL --> FS
  MORPH --> TM
  FS --> CRYPTO
  FS --> TM
  CRYPTO --> FS
  COVER --> TM
  SC -.-> FS
  KEYM -.tickets.-> SC
  TG -.opt-in.-> MORPH

  subgraph Mesh["Federated Egress Mesh (stateless)"]
    N1[Egress node A<br/>+ epoch key]
    N2[Egress node B<br/>+ epoch key]
    N3[Egress node C]
  end
  TM <===>|binding: активная обложка| N1
  TM <===>|ticket resume, make-before-break| N2
  N1 -.optional hop.-> N3
  N1 --> NET((Internet))
  N2 --> NET
```

Ключевое отличие v1: **FrameSession** — отдельный слой между PolicyEngine и транспортами.
Именно он (а не «inner QUIC») — то, что переживает морфинг обложки и ротацию узла.

## Установление сессии и ротация (ticket-based)

```mermaid
sequenceDiagram
  participant C as Client
  participant N1 as Node A
  participant N2 as Node B
  Note over C,N1: 1) Outer QUIC (standard TLS) к N1
  Note over C,N1: 2) Noise-XX hybrid на control-стриме<br/>(X25519MLKEM768: клиент 32+1184 B, сервер 32+1088 B)
  C->>N1: handshake -> K_session, session-id
  C->>N1: [опционально] N1 минтит ticket = AEAD(TFK_epoch, {sid, K_session, exp})
  Note over C,N2: 3) Ротация (make-before-break)
  C->>N2: outer QUIC к N2 (новая обложка допустима)
  C->>N2: Resume { ticket, last_seq }
  N2->>C: ResumeAck { continuity_point }
  Note over C: frame-слой продолжает с last_seq;<br/>дублирует записи на оба канала до ACK
  C->>N1: teardown старого outer после подтверждения
  Note over C,N2: 4) Post-rotation re-key (forward secrecy):<br/>K_session' = HKDF(K_session, "rotate", eph_N2)
```

## Поток данных (пакет → байты)

1. Приложение шлёт пакет → **DeviceAdapter** захватывает (TUN / WFP / utun).
2. **PolicyEngine** решает: route / fake-ip / block.
3. Поток получает `stream_id` в **FrameSession** — таблица потоков живёт на клиенте.
4. **CryptoCore** запечатывает record (`XChaCha20-Poly1305`, per-record nonce).
5. **MorphController** определяет активную обложку (FSM, `02-protocols §4`); **CoverEngine**
   опционально добавляет декой-трафик.
6. **TransportMux** биндит records к активному транспорту:
   - QUIC-байндинг: `stream_id` ↔ QUIC stream (no-HOL бесплатно);
   - MASQUE-байндинг: records как UDP-полезная нагрузка CONNECT-UDP;
   - Reality/TCP-байндинг: length-prefixed frames поверх сплайснутого TLS (HOL — tradeoff, см. `02 §2.2`).
7. Egress-узел терминирует байндинг, восстанавливает FrameSession из ticket при ротации,
   форвардит в интернет. Серверного per-session state нет.
8. **TelemetryGuard** — opt-in, без payload/destinations/identities.

## Почему эта схема корректна (ответ на аудит v1)

- **Морфинг не рвёт сессию** потому, что сессия — это FrameSession (ключи, stream table, seq),
  а не транспортное соединение. Смена обложки = смена байндинга; overlap-window дублирует
  records на старый+новый каналы до подтверждения (границы оверхеда — `02 §5`).
- **Ротация без серверного state** потому, что узел восстанавливает сессию из ticket,
  завернутого под fleet-epoch ключом (паттерн TLS session tickets, RFC 8446 §2.2).
  Компромисс (epoch-key компромет exposes сессии эпохи) задокументирован и смягчён
  короткими эпохами + post-rotation re-key (`02 §3`).
- **PQ-семантика честная**: гибрид защищает сессию (payload); outer QUIC handshake —
  стандартный TLS 1.3 (классический), его роль — только транспорт. HNDL-безопасность
  касается записей frame-слоя, зашифрованных ключами из Noise-XX гибрида.
