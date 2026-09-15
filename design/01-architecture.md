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
    CRYPTO[CryptoCore<br/>Noise_IK hybrid PQ + XChaCha20-Poly1305]
    COVER[CoverEngine<br/>App Mirage decoy synth]
    TM[TransportMux<br/>QUIC / MASQUE / Reality bindings]
    SC[SessionStore<br/>keyed (sub,UUID,sid) + tickets]
    KEYM[KeyCoordinator<br/>ticket store + PoP sign<br/>no mint, no epoch keys]
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

  subgraph Mesh["Federated Egress Mesh (no state across rotation)"]
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
  Note over C,N1: 2) Noise_IK hybrid на control-стриме<br/>(X25519MLKEM768: клиент 32+1184 B, сервер 32+1088 B)<br/>IK: статик узла из манифеста, статик клиента — в msg1
  C->>N1: handshake -> K_session, session-id (cryptokey routing)
  C->>N1: MINT_REQ -> N1 минтит ticket = AEAD(TFK_epoch, {sid, K_session, client_auth_pub, window, exp})
  Note over C,N2: 3) Ротация (make-before-break), 1 RTT
  C->>N2: outer QUIC к N2 (новая обложка допустима)
  C->>N2: ticket_blob ‖ sealed{K_resume}{last_seq, window, eph_client, nonce, sig_client}
  Note over N2: unwrap ticket флотским TFK_epoch;<br/>проверка sig_client по client_auth_pub;<br/>consumed-set: повтор -> RESUME_NAK replay
  N2->>C: sealed{K_resume}{continuity_point, window, eph_node, sig_node}
  Note over C: frame-слой продолжает с last_seq;<br/>дублирует записи на оба канала до валидного ACK<br/>(T_morph = 2×SRTT, N ≤ 4096)
  C->>N1: teardown старого outer после подтверждения
  Note over C,N2: 4) Post-rotation re-key (forward secrecy):<br/>K_session' = HKDF(DH(eph_client, eph_node) ‖ K_session)
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
7. Egress-узел терминирует байндинг, при ротации разворачивает ticket флотским `TFK_epoch`,
   проверяет PoP-подпись клиента и попадает в consumed-set, восстанавливает FrameSession,
   форвардит в интернет. Состояния, переживающего ротацию, нет; на время сессии узел
   держит in-memory окно дедупликации (4096) и consumed-set эпохи.
8. **TelemetryGuard** — opt-in, без payload/destinations/identities.

## Почему эта схема корректна (ответ на аудит v1)

- **Морфинг не рвёт сессию** потому, что сессия — это FrameSession (ключи, stream table, seq),
  а не транспортное соединение. Смена обложки = смена байндинга; overlap-window дублирует
  records на старый+новый каналы до подтверждения, таймер и бюджет окна — за FrameSession
  (`02 §4`); исчерпание бюджета даёт MorphFailed и откат, не разрыв сессии.
- **Ротация без состояния, переживающего ротацию**, потому что узел восстанавливает сессию из ticket,
  завернутого под fleet-epoch ключом (паттерн TLS session tickets, RFC 8446 §2.2). Ticket не даёт
  сессии сам по себе: резюм проходит только с PoP-подписью клиента (`02 §3.3`).
  Компромисс (компрометация epoch-ключа вскрывает сессии эпохи) — задокументированный tradeoff
  флотского wrap, смягчён короткими эпохами и ротацией TFK (`02 §3.9`).
- **PQ-семантика честная**: гибрид защищает сессию (payload); outer QUIC handshake —
  стандартный TLS 1.3 (классический), его роль — только транспорт. HNDL-безопасность
  касается записей frame-слоя, зашифрованных ключами из Noise_IK гибрида.
