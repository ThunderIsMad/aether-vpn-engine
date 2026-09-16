# Aether — спецификация модулей (v2)

Каждый модуль — отдельный крейт с узким интерфейсом. Язык ядра: **Rust**.
Изменения v2: добавлены `frame-session` и `key-coordinator`; исправлен стек зависимостей
(проверено на реализуемость, а не «по названиям»); masque-go понижен до reference-имплементации.

## Верифицированный стек (смотри DEPENDENCIES.md в scaffold'е)

| Назначение | Крейт | Примечание |
|------------|-------|------------|
| QUIC | `quinn` | BBR там **экспериментальный и не сопровождается** (BBRv1-класс, «use at your own risk», issue #2156: отстаёт от upstream BBR) — дефолт cubic, BBR за флагом с бенчмарком. Migration: серверная — есть (default on), активная клиентская в API 0.11.12 — нет (`phase-0.5.md`) |
| Outer TLS PQ | — | **не включается:** фича quinn `__rustls-post-quantum-test` — тестовая (`__`-префикс, гейтит только тест, тянет `rustls/prefer-post-quantum` на aws-lc-rs); outer остаётся классический TLS 1.3 (Phase 0.5, Q7) |
| HTTP/3 | `h3` + `quinn` | для MASQUE CONNECT-UDP |
| Noise PQ | `clatter` (PQNoise, ML-KEM-768) — единственный готовый путь; KEM-бэкенд — **только `use-pqclean-ml-kem`** (второй, `use-rust-crypto-ml-kem`, в workspace не тянется: транзитивный `ml-kem 0.2.1` не собирается, Q8); `noise-protocol` + RustCrypto `ml-kem` **не композиция**: в `noise-protocol` трейты только DH/Cipher/Hash, KEM-токенов нет → форк | `snow` не подходит — только Kyber1024 round-3 (закрытый enum); `clatter` без формального аудита; interop RustCrypto ⇄ PQClean доказан двунаправленным тестом (`crypto-core`) |
| AEAD | `chacha20poly1305`, `x25519-dalek` | |
| Reality-обложка | xray-core (Go) как **reference**; Rust-путь: `boring` (BoringSSL) c контролем ClientHello | TLS-слойного uTLS-эквивалента в Rust нет (`impersonate-rs` есть, но он HTTP-уровня) — самый дорогой cover, делать после остальных. Риск: два libcrypto в одном дереве рядом с rustls |
| ML-классификатор | `ort` (ONNX Runtime) / TFLite | `ort` 2.0 — release candidate (2.0.0-rc.13): нужен план отката на 1.x |
| Секьюрное хранилище | keyring / DPAPI / Keychain / libsecret | |

`masque-go` и `quic-go` — **не зависимости**: читаем как reference для минимального
Rust-клиента RFC 9298 поверх quinn+h3.

Версии в этой таблице не пинуются: **пины живут в `DEPENDENCIES.md` → «Phase 0 pins»**
(TTL 90d) и продублированы в `Cargo.toml` → `[workspace.dependencies]` — таблица версий здесь
не дублируется.

## Модули

### 1. frame-session — record-протокол, носитель сессии (NEW, критический путь)
- **In:** app flows от PolicyEngine; морф/ротация события.
- **Out:** records в активный байндинг; ACK/NAK/continuity события.
- **State:** stream_table, seq, ratchet `K_record[n]`, duplicate-window (4096 записей, bitmap 512 B).
- **Контракт:** переживает смену байндинга и узла; **идемпотентный дедуп по (sid, seq),
  at-most-once на выходе** (exactly-once не заявляется — см. `02 §3.5`).
- **Владеет таймером** overlap-window и бюджетом дублирования (`02 §4`).

### 2. crypto-core
- **In:** session-id, свой и парный static (из манифеста подписки), KEM selection.
- **Out:** `K_session`, seal/open записей.
- **Impl:** Clatter (Noise_IK гибрид, `02 §5`); constant-time; KEM registry. Путь через `noise-protocol`
  требует форка: KEM-токенов в абстрактной реализации нет.
- Тест: KAT-векторы на ML-KEM-768 (FIPS 203) + interop. У clatter собственное именование
  PQ-примитивов, поэтому interop-тесты против эталона обязательны, а не желательны.

### 3. key-coordinator — ticket-обёртка и PoP на клиенте (NEW)
- **In:** манифест подписки (только публичные ключи узлов и свои ключи), запросы mint.
- **Out:** `RESUME` с PoP-подписью, `RESUME_ACK`-проверка, re-key события.
- **Impl:** запрашивает mint **у узла** (сам не минтит и `TFK_epoch` не получает);
  `sig_client` Ed25519 по `client_identity`; post-rotation re-key со свежим DH
  `HKDF(HKDF-Extract(DH(eph_client, eph_node) ‖ K_session))` (`02 §3.3`).
- **Не владеет:** epoch keys, wrap-ключами, состоянием дедупа.

### 4. transport-mux — байндинги
- QUIC-байндинг (quinn; resumption/0-RTT — по результату Phase 0.5).
- MASQUE-байндинг: минимальный RFC 9298 CONNECT-UDP клиент на quinn+h3 (свой; оценка, уточняется в Phase 1).
- Reality/TCP-байндинг: length-prefixed frames; HOL tradeoff задокументирован.
- SS-2022/padded байндинг (fallback, чистый Rust).

### 5. morph-controller — Liquid Tunnel FSM + on-device классификатор
- **In:** uplink телеметрия, probe/block сигналы, latency.
- **Out:** выбранный байндинг + морф-параметры (padding, target site, fingerprint).
- **Impl:** FSM из `02 §4`; классификатор ONNX (класс 2506.11319); overlap-window менеджер.
- Research-grade: пороговые значения тюнятся на тестбеде (Phase 2).

### 6. cover-engine (App Mirage) — research-grade
- FlowPaint-класс генератор, rate-limited, по требованию morph-controller.

### 7. session-store (клиент) — **владелец клиентских ключей личности**
- In/State: `(subscription_id, UUID, session_id)` + K_session + tickets + chain descriptor;
  **`client_identity` (Ed25519 priv)** — подпись RESUME (PoP, `02 §3.3`);
  **`client_static` (X25519 priv)** — статик инициатора в IK (`02 §5`).
- **Владелец назначен явно здесь:** обе приватные пары личности живут в session-store; никакой
  другой модуль их не хранит (v3 ввёл их, и без этой строки они оставались без владельца).
- At-rest: OS secure store (keyring / DPAPI / Keychain / libsecret) для `client_identity`,
  `client_static` и K_session; tickets — только in-memory. У сервера нет состояния,
  переживающего ротацию (на время сессии — in-memory окно дедупликации).

### 8. policy-engine
- Rule matcher + fake-ip DNS (198.18.0.0/16), Clash-стиль, split-tunnel.

### 9. device-adapter
- utun (macOS/iOS), TUN (Linux/Android), WFP/WinDivert (Windows).
- Порядок платформ: Linux → Windows → macOS.

### 10. telemetry-guard
- Opt-in, без payload/destinations/identities, default OFF.

## Контракты (Rust)

Типы ниже — примитивы, объявляемые крейтами-владельцами (`Seq`, `SessionId` — `frame-session`;
`X25519Pub`, `Signature` — рядом с тем, кто их несёт). Дублирование примитива в стороне узла
или клиента сознательно: `ticket-mint` дублирует `SessionId`, потому что не тянет клиентские типы.
Поля окон (`Window`, `DuplicateWindow`, `Continuity`) — те же числа, что `Seq`: в `frame-session`
это `Seq`, в крейтах без зависимости на него — `u64` до решения по сшивке (`QUESTIONS.md` Q3).

```rust
trait FrameSession {
    fn open_stream(&mut self, flow: FlowId) -> StreamId;
    fn seal_record(&mut self, stream: StreamId, data: &[u8]) -> Record;

    /// `RESUME_ACK` нового узла (`02 §3.3`): его `continuity_point`, его окно,
    /// `eph_node` и `sig_node`. Возвращает собственное окно дубликатов клиента.
    fn on_resume_ack(
        &mut self,
        continuity_point: Seq,
        window: DuplicateWindow,
        eph_node: X25519Pub,
        sig_node: Signature,
    ) -> DuplicateWindow;

    /// `RESUME_NAK` (`02 §3.7`): узел отклонил резюм, сессия остаётся на старом канале.
    fn on_resume_nak(&mut self, nak: ResumeNak);
}

/// Ветки `RESUME_NAK` (`02 §3.7`) — ровно четыре, без расширения.
enum ResumeNak {
    BadPop,    // sig_client неверна: ticket не консумируется, инцидент в телеметрию узла
    Replay,    // повтор ticket на том же узле (consumed-set эпохи, `02 §3.6`)
    Epoch,     // epoch_id не совпал → фолбэк: полный IK-handshake (`02 §5`)
    Expired,   // exp истёк → фолбэк: полный handshake
}

trait Rotation {                       // клиентская сторона; mint здесь НЕТ
    fn request_ticket(&mut self, node: &Node) -> Result<Ticket, MintError>;
    fn resume(&mut self, node: &Node, ticket: &Ticket, eph: X25519Pub) -> Result<Continuity, ResumeError>;
    fn post_rotation_rekey(&mut self, eph_node: &X25519Pub) -> Result<(), RekeyError>;
}

trait TicketMint {                     // сторона узла (fix #29: единственный владелец mint)
    fn mint(&self, sid: SessionId, client_auth: Ed25519Pub, window: Window) -> TicketBlob;
    fn unwrap_ticket(&self, blob: &TicketBlob) -> Result<TicketPlain, TicketError>;
    fn verify_pop(&self, ticket: &TicketPlain, sig: &Signature, ctx: &ResumeCtx) -> bool;
}

/// Ответ нового узла на успешный `RESUME` (`02 §3.3`): **все поля `RESUME_ACK`, которые клиент
/// проверил** — включая `eph_node` и `sig_node` (Q17). `FrameSession::on_resume_ack` получает
/// их из этого типа; ручной разбор AEAD-ответа в клиентском коде не нужен.
struct Continuity {
    point: Seq,
    window_lo: Seq,
    window_hi: Seq,
    eph_node: X25519Pub,
    sig_node: Signature,
}
/// Пол окна на момент минта (`02 §3.1`).
struct Window { lo: Seq, hi: Seq }
/// Окно дедупа в `RESUME_ACK` (`02 §3.3`, окно 4096 — `02 §3.5`).
struct DuplicateWindow { lo: Seq, hi: Seq }

/// Ошибка резюма на стороне клиента (`02 §3.7`).
enum ResumeError {
    AckTimeout,          // `RESUME_ACK` не пришёл за T_ack = 2 × SRTT, клип [200 ms, 2 s]
    BadNodeSignature,    // sig_node неверна → канал не подтверждён, узел в quarantine
    Nacked,              // в ветке лежат bad_pop | replay | epoch | expired (`02 §3.7`)
}

trait CoverBinding {
    fn send(&mut self, rec: &Record) -> Result<(), BindingError>;  // синхронный отказ
    fn supports(&self) -> BindingCaps; // { NO_HOL, DATAGRAM, DPI_PROFILE }
    fn on_failure(&mut self) -> Option<BindingFailure>;            // асинхронный отказ
}

trait Classifier {
    fn classify(&self, telemetry: &UplinkTelemetry) -> CoverVerdict;
}
```

## Порядок зависимостей для сборки

frame-session и crypto-core не зависят от транспортов (тестируются на моках байндингов).
transport-mux зависит от frame-session (интерфейс CoverBinding). morph-controller — последний.
