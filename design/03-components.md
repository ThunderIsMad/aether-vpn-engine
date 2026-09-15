# Aether — спецификация модулей (v2)

Каждый модуль — отдельный крейт с узким интерфейсом. Язык ядра: **Rust**.
Изменения v2: добавлены `frame-session` и `key-coordinator`; исправлен стек зависимостей
(проверено на реализуемость, а не «по названиям»); masque-go понижен до reference-имплементации.

## Верифицированный стек (смотри DEPENDENCIES.md в scaffold'е)

| Назначение | Крейт | Примечание |
|------------|-------|------------|
| QUIC | `quinn` | BBR там **экспериментальный** (BBRv1-класс, «use at your own risk») — дефолт cubic, BBR за флагом с бенчмарком |
| HTTP/3 | `h3` + `quinn` | для MASQUE CONNECT-UDP |
| Noise PQ | `clatter` (PQNoise, ML-KEM-768) либо `noise-protocol` + RustCrypto `ml-kem` | `snow` не подходит — только Kyber1024 round-3 |
| AEAD | `chacha20poly1305`, `x25519-dalek` | |
| Reality-обложка | xray-core (Go) как **reference**; Rust-путь: `boring` (BoringSSL) c контролем ClientHello | uTLS-эквивалента в Rust нет — самый дорогой cover, делать после остальных |
| ML-классификатор | `ort` (ONNX Runtime) / TFLite | |
| Секьюрное хранилище | keyring / DPAPI / Keychain / libsecret | |

`masque-go` и `quic-go` — **не зависимости**: читаем как reference для минимального
Rust-клиента RFC 9298 поверх quinn+h3.

## Модули

### 1. frame-session — record-протокол, носитель сессии (NEW, критический путь)
- **In:** app flows от PolicyEngine; морф/ротация события.
- **Out:** records в активный байндинг; ACK/continuity события.
- **State:** stream_table, seq, ratchet `K_record[n]`, duplicate-window.
- **Контракт:** переживает смену байндинга и узла; ровно-once delivery на узле по (sid, seq).

### 2. crypto-core
- **In:** session-id, peer static, KEM selection.
- **Out:** `K_session`, seal/open записей.
- **Impl:** Clatter / noise-protocol+ml-kem (NoisePQC++ паттерн); constant-time; KEM registry.
- Тест: KAT-векторы на ML-KEM-768 (FIPS 203) + interop с эталонной имплементацией.

### 3. key-coordinator — fleet epoch keys + tickets (NEW)
- **In:** subscription update (epoch keys), ticket requests.
- **Out:** mint/unwrapped tickets для RESUME; re-key события.
- **Impl:** AEAD-обёртка TLS-ticket-стиля (см. `02-protocols §3`); эпохи с TTL;
  post-rotation re-key `HKDF(K_session, "rotate", eph)`.

### 4. transport-mux — байндинги
- QUIC-байндинг (quinn; resumption/0-RTT — по результату Phase 0.5).
- MASQUE-байндинг: минимальный RFC 9298 CONNECT-UDP клиент на quinn+h3 (свой, ~1–2k LOC).
- Reality/TCP-байндинг: length-prefixed frames; HOL tradeoff задокументирован.
- SS-2022/padded байндинг (fallback, чистый Rust).

### 5. morph-controller — Liquid Tunnel FSM + on-device классификатор
- **In:** uplink телеметрия, probe/block сигналы, latency.
- **Out:** выбранный байндинг + морф-параметры (padding, target site, fingerprint).
- **Impl:** FSM из `02 §4`; классификатор ONNX (класс 2506.11319); overlap-window менеджер.
- Research-grade: пороговые значения тюнятся на тестбеде (Phase 2).

### 6. cover-engine (App Mirage) — research-grade
- FlowPaint-класс генератор, rate-limited, по требованию morph-controller.

### 7. session-store (клиент)
- `(subscription_id, UUID, session_id)` + K_session + tickets + chain descriptor.
- In-memory + OS secure store. Серверного состояния нет по построению.

### 8. policy-engine
- Rule matcher + fake-ip DNS (198.18.0.0/16), Clash-стиль, split-tunnel.

### 9. device-adapter
- utun (macOS/iOS), TUN (Linux/Android), WFP/WinDivert (Windows).
- Порядок платформ: Linux → Windows → macOS.

### 10. telemetry-guard
- Opt-in, без payload/destinations/identities, default OFF.

## Контракты (Rust)

```rust
trait FrameSession {
    fn open_stream(&mut self, flow: FlowId) -> StreamId;
    fn seal_record(&mut self, stream: StreamId, data: &[u8]) -> Record;
    fn on_resume_ack(&mut self, continuity: Seq) -> DuplicateWindow;
}

trait Rotation {
    fn mint_ticket(&self, epoch: EpochId) -> Ticket;
    fn resume(&mut self, node: &Node, ticket: &Ticket) -> Result<Continuity, ResumeError>;
    fn post_rotation_rekey(&mut self, eph: &[u8; 32]);
}

trait CoverBinding {
    fn send(&mut self, rec: &Record);
    fn supports(&self) -> BindingCaps; // { NO_HOL, DATAGRAM, DPI_PROFILE }
}

trait Classifier {
    fn classify(&self, telemetry: &UplinkTelemetry) -> CoverVerdict;
}
```

## Порядок зависимостей для сборки

frame-session и crypto-core не зависят от транспортов (тестируются на моках байндингов).
transport-mux зависит от frame-session (интерфейс CoverBinding). morph-controller — последний.
```
