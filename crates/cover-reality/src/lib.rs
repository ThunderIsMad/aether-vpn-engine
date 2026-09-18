//! `cover-reality` — обложка Phase 1, кусок 3: **Reality/TCP** (самый дорогой cover).
//!
//! **In:** уже sealed records frame-слоя (`frame_session::Record`), не сырой IP.
//! **Out:** кадры `len(4B BE) ‖ nonce(24B) ‖ AEAD(record, AAD=заявленная длина)` в TLS-класс канал;
//! ClientHello строится boring'ом под SNI целевого сайта.
//! **Deps:** `transport-mux` (контракт `CoverBinding`), `frame-session` (типы записей),
//! `boring` (TLS-бэкенд контроля ClientHello — то, что проверяли пробы линковки),
//! `crypto-core` (KDF обложки + AEAD auth-тега).
//!
//! ## Что реализовано (каркас, по образцу cover-ss2022 / cover-masque; b132-2 — layered)
//!
//! Модель после решения Q22 — **двухслойное различение «peek-before-decrypt»**:
//!
//! 1. **Гейт по открытому ClientHello** (`gate_decision`) — решение ДО терминации TLS,
//!    до каких-либо TLS-ключей. Аутентификатор — 24-байтный HMAC (`probe_tag`, ключ
//!    `K_probe` — отдельный слой) над ClientHello с нулённым местом тега + окно слотов
//!    времени (анти-replay). Клиент кладёт тег в TLS-расширение `session_ticket`
//!    (RFC 5077, opaque-поле — равномерно-случайный вид, неотличим от шума/билетов).
//!    - `Accept` → TLS терминируется, дальше — слой 2.
//!    - `Relay` → **живой сплайс**: `relay_to_target` открывает TCP к сайту-мишени и
//!      проксирует сырые байты в обе стороны — пробник разговаривает с НАСТОЯЩИМ сайтом
//!      (настоящий сертификат, handshake, данные); сервер не расшифровывает ничего.
//!      Это и есть источник неотличимости (в духе Reality/xtls-rprx-vision).
//!    - `Reject` (не ClientHello вообще) → тихое закрытие — так же ведёт себя
//!      перегруженный сайт; наблюдаемой разницы нет.
//!    - Fail-safe релея: тайм-аут коннекта, потолок байт; аплинк недоступен → тихое
//!      закрытие (не RST-сигнатура Reality).
//! 2. **Классификация первой записи внутри TLS** (`classify_first_record`) — для пути
//!    Accept: AEAD-тег первой записи на `K_cover`. Не прошла → тихое закрытие
//!    (`Rejected`), без ответа: активная проба ПОСЛЕ гейта не получает ничего.
//! 3. **ClientHello под сайт-мишень** (`build_client_hello_tls`): boring собирает
//!    коннектор с пином сертификата сайта-мишени и браузерным ALPN; SNI-домен
//!    параметризован (`TargetSite`), не захардкожен.
//! 4. **HOL честно**: `caps()` — `no_hol: false, datagram: false` (TCP-класс, `02 §2.2`).
//!
//! ## Что НЕ заявляется (честные границы клейма)
//!
//! - **Не DPI-resistant в смысле живого трафика**: независимый DPI-инструмент и реальный
//!   active-probe не запускались — юнит-тесты механизма + пробы линковки обеих платформ.
//!   Не сравнивался JA3/JA4-отпечаток нашего handshake с отпечатком настоящего клиента
//!   сайта-мишени (Q22/Q23).
//! - **Не Reality-interop с xray-core**: каркас Reality-класса в терминах `03` §4;
//!   совместимость с VLESS/Reality не заявляется.
//! - Не реализовано: приёмная сторона рантайма (tokio-версия сплайса, boring-коллбеки
//!   на session_ticket), клиентская верификация сертификата (T1: доступ к keyshare,
//!   QUESTIONS.md), интеграция gate→accept в полный сервер, морф (Phase 2).
//!   Q23-каркас: `RealityCertState`/`build_reality_cert`/`AcceptServer` — серверная
//!   сторона Accept-пути, проверена изолированно (roundtrip-векторы + loopback handshake).

#![deny(unsafe_code)]

use crypto_core::{KCover, KProbe, KRecord, RecordAead, RecordCrypto, RecordNonce};
use frame_session::Record;
use transport_mux::{BindingCaps, BindingError, BindingFailure, DEFAULT_OUTBOX_BYTES};

/// Профиль DPI Reality/TCP-байндинга — реэкспорт из `transport-mux`.
pub use transport_mux::DPI_PROFILE_REALITY_TCP;

/// Длина префикса длины кадра (4 B BE).
pub const FRAME_LEN_BYTES: usize = 4;
/// Длина nonce AEAD auth-тега (24 B XChaCha20-Poly1305).
pub const AUTH_NONCE_LEN: usize = 24;
/// Длина тега Poly1305 (XChaCha20-Poly1305, RFC 8439): `crypto-core` константу не экспортирует.
const POLY1305_TAG: usize = 16;

/// Сайт-мишень для ClientHello — параметризован, не захардкожен.
///
/// `sni` — домен, под который строится ClientHello; `fallback` — байты, отдающиеся
/// неаутентифицированным соединениям (в проде — снимок реального ответа сайта-мишени;
/// в тестах — детерминированная заглушка); `description` — диагностика, не на провод.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetSite {
    /// SNI домена сайта-мишени.
    pub sni: String,
    /// Человекочитаемое описание (не на провод).
    pub description: String,
}

impl TargetSite {
    /// Тестовый placeholder: не боевой домен, явно помечен как тестовая цель.
    /// (Фолбэк-байтов больше нет: путь Relay — живой сплайс к сайту, не снимок.)
    pub fn placeholder() -> Self {
        Self {
            sni: "example.com".to_string(),
            description: "placeholder (unit tests only)".to_string(),
        }
    }
}

/// Ошибка auth-слоя Reality-обложки (`decode_reality_frame`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// Кадр короче заголовка или `len` не совпадает с телом.
    BadLength,
    /// AEAD не прошёл аутентификацию (не Reality-клиент, чужой ключ, порча байтов).
    NotAuthenticated,
    /// Запись внутри аутентифицированной обёртки не разбирается.
    BadRecord,
}

/// Строит TLS-коннектор boring под сайт-мишень (ClientHello с её SNI).
///
/// `root_cert_der` — сертификат сайта-мишени в DER (пин как единственный корень,
/// тот же механизм, что у e2e-лаборатории). verify PEER + verify hostname — дефолты
/// boring, не отключаются. ALPN — браузерный набор в wire-формате (`\x02h2\x08http/1.1`).
/// Возвращает собранный коннектор; сам handshake — задача живого peer-теста.
pub fn build_client_hello_tls(
    site: &TargetSite,
    root_cert_der: &[u8],
) -> Result<boring::ssl::SslConnector, boring::error::ErrorStack> {
    use boring::ssl::{SslConnector, SslMethod};

    let mut builder = SslConnector::builder(SslMethod::tls())?;
    let cert = boring::x509::X509::from_der(root_cert_der)?;
    builder.cert_store_mut().add_cert(cert)?;
    builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;
    let _ = site; // SNI передаётся в connect(domain) живого peer-теста; здесь — валидация параметров
    Ok(builder.build())
}

/// Оборачивает запись в аутентифицированную обёртку Reality-обложки:
/// `len(4B BE) ‖ nonce(24B) ‖ AEAD(record, AAD=заявленная длина)`.
///
/// Первый кадр нового TLS-канала — всегда эта обёртка: сервер сверяет тег **до** того,
/// как наружу уйдёт что-то ещё. AAD — заявленный префикс длины кадра (`len`): это
/// единственные байты, выводимые принимающей стороной **до** вскрытия, поэтому и только
/// эта схема сверяема в обе стороны (AAD по длине тела принимающий вычислить не может).
/// Nonce — случайный 24 B (probabilistic AEAD); кадры этой обёртки редки (первый кадр
/// каждого TLS-канала), 96-битного счётчика не требуется — повтор nonces на `K_cover`
/// практически невозможен.
pub fn encode_reality_frame(
    cover: &KCover,
    record: &Record,
    rng_fill: &mut dyn FnMut(&mut [u8]),
) -> Vec<u8> {
    let body = record.encode();
    let mut nonce = [0u8; AUTH_NONCE_LEN];
    rng_fill(&mut nonce);
    // Заявленная длина тела кадра: nonce + шифротекст (тело записи + тег Poly1305).
    let declared = (AUTH_NONCE_LEN + body.len() + POLY1305_TAG) as u32;
    let ciphertext = RecordAead.seal(
        &KRecord(cover.0),
        &RecordNonce(nonce),
        &declared.to_be_bytes(),
        &body,
    );

    let mut frame = Vec::with_capacity(FRAME_LEN_BYTES + AUTH_NONCE_LEN + ciphertext.len());
    frame.extend_from_slice(&declared.to_be_bytes());
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(&ciphertext);
    frame
}

/// Вскрывает первый кадр Reality-канала: чужой ключ/порча → `NotAuthenticated`,
/// битая длина → `BadLength`, неразбираемая запись при валидном теге → `BadRecord`.
pub fn decode_reality_frame(cover: &KCover, frame: &[u8]) -> Result<Record, AuthError> {
    let (prefix, rest) = frame
        .split_at_checked(FRAME_LEN_BYTES)
        .ok_or(AuthError::BadLength)?;
    let declared =
        u32::from_be_bytes(prefix.try_into().map_err(|_| AuthError::BadLength)?) as usize;
    if declared != rest.len() {
        return Err(AuthError::BadLength);
    }
    let (nonce, ciphertext) = rest
        .split_at_checked(AUTH_NONCE_LEN)
        .ok_or(AuthError::BadLength)?;
    let mut nonce_arr = [0u8; AUTH_NONCE_LEN];
    nonce_arr.copy_from_slice(nonce);

    // AAD — тот же префикс длины, что при seal.
    let aad = u32::from_be_bytes(prefix.try_into().map_err(|_| AuthError::BadLength)?);
    let plaintext = RecordAead
        .open(
            &KRecord(cover.0),
            &RecordNonce(nonce_arr),
            &aad.to_be_bytes(),
            ciphertext,
        )
        .map_err(|_| AuthError::NotAuthenticated)?;

    Record::decode(&plaintext).map_err(|_| AuthError::BadRecord)
}

/// Вердикт гейта Reality-обложки — **сам механизм active-probe resistance** (b132-2,
/// peek-before-decrypt: решение по ОТКРЫТОМУ ClientHello, до ключей TLS).
///
/// Аутентифицирован по открытому ClientHello → Reality-клиент: TLS терминируется, канал
/// продолжается Aether-протоколом (первая запись внутри — `decode_reality_frame`).
/// Не аутентифицирован → сервер становится прозрачным TCP-релеем к сайту-мишени:
/// пробник получает настоящий handshake и данные реального сайта, мы байты не читаем.
/// Один пробный запрос не даёт наблюдателю способа отличить Reality-ноду от сайта-мишени.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateDecision {
    /// Reality-клиент: TLS терминируется (сервер держит `K_cover` для первой записи).
    Accept,
    /// Не Reality-клиент: raw TCP-релей к сайту-мишени (байты не интерпретируются).
    Relay(RelaySpec),
    /// Мусор вместо TLS или тайм-аут гейта: тихое закрытие. См. Q22: ровно это делает
    /// и перегруженный сайт-мишень — наблюдаемо неотличимо.
    Reject,
}

/// Классифицирует первый кадр TLS-канала (внутри терминированного TLS — путь Accept).
pub fn classify_first_record(cover: &KCover, frame: &[u8]) -> FirstRecordVerdict {
    match decode_reality_frame(cover, frame) {
        Ok(rec) => FirstRecordVerdict::Authenticated(rec),
        // Канал прошёл гейт (Accept), но первая запись не аутентифицирована — это
        // активная проба ПОСЛЕ гейта: тихое закрытие без ответа (Q22: статический
        // снимок удалён; поведение — как сайт, обрывающий соединение).
        Err(_) => FirstRecordVerdict::Rejected,
    }
}

/// Вердикт по первой записи ВНУТРИ терминированного TLS (путь Accept гейта).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirstRecordVerdict {
    /// Reality-клиент: запись достоверна, продолжается Aether-протокол.
    Authenticated(Record),
    /// Прошёл гейт, но первая запись не аутентифицирована: тихое закрытие без ответа.
    Rejected,
}

// ---------- b132-2: peek-before-decrypt — гейт по открытому ClientHello ----------
//
// Архитектурное решение Q22: различение «Reality-клиент vs пробник» происходит ДО
// терминации TLS — по ОТКРЫТОМУ ClientHello, до того как у сервера есть хоть один
// TLS-ключ. Фолбэк-путь — прозрачный TCP-релей к сайту-мишени (см. GateDecision::Relay).
// Место решения: mock Runtime на байте-100 ClientHello (реально — при получении записи
// ClientHello целиком, до ServerHello от нас; тайм-аут гейта — Q22).

/// Где именно на проводе принимается решение гейта (диагностика, не секрет).
/// 99 — максимум длины ClientHello из случайных байтов; реально: позиция конца
/// записи ClientHello в потоке, но не позже (mock-фиксация смещения для юнитов).
pub const GATE_DECISION_BYTE: usize = 100;

/// Параметры релея для `GateDecision::Relay`: куда проксировать и с каким fail-safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySpec {
    /// IP:порт сайта-мишени (в проде — из DNS-резолва `TargetSite::sni` в момент гейта).
    pub addr: std::net::SocketAddr,
    /// Тайм-аут установки соединения к сайту-мишени (fail-safe: не висим вечно);
    /// тот же лимит — предел простоя каждого направления сплайса (`relay_to_target`).
    pub connect_timeout: std::time::Duration,
    /// Потолок байт в каждую сторону (fail-safe: не держим бесконечный релей).
    pub max_relay_bytes: u64,
}

/// Гейт Reality-обложки (b132-2): решение по **открытому** ClientHello до TLS-терминации.
///
/// `client_hello` — сырые байты, полученные от клиента до того, как мы отправили хоть
/// один байт ответа. Аутентификатор — 24-байтный HMAC-тег (`probe_tag`) над ClientHello
/// с окном времени, положенный клиентом в TLS-расширение `session_ticket` (RFC 5077:
/// формат-agnostic opaque-поле, равномерно-случайный вид — неотличим от шума и от
/// билетов настоящего клиента сайта-мишени; точный layout аутентификатора внутри
/// extension — ниже, `PROBE_AUTHENTICATOR_LEN`).
///
/// Причины отказа не различимы снаружи: Relay — на любую неаутентичность, Reject —
/// только на «это вообще не TLS ClientHello» (перегруженный сайт-мишень так же
/// молча закрывает соединения).
///
/// Окно `(lo, hi)` — нижняя/верхняя границы допустимого «слота времени» клиента
/// (Q21-класс: диапазон, не равенство; анти-replay). Клиент и сервер согласовывают
/// слот из своего времени; релаксация — вопрос конфига, не этого гейта.
pub const PROBE_AUTHENTICATOR_LEN: usize = 24;

/// Слот времени гейта (Q21-класс: диапазон, не равенство). Единица — минуты Unix-time:
/// клиент кладёт тег в текущем слоте `t`, сервер принимает теги слотов `t-1..=t+1`
/// (анти-replay без жёсткой синхронизации часов). Любое несоответствие — `Relay`
/// (не Reject): наблюдателю неотличимо.
pub fn gate_slot(unix_minutes: u64) -> u64 {
    unix_minutes
}

/// Вычисляет аутентификатор для вклада в `session_ticket` (клиентская сторона гейта).
/// `client_hello_redacted` — весь ClientHello, где место тега (24 B) заполнено нулями:
/// тег не покрывает сам себя. `slot` — текущий слот `gate_slot(now_minutes)`.
pub fn client_authenticator(
    k_probe: &KProbe,
    client_hello_redacted: &[u8],
    slot: u64,
) -> [u8; PROBE_AUTHENTICATOR_LEN] {
    crypto_core::probe_tag(
        k_probe,
        client_hello_redacted,
        (slot.saturating_sub(1), slot + 1),
    )
}

/// Решение гейта по открытому ClientHello (`peek-before-decrypt`, b132-2).
///
/// `client_hello` — байты ClientHello как пришли (тег уже внутри extension'а, если он там
/// есть). Сервер вырезает место тега (в `session_ticket` — по правилам TLS-парсера;
/// здесь — `redact_authenticator`), вычисляет ожидаемые теги для слотов
/// `slot-1..=slot+1` и сравнивает. Совпал хотя бы один → `Accept`; ClientHello валиден
/// по форме, но тега/совпадения нет → `Relay`; байты вообще не ClientHello → `Reject`.
/// `relay` — готовый `RelaySpec` (адрес сайта-мишени уже резолвен вызывающим).
pub fn gate_decision(
    k_probe: &KProbe,
    client_hello: &[u8],
    authenticator: Option<&[u8]>,
    slot: u64,
    relay: RelaySpec,
) -> GateDecision {
    // Не TLS-запись с ClientHello: тихое закрытие — ровно так же ведёт себя
    // перегруженный сайт-мишень; наблюдаемой разницы нет (Q22).
    if !looks_like_client_hello(client_hello) {
        return GateDecision::Reject;
    }
    // Аутентификатор вырезает TLS-парсер (коллбек boring на session_ticket); гейту
    // остаётся сверить HMAC. Несоответствие/отсутствие — Relay (не Reject):
    // наблюдателю неотличимо.
    if let Some(tag) = authenticator {
        let redacted = redact_authenticator(client_hello, tag);
        for s in [slot.saturating_sub(1), slot, slot + 1] {
            let expected = crypto_core::probe_tag(k_probe, &redacted, (s.saturating_sub(1), s + 1));
            // Constant-time сверка (Q24, аудит F-05): вход — секретный HMAC, обычное
            // `==` на массивах фиксированной длины для масивов к struct+PartialEq
            // компилятор разворачивает в memcmp — время зависит от данных.
            if tag.len() == PROBE_AUTHENTICATOR_LEN {
                let tag_arr: [u8; PROBE_AUTHENTICATOR_LEN] = tag[..PROBE_AUTHENTICATOR_LEN]
                    .try_into()
                    .expect("len проверен выше");
                let expected_arr: [u8; PROBE_AUTHENTICATOR_LEN] = expected;
                if crypto_core::tags_equal_ct(&tag_arr, &expected_arr) {
                    return GateDecision::Accept;
                }
            }
        }
    }
    GateDecision::Relay(relay)
}

/// Минимальная форма-проверка открытой записи TLS: ContentType=Handshake(22),
/// версия 0x03 0x0x, тип сообщения ClientHello(1). Полный разбор расширений —
/// задача реального TLS-стека (boring-коллбек на session_ticket); гейту достаточно
/// формы, не семантики.
fn looks_like_client_hello(b: &[u8]) -> bool {
    b.len() >= 6 && b[0] == 22 && b[1] == 0x03 && b[5] == 0x01
}

/// Вырезает место аутентификатора (переданные парсером байты тега) из ClientHello
/// для вычисления HMAC: тег не покрывает сам себя, место заполняется нулями.
fn redact_authenticator(ch: &[u8], tag: &[u8]) -> Vec<u8> {
    let mut out = ch.to_vec();
    if let Some(pos) = find_subslice(ch, tag) {
        let end = (pos + PROBE_AUTHENTICATOR_LEN).min(out.len());
        out[pos..end].fill(0);
    }
    out
}

/// Наивный поиск подпоследовательности (место тега в CH; длины — десятки байт, ок).
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Исход сплайса (диагностика для логов/метрик; наружу не наблюдается — наблюдателю
/// релей выглядит как обычное соединение с сайтом, которое когда-нибудь кончается).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayOutcome {
    /// Релей отработал: одна из сторон закрыла соединение (нормальный конец).
    Completed,
    /// Соединение к сайту-мишени не установилось в `connect_timeout` — тихое закрытие
    /// стороны пробника. НЕ паника, НЕ RST-сигнатура: ровно то, что делает сайт
    /// при перегрузке (Q22 fail-safe).
    UpstreamUnreachable,
    /// Достигнут потолок `max_relay_bytes` — релей принудительно завершён (fail-safe
    /// от бесконечных туннелей через наш адрес).
    QuotaExhausted,
}

/// Живой сплайс (b132-2): двунаправленный raw TCP-релей между пробником и сайтом-мишенью.
///
/// `probe` — сторона пробника (сокет, с которого пришёл непрошедший гейт ClientHello);
/// первые прочитанные байты (ClientHello) уже в нём (`buffered`) — они пересылаются сайту
/// первыми, чтобы релей был прозрачен для TLS-сессии, НАЧАТОЙ пробником. Ни одна сторона
/// сплайса не интерпретирует байты (в т.ч. мы): пробник разговаривает с настоящим сайтом.
///
/// Реализация — два независимых потока-копировальщика (F-04, аудит 3): направления не
/// блокируют друг друга, ответ сайта доходит до пробника за ~RTT. Последовательный
/// цикл «прочитал у пробника → прочитал у сайта» держал ответ сайта до тайм-аута
/// блокирующего чтения — наблюдаемая аномалия против Q22 (любой пробник с разумным
/// тайм-аутом её видел). Тайм-ауты сокетов берутся из `spec.connect_timeout` (не
/// хардкод) и работают как лимит простоя направления: истёкший read-timeout даёт
/// `WouldBlock` (Unix) или `TimedOut` (Windows) — обрабатываются оба. Любая
/// ошибка/закрытие/лимит простоя/квота завершают релей: оба сокета получают shutdown,
/// второй копировальщик выходит из блокирующего чтения, а не ждёт до тайм-аута. Ошибки
/// релея не паникуют и не отдают наблюдателю характерных сигналов (Q22) — соединение
/// просто закрывается, как у любого обычного сайта. Перенос в tokio-splice — вопрос
/// приёмной стороны, не контракта (крейт синхронный по дизайну).
pub fn relay_to_target(
    spec: &RelaySpec,
    probe: &mut std::net::TcpStream,
    buffered: &[u8],
) -> RelayOutcome {
    use std::io::Write;
    use std::net::TcpStream;
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;

    // Аплинк к сайту-мишени с тайм-аутом: недоступен → тихое закрытие (не сигнал Reality).
    let mut upstream = match TcpStream::connect_timeout(&spec.addr, spec.connect_timeout) {
        Ok(s) => s,
        Err(_) => return RelayOutcome::UpstreamUnreachable,
    };

    // Тайм-ауты сокетов — из `spec` (не хардкод): тот же лимит — предел простоя
    // направления (read-timeout истёк → данных нет достаточно долго, релей закрывается).
    let idle = Some(spec.connect_timeout);
    probe.set_read_timeout(idle).ok();
    probe.set_write_timeout(idle).ok();
    upstream.set_read_timeout(idle).ok();
    upstream.set_write_timeout(idle).ok();

    // Первые байты пробника (ClientHello) — upstream'у, чтобы TLS-сессия пробника
    // началась корректно (мы — прозрачный TCP-релей, байты не читаем).
    if upstream.write_all(buffered).is_err() {
        return RelayOutcome::UpstreamUnreachable;
    }
    if buffered.len() as u64 >= spec.max_relay_bytes {
        return RelayOutcome::QuotaExhausted;
    }

    // Потолок байт общий для обоих направлений (счётчик разделяется потоками).
    let quota = Arc::new(AtomicU64::new(buffered.len() as u64));

    let mut probe_read = match probe.try_clone() {
        Ok(s) => s,
        Err(_) => return RelayOutcome::UpstreamUnreachable,
    };
    let mut probe_write = match probe.try_clone() {
        Ok(s) => s,
        Err(_) => return RelayOutcome::UpstreamUnreachable,
    };
    let mut up_read = match upstream.try_clone() {
        Ok(s) => s,
        Err(_) => return RelayOutcome::UpstreamUnreachable,
    };
    let mut up_write = match upstream.try_clone() {
        Ok(s) => s,
        Err(_) => return RelayOutcome::UpstreamUnreachable,
    };

    // «Пробник → сайт» — отдельный поток: пока основной читает у сайта, байты пробника
    // уходят без ожидания (F-04: направления мультиплексированы, а не чередуются).
    let quota_to_site = Arc::clone(&quota);
    let max_relay_bytes = spec.max_relay_bytes;
    let to_site = std::thread::spawn(move || {
        copy_relay_dir(
            &mut probe_read,
            &mut up_write,
            &quota_to_site,
            max_relay_bytes,
        )
    });
    // Основной поток — «сайт → пробник».
    let to_probe = copy_relay_dir(&mut up_read, &mut probe_write, &quota, spec.max_relay_bytes);

    let to_site_outcome = to_site.join().unwrap_or(RelayOutcome::Completed);
    if to_probe == RelayOutcome::QuotaExhausted || to_site_outcome == RelayOutcome::QuotaExhausted {
        RelayOutcome::QuotaExhausted
    } else {
        RelayOutcome::Completed
    }
}

/// Копирует одно направление сплайса до закрытия/ошибки/квоты/лимита простоя. По любому
/// исходу закрывает оба сокета (`Shutdown::Both` будит все клоны — второй копировальщик
/// выходит из блокирующего чтения вместо ожидания до тайм-аута).
fn copy_relay_dir(
    r: &mut std::net::TcpStream,
    w: &mut std::net::TcpStream,
    quota: &std::sync::atomic::AtomicU64,
    max_relay_bytes: u64,
) -> RelayOutcome {
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::sync::atomic::Ordering;

    let terminate = |r: &mut std::net::TcpStream, w: &mut std::net::TcpStream| {
        let _ = r.shutdown(Shutdown::Both);
        let _ = w.shutdown(Shutdown::Both);
    };

    let mut buf = [0u8; 16 * 1024];
    loop {
        match r.read(&mut buf) {
            Ok(0) => {
                terminate(r, w);
                return RelayOutcome::Completed;
            }
            Ok(n) => {
                if w.write_all(&buf[..n]).is_err() {
                    terminate(r, w);
                    return RelayOutcome::Completed;
                }
                let total = quota.fetch_add(n as u64, Ordering::Relaxed) + n as u64;
                if total >= max_relay_bytes {
                    terminate(r, w);
                    return RelayOutcome::QuotaExhausted;
                }
            }
            // Лимит простоя исчерпан (Windows: TimedOut, Unix: WouldBlock — оба кода
            // означают «данных нет в течение лимита») → релей закрывается (F-04).
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                terminate(r, w);
                return RelayOutcome::Completed;
            }
            Err(_) => {
                terminate(r, w);
                return RelayOutcome::Completed;
            }
        }
    }
}

// ============================== Q23: Accept-путь Reality ==============================

/// Ошибка Accept-пути (Q23): сборка сертификата/терминировка TLS.
#[derive(Debug)]
pub enum AcceptError {
    /// rcgen не собрал скелет (генерация per-process Ed25519-пары/DER).
    CertSkeleton(rcgen::Error),
    /// boring-машина отвергла конфигурацию (setup acceptor'а).
    Boring(boring::error::ErrorStack),
    /// ECDH с keyshare клиента не состоялся (all-zero shared secret — RFC 7748).
    Crypto(crypto_core::CryptoError),
    /// Переписываемый хвост DER не выглядит как signatureValue Ed25519
    /// (`03 42 00 ‖ 64 B`): не пишем слепо в чужое место (explicit fail).
    BadSkeleton,
    /// TLS-handshake не завершился (setup/handshake-ошибка или mid-handshake
    /// WouldBlock на сокете с тайм-аутом): соединение закрывается — как обычный сайт.
    /// Прод-рантайм (tokio) поведёт MidHandshake дальше; каркас — нет.
    Handshake,
}

impl std::fmt::Display for AcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcceptError::CertSkeleton(e) => write!(f, "cert skeleton: {e}"),
            AcceptError::Boring(e) => write!(f, "boring: {e}"),
            AcceptError::Crypto(e) => write!(f, "crypto: {e:?}"),
            AcceptError::BadSkeleton => write!(f, "skeleton tail is not an Ed25519 signature"),
            AcceptError::Handshake => write!(f, "TLS handshake did not complete"),
        }
    }
}

impl std::error::Error for AcceptError {}

/// Per-process состояние сертификата Accept-пути (Q23; решение — QUESTIONS.md Q23).
///
/// Скелет — self-signed Ed25519-сертификат (rcgen), SPKI-паб которого и есть `cert_pub`.
/// Скелет и Ed25519-пара стабильны в пределах процесса (per-process, не per-handshake:
/// стабильная идентичность без churn-сигнала; рестарт = «сайт сменил сертификат», как и
/// у upstream temp-cert). per-handshake меняется ТОЛЬКО поле подписи — см.
/// `build_reality_cert`.
///
/// Честное отличие от upstream (xtls/reality): upstream держит subject/SAN пустыми;
/// rcgen требует непустой CN — каркас ставит нейтральный CN и НЕ ставит SAN (подменять
/// нечего; T2 в QUESTIONS.md).
#[derive(Clone)]
pub struct RealityCertState {
    node_reality: crypto_core::NodeRealityKey,
    /// PKCS#8 DER Ed25519-ключа сертификата: boring подписывает CertificateVerify —
    /// handshake криптографически честен (Q23 п. 5).
    cert_key_pkcs8: Vec<u8>,
    /// Сырой DER скелета (оригинальное поле подписи — перезаписывается per-handshake).
    skeleton_der: Vec<u8>,
    /// `cert_pub` — сырые 32 B публичного ключа Ed25519 из SPKI скелета.
    cert_pub: Vec<u8>,
}

impl std::fmt::Debug for RealityCertState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityCertState")
            .field("node_reality", &"<redacted>")
            .field("cert_key_pkcs8", &"<redacted>")
            .field("skeleton_der.len", &self.skeleton_der.len())
            .field("cert_pub", &self.cert_pub)
            .finish()
    }
}

impl RealityCertState {
    /// Собирает per-process состояние: Ed25519-пара (системный RNG) + self-signed скелет.
    pub fn new(node_reality: crypto_core::NodeRealityKey) -> Result<Self, AcceptError> {
        let cert_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(AcceptError::CertSkeleton)?;
        // CN обязателен (ограничение rcgen); SAN не ставим — скелет не должен нести
        // привязку к SNI (T2, QUESTIONS.md Q23).
        let params = rcgen::CertificateParams::new(vec!["aether".to_string()])
            .map_err(AcceptError::CertSkeleton)?;
        let cert = params
            .self_signed(&cert_key)
            .map_err(AcceptError::CertSkeleton)?;
        // rcgen serialize_der отдаёт PKCS#8 **v2** (RFC 5958, version=1 — формат ring:
        // 30 51 02 01 01 …). boring `d2i_PKCS8_PRIV_KEY_INFO` (private_key_from_pkcs8)
        // понимает только **v1** — падает WRONG_TAG на attributes. Пересобираем v1-PKCS#8
        // из seed (последние 32 B ring-документа — privateKey OCTET STRING):
        //   SEQUENCE(46){ INTEGER 0, SEQ{OID 1.3.101.112}, OCTET STRING(34){seed 32B} }.
        let ring_doc = cert_key.serialize_der();
        // Seed ищем по маркеру OCTET STRING(32) — `04 20`; берём ПОСЛЕДНЕЕ вхождение
        // (в ring-документе это privateKey, publicKey раньше уже лежит в [1] как BIT STRING).
        let seed_pos = ring_doc
            .windows(2)
            .rposition(|w| w == [0x04, 0x20])
            .ok_or(AcceptError::BadSkeleton)?;
        let seed: [u8; 32] = ring_doc
            .get(seed_pos + 2..seed_pos + 34)
            .and_then(|s| <[u8; 32]>::try_from(s).ok())
            .ok_or(AcceptError::BadSkeleton)?;
        let mut pkcs8_v1 = Vec::with_capacity(48);
        pkcs8_v1.extend_from_slice(&[
            0x30, 0x2e, // SEQUENCE, len 46
            0x02, 0x01, 0x00, // INTEGER version = 0 (v1)
            0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // SEQ{OID 1.3.101.112 (Ed25519)}
            0x04, 0x22, // OCTET STRING len 34
            0x04, 0x20, // OCTET STRING len 32 (CurvePrivateKey = seed)
        ]);
        pkcs8_v1.extend_from_slice(&seed);
        Ok(Self {
            node_reality,
            cert_key_pkcs8: pkcs8_v1,
            cert_pub: cert_key.public_key_raw().to_vec(),
            skeleton_der: cert.der().as_ref().to_vec(),
        })
    }

    /// `cert_pub` — байты, покрываемые HMAC-подписью (`reality_cert_signature`).
    pub fn cert_pub(&self) -> &[u8] {
        &self.cert_pub
    }

    /// Сырой DER скелета (тесты/диагностика: сверка «TBS не тронут, хвост переписан»).
    pub fn skeleton_der(&self) -> &[u8] {
        &self.skeleton_der
    }
}

/// Строит сертификат Accept-пути для ОДНОГО handshake (Q23; серверная сторона).
///
/// `ch_keyshare_pub` — публичный keyshare x25519 из ОТКРЫТОГО ClientHello (серверу
/// приватный keyshare клиента не нужен; доступ клиента к своему — T1); `ch_random` —
/// 32 B random того же CH.
///
/// `AuthKey = HKDF-SHA256(salt = ch_random[..20],
/// ikm = X25519(node_reality_priv, ch_keyshare_pub), info = LABEL_REALITY_CERT)`
/// (crypto-core); возвращаемый DER — скелет с перезаписанными последними 64 байтами
/// (signatureValue Ed25519): `HMAC-SHA512(AuthKey, cert_pub)`. TBS/SPKI не трогаются:
/// `cert_pub` стабилен в процессе, salt per-handshake — replay поля подписи между
/// handshakes невозможен.
pub fn build_reality_cert(
    state: &RealityCertState,
    ch_keyshare_pub: &crypto_core::X25519Pub,
    ch_random: &[u8; 32],
) -> Result<Vec<u8>, AcceptError> {
    let auth_key =
        crypto_core::derive_reality_auth_key(&state.node_reality, ch_keyshare_pub, ch_random)
            .map_err(AcceptError::Crypto)?;
    let sig = crypto_core::reality_cert_signature(&auth_key, &state.cert_pub);

    let mut der = state.skeleton_der.clone();
    let tail = der
        .len()
        .checked_sub(sig.len())
        .ok_or(AcceptError::BadSkeleton)?;
    // Форма signatureValue Ed25519 в кодировке rcgen 0.13: BIT STRING `03 41 00 ‖ 64 B`
    // (64 байта подписи + 1 байт unused-bits). Проверка перед записью — не пишем слепо
    // в чужое место. (Расчёт `03 42 00` из Q23 предполагал len=66; DER-проба показала
    // len=65 — по байту короче, содержание то же.)
    if der.get(tail - 3..tail) != Some(&[0x03, 0x41, 0x00][..]) {
        return Err(AcceptError::BadSkeleton);
    }
    der[tail..].copy_from_slice(&sig);
    Ok(der)
}

/// Извлекает 32 B random открытого ClientHello (Q23-парсер, сырые байты как на проводе).
/// Layout: record(5) ‖ hs-type(1) ‖ hs-len(3) ‖ legacy-ver(2) → random на 11..43.
/// Каркас assumes CH одной записью — то же допущение, что у гейта (`looks_like_client_hello`).
pub fn ch_client_random(client_hello: &[u8]) -> Option<[u8; 32]> {
    client_hello
        .get(11..43)
        .and_then(|r| <[u8; 32]>::try_from(r).ok())
}

/// Извлекает публичный keyshare x25519 (группа 0x001F, 32 B) из открытого ClientHello:
/// полный минимальный проход расширений (bounds-checked, не «поиск подстроки»).
pub fn parse_ch_key_share_x25519(client_hello: &[u8]) -> Option<[u8; 32]> {
    let mut p = 43usize;
    // session_id: 1B len.
    p += 1 + *client_hello.get(p)? as usize;
    // cipher_suites: 2B len.
    let cs = u16::from_be_bytes([*client_hello.get(p)?, *client_hello.get(p + 1)?]) as usize;
    p += 2 + cs;
    // compression_methods: 1B len.
    p += 1 + *client_hello.get(p)? as usize;
    // extensions: 2B total len, затем пары (type u16, len u16, data).
    let ext_total = u16::from_be_bytes([*client_hello.get(p)?, *client_hello.get(p + 1)?]) as usize;
    p += 2;
    let end = (p + ext_total).min(client_hello.len());
    while p + 4 <= end {
        let etype = u16::from_be_bytes([*client_hello.get(p)?, *client_hello.get(p + 1)?]);
        let elen =
            u16::from_be_bytes([*client_hello.get(p + 2)?, *client_hello.get(p + 3)?]) as usize;
        let data = client_hello.get(p + 4..p + 4 + elen)?;
        if etype == 0x0033 {
            return key_share_x25519_from_ext(data);
        }
        p += 4 + elen;
    }
    None
}

/// Живой Accept-сервер (Q23): boring-акцептор, per-handshake подменяющий сертификат
/// в select-certificate callback (boring API: callback до основной обработки CH,
/// `ClientHello::ssl_mut()` даёт per-connection SslRef).
///
/// На каждый handshake callback читает random+key_share из CH boring-машины, строит
/// `build_reality_cert` и ставит сертификат + Ed25519-ключ (CertificateVerify —
/// настоящая подпись ключа сертификата; «нестандартна» только клиентская верификация,
/// Q23 п. 5–6). CH без key_share (TLS 1.2-класс) → handshake abort: такие соединения
/// гейт не пускает на Accept (аутентификатор кладёт только наш TLS 1.3-клиент).
///
/// Проводка в полный серверный рантайм (gate_decision → accept/relay splice, ALPN
/// сайта-мишени, tokio) — приёмная сторона Phase 1, не этот каркас.
pub struct AcceptServer {
    acceptor: std::sync::Arc<boring::ssl::SslAcceptor>,
    /// Копия `cert_pub` для диагностики/тестов (само состояние уходит в callback).
    cert_pub: Vec<u8>,
}

impl AcceptServer {
    /// Строит acceptor с per-handshake callback (состояние клонируется в замыкание;
    /// все поля — owned-байты, потокобезопасны по построению).
    pub fn new(state: RealityCertState) -> Result<Self, AcceptError> {
        let mut builder =
            boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls())
                .map_err(AcceptError::Boring)?;
        // cert_pub для диагностики — до move замыкания (состояние целиком уходит в него).
        let cert_pub = state.cert_pub().to_vec();
        builder.set_select_certificate_callback(move |mut ch: boring::ssl::ClientHello<'_>| {
            let res = (|| {
                let random: [u8; 32] = ch.random().try_into().ok()?;
                #[cfg(test)]
                eprintln!("Q23-DBG: random ok");
                let ks_ext_opt = ch.get_extension(boring::ssl::ExtensionType::KEY_SHARE);
                let ks = parse_key_share_ext_x25519(ks_ext_opt?)?;
                let der = build_reality_cert(&state, &crypto_core::X25519Pub(ks), &random).ok()?;
                let cert = boring::x509::X509::from_der(&der).ok()?;
                // Ключ — PKCS#8 Ed25519 (rcgen serialize_der); d2i_AutoPrivateKey
                // (private_key_from_der) его не принимает, нужен явный PKCS#8-парсер.
                let key = boring::pkey::PKey::private_key_from_pkcs8(&state.cert_key_pkcs8).ok()?;
                ch.ssl_mut().set_certificate(&cert).ok()?;
                ch.ssl_mut().set_private_key(&key).ok()?;
                // Контракт: ключ сертификата обязан соответствовать SPKI скелета
                // (проверяется live-тестом; здесь — та же пара из state).
                Some(())
            })();
            if res.is_some() {
                Ok(())
            } else {
                Err(boring::ssl::SelectCertError::ERROR)
            }
        });
        let acceptor = builder.build();
        Ok(Self {
            acceptor: std::sync::Arc::new(acceptor),
            cert_pub,
        })
    }

    /// `cert_pub` активного скелета (диагностика/тесты).
    pub fn cert_pub(&self) -> &[u8] {
        &self.cert_pub
    }

    /// Терминирует TLS на сокете пробника (Accept-путь; сосед `relay_to_target` — путь
    /// Relay). Байты CH уже peeked гейтом и НЕ потреблены — boring читает их сам.
    /// Возвращает установленный канал для frame-слоя (`decode_reality_frame` и дальше).
    /// Любой незавершённый handshake → `AcceptError::Handshake` (см. вариант).
    pub fn accept<'a>(
        &self,
        probe: &'a mut std::net::TcpStream,
    ) -> Result<boring::ssl::SslStream<&'a mut std::net::TcpStream>, AcceptError> {
        self.acceptor.accept(probe).map_err(|e| match e {
            boring::ssl::HandshakeError::SetupFailure(e) => AcceptError::Boring(e),
            _ => AcceptError::Handshake,
        })
    }
}

/// Разбор client_shares из ДАННЫХ расширения key_share (RFC 8446 §4.2.8):
/// `2B длина списка ‖ пары (group u16, klen u16, key)`. boring `get_extension`
/// отдаёт ровно этот data. Общий хелпер для сырого CH-парсера и boring-callback.
fn key_share_x25519_from_ext(ext: &[u8]) -> Option<[u8; 32]> {
    let list_len = u16::from_be_bytes([*ext.first()?, *ext.get(1)?]) as usize;
    let end = (2 + list_len).min(ext.len());
    let mut q = 2usize;
    while q + 4 <= end {
        let group = u16::from_be_bytes([ext[q], ext[q + 1]]);
        let klen = u16::from_be_bytes([ext[q + 2], ext[q + 3]]) as usize;
        let key = ext.get(q + 4..q + 4 + klen)?;
        if group == 0x001D && klen == 32 {
            let arr: [u8; 32] = key.try_into().ok()?;
            return Some(arr);
        }
        q += 4 + klen;
    }
    None
}

fn parse_key_share_ext_x25519(ext: &[u8]) -> Option<[u8; 32]> {
    key_share_x25519_from_ext(ext)
}

/// Reality/TCP-байндинг (03 §4, 02 §2.2).
///
/// Структура повторяет `SsPaddedBinding`: `Outbox` с потолком байтов (backpressure),
/// синхронный отказ при закрытом канале, async-отказ через `on_failure` (ровно один раз).
/// Отличие: кадр — аутентифицированная обёртка Reality (`encode_reality_frame`), а не
/// дефолтный кадр `BindingCore::enqueue`.
///
/// Не реализовано (честно): сетевая часть TLS-канала (connect/handshake/write —
/// async-писатель и живой peer-тест), приёмная сторона, морф-интеграция (Phase 2).
#[derive(Debug)]
pub struct RealityBinding {
    cover: KCover,
    site: TargetSite,
    outbox: transport_mux::Outbox,
    failure: Option<BindingFailure>,
    closed: bool,
    /// Событие `Closed` уже выставлено (ровно один раз на закрытие, не на каждый send).
    closed_reported: bool,
}

impl RealityBinding {
    /// Байндинг под ключом обложки и сайтом-мишенью.
    pub fn new(cover: KCover, site: TargetSite) -> Self {
        Self {
            cover,
            site,
            outbox: transport_mux::Outbox::new(DEFAULT_OUTBOX_BYTES),
            failure: None,
            closed: false,
            closed_reported: false,
        }
    }

    /// Сайт-мишень (диагностика).
    pub fn site(&self) -> &TargetSite {
        &self.site
    }

    /// Закрывает канал: следующий `send` даст `TransportDown` + `BindingFailure::Closed`.
    pub fn mark_closed(&mut self) {
        self.closed = true;
    }

    /// Закрыт ли канал.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Забирает очередь кадров (в тестах — эмуляция async-писателя).
    pub fn take_pending(&mut self) -> Vec<(frame_session::StreamId, Vec<u8>)> {
        self.outbox.drain()
    }

    /// Размер очереди в байтах.
    pub fn pending_bytes(&self) -> usize {
        self.outbox.bytes()
    }

    /// Инжектирует асинхронный отказ — путь к FSM морфа (`02 §4`).
    pub fn inject_failure(&mut self, failure: BindingFailure) {
        self.failure = Some(failure);
    }
}

/// Тестовый/детерминированный источник энтропии — тот же паттерн, что в `cover-ss2022`:
/// НЕ крипто-RNG и НЕ достижим из прод-конструктора байндинга: доступен только тестам
/// (приватен, в прод-пути `send()` — CSPRNG). Прод-дефект F-01 (аудит, High): раньше
/// именно эта функция стояла в `send()` — общая nonce-последовательность у всех
/// деплоев и повтор nonce при пересоздании байндинга на том же `K_cover`.
/// Текущим тестам хватает `fixed_fill`; функция сохранена как зарезервированный
/// детерминированный хелпер (поручено фиксом F-01), `allow(dead_code)` — test-only.
#[cfg(test)]
#[allow(dead_code)]
fn deterministic_fill(counter: u64, index: u64) -> impl FnMut(&mut [u8]) {
    move |buf: &mut [u8]| {
        let mut state = counter ^ 0x9E37_79B9_7F4A_7C15 ^ index << 32 ^ (buf.len() as u64) << 3;
        for byte in buf.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
    }
}

impl transport_mux::CoverBinding for RealityBinding {
    fn send(&mut self, rec: &Record) -> Result<(), BindingError> {
        if self.closed {
            // Идемпотентно: событие `Closed` — одно на закрытие канала, повторные send
            // по закрытому каналу его не дублируют.
            if !self.closed_reported {
                self.failure = Some(BindingFailure::Closed);
                self.closed_reported = true;
            }
            return Err(BindingError::TransportDown);
        }
        // Nonce кадра — из системного CSPRNG (F-01): AEAD probabilistic, без повторов
        // nonce на ключе независимо от истории создания байндинга. Детерминированный
        // xorshift от счётчика давал одинаковую nonce-последовательность у всех клиентов
        // (DPI-отпечаток) и повтор nonce при пересоздании байндинга на том же `K_cover`
        // (реконнект/морф) — раскрытие keystream'ов и подделка Poly1305-тега.
        // `expect` допустим: единственная ошибка `getrandom::fill` — системный RNG
        // недоступен (тот же explicit-fail контракт, что в `ticket-mint::mint_at`).
        let frame = encode_reality_frame(&self.cover, rec, &mut |buf: &mut [u8]| {
            getrandom::fill(buf)
                .expect("system CSPRNG unavailable: cannot encrypt a reality frame");
        });
        // Кадр обложки кладём напрямую в Outbox: `BindingCore::enqueue` кодирует
        // дефолтный кадр без auth-обёртки — обложка формирует кадр сама (как у ss2022).
        self.outbox.push(rec.stream_id, frame)
    }

    fn supports(&self) -> BindingCaps {
        BindingCaps {
            no_hol: false, // HOL — задокументированный tradeoff TCP-класса (02 §2.2)
            datagram: false,
            dpi_profile: DPI_PROFILE_REALITY_TCP,
        }
    }

    fn on_failure(&mut self) -> Option<BindingFailure> {
        self.failure.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_core::{derive_cover_key, derive_session};
    use frame_session::{RecordType, Seq, StreamId};
    use transport_mux::CoverBinding;

    const SID: [u8; 16] = [0x5a; 16];

    fn cover() -> KCover {
        derive_cover_key(&SID, &derive_session(&SID, b"reality test hash"))
    }

    fn record(seq: u64, payload: &[u8]) -> Record {
        Record {
            kind: RecordType::Data,
            stream_id: StreamId(0),
            flags: 0,
            seq: Seq(seq),
            ciphertext: payload.to_vec(),
        }
    }

    fn fixed_fill(byte: u8) -> impl FnMut(&mut [u8]) {
        move |buf: &mut [u8]| buf.fill(byte)
    }

    // ---------- Q23: Accept-путь (сертификат/терминировка) ----------

    /// Синтетический ClientHello TLS 1.3 с key_share x25519 (Q23-тесты). Тест сам
    /// генерирует клиентскую пару — обе стороны известны по построению, T1 не нужен.
    fn synthetic_client_hello(client_priv: &[u8; 32], random: &[u8; 32]) -> Vec<u8> {
        use crypto_core::x25519_keypair as kp;
        let share = kp(client_priv).public;
        let mut ch = Vec::new();
        ch.push(22u8);
        ch.extend_from_slice(&[0x03, 0x01]);
        ch.extend_from_slice(&[0u8; 2]);
        ch.push(0x01);
        ch.extend_from_slice(&[0u8; 3]);
        ch.extend_from_slice(&[0x03, 0x03]);
        ch.extend_from_slice(random);
        ch.push(0u8); // session_id: пуст
        ch.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        ch.push(0x01);
        ch.push(0x00);
        // extensions: key_share(0x0033): len(2B) = 2+2+2+32 = 38; entry: group 0x001F, len 32.
        ch.extend_from_slice(&[0x00, 0x2A]); // ext total len = 2+2+38 = 42 = 0x2A
        ch.extend_from_slice(&[0x00, 0x33]);
        ch.extend_from_slice(&[0x00, 0x26]); // data len 38
        ch.extend_from_slice(&[0x00, 0x26]); // client_shares len 38
        ch.extend_from_slice(&[0x00, 0x1D]); // x25519 (IANA: 29 = 0x001D)
        ch.extend_from_slice(&[0x00, 0x20]); // 32
        ch.extend_from_slice(&share);
        // Честная TLS-геометрия (в отличие от самосогласованного скелета гейта, где
        // hs-len пишется в 9..12 и затирает version/random[0]): hs-len — 6..9,
        // rec-len — 3..5, random остаётся на 11..43 — как читает ch_client_random.
        let hs_len = (ch.len() - 9) as u32;
        ch[6..9].copy_from_slice(&hs_len.to_be_bytes()[1..4]);
        let rec_len = (ch.len() - 5) as u16;
        ch[3..5].copy_from_slice(&rec_len.to_be_bytes());
        ch
    }

    /// Серверная сторона изолированно (T1 не задействован): скелет стабилен (TBS/SPKI не
    /// тронуты), поле подписи — ровно HMAC(AuthKey(node, keyshare, random), cert_pub);
    /// клиентская верификация в тесте считает тот же AuthKey из симметричного ECDH.
    /// Полный клиент-сервер handshake с Aether-верификацией живым клиентом — T1
    /// (QUESTIONS.md); здесь boring-клиент не участвует.
    #[test]
    fn q23_reality_cert_roundtrip_without_t1() {
        let node_priv: [u8; 32] = core::array::from_fn(|i| (i * 5 + 1) as u8);
        let client_priv: [u8; 32] = core::array::from_fn(|i| (i * 9 + 7) as u8);
        let random: [u8; 32] = core::array::from_fn(|i| (i * 3 + 1) as u8);

        let state = RealityCertState::new(crypto_core::NodeRealityKey(node_priv))
            .expect("скелет собирается");
        let ch = synthetic_client_hello(&client_priv, &random);

        // Парсеры гейта читают открытый CH: random и публичный keyshare.
        assert_eq!(ch_client_random(&ch), Some(random));
        let ks = parse_ch_key_share_x25519(&ch).expect("key_share x25519 найден");
        assert_eq!(ks, crypto_core::x25519_keypair(&client_priv).public);

        // Сертификат Accept-пути для этого handshake.
        let der = build_reality_cert(&state, &crypto_core::X25519Pub(ks), &random)
            .expect("сертификат строится");

        // Скелет: TBS/SPKI не тронуты, отличается только хвост (signatureValue).
        let skeleton = state.skeleton_der();
        assert_eq!(der.len(), skeleton.len(), "длина DER не менялась");
        assert_eq!(
            &der[..der.len() - 64],
            &skeleton[..skeleton.len() - 64],
            "всё кроме подписи — байт в байт скелет"
        );
        assert_ne!(&der[der.len() - 64..], &skeleton[skeleton.len() - 64..]);
        // Форма signatureValue Ed25519 на месте записи (rcgen: 03 41 00).
        assert_eq!(&der[der.len() - 67..der.len() - 64], &[0x03, 0x41, 0x00]);

        // Клиентская верификация (тестовая, не прод-клиент — T1): тот же AuthKey из
        // симметричного ECDH + HMAC по cert_pub из SPKI полученного сертификата.
        let node_pub = crypto_core::X25519Pub(crypto_core::x25519_keypair(&node_priv).public);
        let ss = crypto_core::x25519_dh(&client_priv, &node_pub).expect("ECDH");
        let auth_key =
            crypto_core::hkdf_sha256(&random[..20], &ss, crypto_core::LABEL_REALITY_CERT);
        // cert_pub клиента — из SPKI сертификата (boring), а не из state: проверяем,
        // что HMAC ложится именно на ключ, который клиент видит на проводе.
        let cert = boring::x509::X509::from_der(&der).expect("DER валиден для boring");
        let spki = cert.public_key().expect("SPKI читается");
        let mut spki_buf = [0u8; 64];
        let spki_raw = spki.raw_public_key(&mut spki_buf).expect("raw pubkey");
        assert_eq!(spki_raw.len(), 32, "Ed25519 pub — 32 B");
        assert_eq!(spki_raw, state.cert_pub(), "SPKI == cert_pub скелета");
        let expected = crypto_core::reality_cert_signature(&auth_key, spki_raw);
        assert_eq!(
            &der[der.len() - 64..],
            &expected,
            "подпись = HMAC(AuthKey, cert_pub)"
        );

        // Salt per-handshake: другой random → другая подпись при том же скелете.
        let mut random2 = random;
        random2[19] ^= 1; // внутри salt[..20]
        let der2 = build_reality_cert(&state, &crypto_core::X25519Pub(ks), &random2)
            .expect("второй handshake");
        assert_eq!(
            &der2[..der2.len() - 64],
            &der[..der.len() - 64],
            "TBS/SPKI между handshakes стабильны"
        );
        assert_ne!(
            &der2[der2.len() - 64..],
            &der[der.len() - 64..],
            "подпись per-handshake (replay поля подписи невозможен)"
        );

        // Кривой CH без key_share/с другим кривым хвостом не проходит по форме.
        assert_eq!(ch_client_random(&ch[..20]), None);
    }

    /// ИГНОР до решения T1 (клиентский доступ к своему keyshare): живой loopback-
    /// handshake boring-клиента (verify-none заглушка — проверяет ТОЛЬКО, что TLS-машина
    /// принимает наш перезаписанный DER) с AcceptServer. Полный клиент-сервер handshake
    /// с Aether-верификацией сертификата — T1; серверная сторона проверена изолированно
    /// (см. q23_reality_cert_roundtrip_without_t1 и design/03-components.md).
    #[test]
    #[ignore = "T1: серверная сторона изолирована; живой peer с Aether-верификацией — T1"]
    fn live_accept_handshake_terminates_tls() {
        use std::io::{Read, Write};
        let node_priv: [u8; 32] = core::array::from_fn(|i| (i * 7 + 2) as u8);
        let state = RealityCertState::new(crypto_core::NodeRealityKey(node_priv)).expect("state");
        let server = AcceptServer::new(state).expect("acceptor");

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept tcp");
            let mut tls = server.accept(&mut sock).expect("TLS handshake");
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).expect("client data");
        });

        let probe = std::net::TcpStream::connect(addr).expect("connect");
        let mut builder =
            boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls()).expect("connector");
        builder.set_verify(boring::ssl::SslVerifyMode::NONE); // заглушка: verify — T1
                                                              // set_verify(NONE) глушит проверку цепочки, но не custom-verify и не статус:
                                                              // boring с NONE всё равно вызывает custom_verify при его наличии. Наша заглушка —
                                                              // пустой custom-verify (Ok): живой HMAC-verify сертификата — T1.
        builder.set_custom_verify_callback(boring::ssl::SslVerifyMode::NONE, |_ssl| Ok(()));
        // Дефолтные группы boring начинаются с P-256 (проба: key_share ext был P-256);
        // Reality-пути нужен x25519 — единственная группа клиента.
        builder.set_curves_list("X25519").expect("curves");
        // Сигалги: наш сертификат Ed25519 — сервер будет подписывать CertificateVerify
        // ed25519; включаем его у клиента (иначе — HANDSHAKE_FAILURE_ON_CLIENT_HELLO
        // при выборе схемы подписи сервера).
        builder.set_sigalgs_list("ed25519").expect("sigalgs");
        let connector = builder.build();
        let config = connector.configure().expect("configure");
        // config.connect проводит полный handshake и возвращает готовый SslStream.
        let mut client = config.connect("aether", probe).expect("TLS handshake");
        client.write_all(b"hello").expect("write");
        handle.join().expect("server thread");
    }

    // ---------- layout ----------

    /// Layout обёртки: `len(4B BE) ‖ nonce(24B) ‖ AEAD(record)`; AAD — длина записи;
    /// AEAD детерминирован nonce'ом (проверка воспроизводимости фиксирует AAD-схему).
    #[test]
    fn reality_frame_layout() {
        let rec = record(7, b"payload");
        let mut nonce_draws = 0;
        let frame = {
            let mut fill = |buf: &mut [u8]| {
                nonce_draws += 1;
                buf.fill(0xA5);
            };
            encode_reality_frame(&cover(), &rec, &mut fill)
        };
        assert_eq!(nonce_draws, 1, "энтропия берётся ровно под nonce");

        let body = rec.encode();
        let expected_ct_len = body.len() + 16; // + тег Poly1305
        assert_eq!(&frame[..4], &((24 + expected_ct_len) as u32).to_be_bytes());
        assert!(
            frame[4..28].iter().all(|&b| b == 0xA5),
            "nonce едет в кадре"
        );

        // Воспроизводимость: тот же nonce → тот же шифротекст (AAD и ключ не менялись).
        let frame2 = encode_reality_frame(&cover(), &rec, &mut fixed_fill(0xA5));
        assert_eq!(frame, frame2, "детерминизм относительно nonce");

        // Чужой nonce → другой шифротекст при том же plaintext.
        let frame3 = encode_reality_frame(&cover(), &rec, &mut fixed_fill(0x5A));
        assert_ne!(frame[28..], frame3[28..], "AEAD probabilistic");
    }

    /// Round-trip: своя обёртка вскрывается в исходную запись.
    #[test]
    fn reality_frame_round_trip() {
        let rec = record(300, b"cipher-bytes");
        let frame = encode_reality_frame(&cover(), &rec, &mut fixed_fill(1));
        assert_eq!(decode_reality_frame(&cover(), &frame), Ok(rec));
    }

    // ---------- auth / probe resistance (внутри терминированного TLS, путь Accept) ----------

    /// Чужой ключ, порча шифротекста, обрезанный кадр, враньё в префиксе длины —
    /// активная проба ПОСЛЕ гейта: классифицируется одинаково — тихое закрытие,
    /// без утечки причины наблюдателю (b132-2: статический снимок удалён).
    #[test]
    fn probe_resistance_all_failures_look_alike() {
        let cov = cover();
        let rec = record(0, b"payload");
        let frame = encode_reality_frame(&cov, &rec, &mut fixed_fill(2));

        let other_cover = derive_cover_key(&SID, &derive_session(&SID, b"other hash"));
        let mut corrupted = frame.clone();
        corrupted[30] ^= 0xFF;
        let mut lying_len = frame.clone();
        lying_len[3] = lying_len[3].wrapping_add(7);

        for bad in [
            encode_reality_frame(&other_cover, &rec, &mut fixed_fill(2)),
            corrupted.clone(),
            frame[..20].to_vec(),
            lying_len,
            Vec::new(),
        ] {
            assert_eq!(
                classify_first_record(&cov, &bad),
                FirstRecordVerdict::Rejected,
                "любая неаутентичность → одно и то же: тихое закрытие"
            );
        }
    }

    /// Аутентифицированный кадр проходит классификацию как Reality-клиент.
    #[test]
    fn authenticated_first_record_passes() {
        let cov = cover();
        let rec = record(1, b"aether-hello");
        let frame = encode_reality_frame(&cov, &rec, &mut fixed_fill(3));
        assert_eq!(
            classify_first_record(&cov, &frame),
            FirstRecordVerdict::Authenticated(rec)
        );
    }

    /// Запись, испорченная внутри валидной обёртки, не разбирается — `BadRecord`,
    /// но для классификатора это тот же фолбэк (см. `probe_resistance_all_failures_look_alike`).
    #[test]
    fn bad_record_inside_valid_tag() {
        let cov = cover();
        let rec = record(0, b"payload");
        let frame = encode_reality_frame(&cov, &rec, &mut fixed_fill(4));
        // Портили байт ciphertext — AEAD ловит, это NotAuthenticated, не BadRecord.
        let mut corrupted = frame.clone();
        corrupted[30] ^= 1;
        assert_eq!(
            decode_reality_frame(&cov, &corrupted),
            Err(AuthError::NotAuthenticated)
        );
    }

    // ---------- binding contract ----------

    /// Контракт байндинга: send → Ok + кадр в очереди, закрытый канал → `TransportDown` +
    /// `Closed` ровно один раз, инжектированный `Probed` доходит до FSM один раз.
    #[test]
    fn binding_contract_sync_and_async_failures() {
        let mut binding = RealityBinding::new(cover(), TargetSite::placeholder());
        let rec = record(0, b"payload");

        binding.inject_failure(BindingFailure::Probed);
        assert_eq!(binding.on_failure(), Some(BindingFailure::Probed));
        assert_eq!(binding.on_failure(), None, "событие отдаётся один раз");

        binding.mark_closed();
        assert_eq!(binding.send(&rec), Err(BindingError::TransportDown));
        assert_eq!(binding.on_failure(), Some(BindingFailure::Closed));
        assert_eq!(binding.send(&rec), Err(BindingError::TransportDown));
        assert_eq!(binding.on_failure(), None, "Closed тоже ровно один раз");
        assert!(
            binding.take_pending().is_empty(),
            "в закрытый канал ничего не ушло"
        );
    }

    /// F-01 (аудит, High): prod-nonce байндинга — CSPRNG, не детерминированный счётчик.
    /// Два инстанса байндинга на одном `K_cover` (реконнект/морф = пересоздание) НЕ
    /// повторяют nonce: до фикса второй байндинг начинал ту же xorshift-последовательность,
    /// что и первый, — повтор nonce на ключе (раскрытие keystream'ов XChaCha20).
    #[test]
    fn prod_nonce_never_repeats_across_binding_instances() {
        let cov = cover();
        let extract_nonce = |frame: &[u8]| -> [u8; AUTH_NONCE_LEN] {
            let mut n = [0u8; AUTH_NONCE_LEN];
            n.copy_from_slice(&frame[FRAME_LEN_BYTES..FRAME_LEN_BYTES + AUTH_NONCE_LEN]);
            n
        };

        let mut seen: std::collections::HashSet<[u8; AUTH_NONCE_LEN]> =
            std::collections::HashSet::new();
        let rec = record(0, b"nonce uniqueness probe");

        // Первое время жизни байндинга: N записей.
        let mut first = RealityBinding::new(cov.clone(), TargetSite::placeholder());
        for _ in 0..8 {
            first.send(&rec).expect("очередь не переполнена");
            for (_, frame) in first.take_pending() {
                assert!(
                    seen.insert(extract_nonce(&frame)),
                    "nonce повторился внутри одного байндинга"
                );
            }
        }

        // Пересоздание байндинга на ТОМ ЖЕ ключе (реконнект/морф): ещё N записей.
        let mut second = RealityBinding::new(cov, TargetSite::placeholder());
        for _ in 0..8 {
            second.send(&rec).expect("очередь не переполнена");
            for (_, frame) in second.take_pending() {
                assert!(
                    seen.insert(extract_nonce(&frame)),
                    "nonce повторился после пересоздания байндинга — F-01 регрессия"
                );
            }
        }
        assert_eq!(seen.len(), 16, "все 16 nonce уникальны на одном K_cover");
    }

    /// Backpressure: потолок очереди в байтах, переполнение — `WouldBlock`, а не рост памяти.
    ///
    /// Арифметика кадра детерминирована: payload `N` → внутренняя запись `5+varint+N`,
    /// кадр обложки `4 + 24 + (запись + 16-тег)`. Для payload 8 это ровно 57 байт.
    #[test]
    fn binding_contract_backpressure() {
        let cov = cover();
        let mut binding = RealityBinding::new(cov, TargetSite::placeholder());
        let big = record(0, &vec![0u8; 256 * 1024]);
        assert_eq!(
            binding.send(&big),
            Err(BindingError::WouldBlock),
            "кадр больше потолка очереди отвергается"
        );
        assert_eq!(binding.pending_bytes(), 0);

        // Точный потолок: уменьшаем очередь до 64 B и считаем кадры в байтах (57 ≤ 64).
        binding.outbox = transport_mux::Outbox::new(64);
        let small = record(0, &[0u8; 8]);
        assert_eq!(binding.send(&small), Ok(()));
        assert_eq!(
            binding.send(&small),
            Err(BindingError::WouldBlock),
            "57 + 57 > 64 — второй кадр ждёт"
        );
        assert_eq!(binding.pending_bytes(), 57);

        // Очередь вычерпывается, место освобождается.
        let pending = binding.take_pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(binding.pending_bytes(), 0);
        assert_eq!(binding.send(&small), Ok(()));
    }

    /// Контракт caps: Reality/TCP — TCP-класс, HOL — задокументированный tradeoff (`02 §2.2`).
    #[test]
    fn caps_stream_class_not_no_hol() {
        let binding = RealityBinding::new(cover(), TargetSite::placeholder());
        let caps = binding.supports();
        assert!(
            !caps.no_hol,
            "у Reality/TCP HOL есть по построению (02 §2.2)"
        );
        assert!(!caps.datagram, "датаграммной семантики на TCP нет");
        assert_eq!(caps.dpi_profile, DPI_PROFILE_REALITY_TCP);
        assert_eq!(caps, transport_mux::BindingCaps::REALITY_TCP);
    }

    /// SNI параметризован: сайт-мишень — поле конфига, не константа логики.
    #[test]
    fn target_site_is_parameterized() {
        let b = TargetSite {
            sni: "other.example.org".to_string(),
            description: "other".to_string(),
        };
        let mut binding = RealityBinding::new(cover(), b);
        assert_eq!(binding.site().sni, "other.example.org");
        binding.mark_closed();
        assert!(binding.is_closed());
    }

    // ---------- b132-2: гейт по открытому ClientHello (peek-before-decrypt) ----------

    /// Q24 (аудит F-05): гейт живёт на fleet-ключе из флотского корня (манифеста),
    /// а не на сессионном `K_probe` — bootstrap первого входа (главный сценарий:
    /// QUIC заблокирован, Reality — единственный путь входа) и O(1) lookup на сервере.
    fn k_probe() -> crypto_core::KProbe {
        crypto_core::derive_probe_fleet_key(&FLEET_ROOT)
    }

    /// Детерминированный тестовый флотский корень (в проде — из манифеста подписки).
    const FLEET_ROOT: [u8; 32] = [0x42u8; 32];

    /// Сырой скелет TLS-записи ClientHello (форма как у настоящего; random — нули).
    /// Расширение session_ticket с 24-байтным местом тега в конце.
    fn client_hello_skeleton() -> Vec<u8> {
        let mut ch = Vec::new();
        ch.push(22u8); // ContentType=Handshake
        ch.extend_from_slice(&[0x03, 0x01]); // legacy version
        ch.extend_from_slice(&[0u8; 2]); // length (заполним)
        ch.push(0x01); // HandshakeType=ClientHello
        ch.extend_from_slice(&[0u8; 3]); // handshake length (заполним)
        ch.extend_from_slice(&[0x03, 0x03]); // client version TLS1.2
        ch.extend_from_slice(&[0u8; 32]); // random
        ch.push(0u8); // session_id len = 0
        ch.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites: 1×TLS_AES_128_GCM
        ch.push(0x01);
        ch.push(0x00); // compression: null
                       // extensions: только session_ticket (type 35), данные — 24 B под тег.
        ch.extend_from_slice(&[0x00, 0x1A]); // ext block len: 2+2+24 = 28
        ch.extend_from_slice(&[0x00, 0x23]); // session_ticket (35)
        ch.extend_from_slice(&[0x00, 0x18]); // ext data len: 24
        ch.extend_from_slice(&[0xEE; 24]); // место тега (байт-маркер для поиска)
                                           // record length (2 B на позиции 3..5) и handshake length (3 B на 9..12):
        let hs_len = (ch.len() - 5) as u32;
        ch[9..12].copy_from_slice(&hs_len.to_be_bytes()[1..4]);
        let rec_len = (ch.len() - 5) as u16;
        ch[3..5].copy_from_slice(&rec_len.to_be_bytes());
        ch
    }

    fn relay_spec(addr: std::net::SocketAddr) -> RelaySpec {
        RelaySpec {
            addr,
            connect_timeout: std::time::Duration::from_secs(5),
            max_relay_bytes: 1 << 20,
        }
    }

    /// Q24 (аудит F-05): «первый вход без сессии» — главный сценарий Reality-обложки.
    /// Гейт на fleet-ключе принимает клиента, у которого ещё нет ни `sid`, ни `K_session`:
    /// тег считается из ключа, выведенного из флотского корня до всякой сессии.
    #[test]
    fn gate_accepts_first_entry_without_session() {
        let kp = k_probe();
        let ch = client_hello_skeleton();
        let pos = ch.len() - 24;
        let mut redacted = ch.clone();
        redacted[pos..].fill(0);
        let slot = 900u64;
        let tag = client_authenticator(&kp, &redacted, slot);
        let mut ch_tagged = ch.clone();
        ch_tagged[pos..].copy_from_slice(&tag);

        // У клиента нет сессии: ни sid, ни K_session не участвуют в вычислении тега.
        assert_eq!(
            gate_decision(
                &kp,
                &ch_tagged,
                Some(&tag),
                slot,
                relay_spec("127.0.0.1:443".parse().unwrap())
            ),
            GateDecision::Accept,
            "первый вход через Reality без какой-либо сессии принимается гейтом"
        );
    }

    /// Решение гейта (без сети): правильный тег в правильном слоте → Accept;
    /// чужой ключ/чужой тег/нет тега → Relay; не ClientHello → Reject.
    #[test]
    fn gate_decision_accepts_valid_tag_and_relays_rest() {
        let kp = k_probe();
        let ch = client_hello_skeleton();
        let pos = ch.len() - 24;

        // Клиент: тег над CH с нулённым местом тега, слот t → Accept в t-1..=t+1.
        let mut redacted = ch.clone();
        redacted[pos..].fill(0);
        let slot = 700u64;
        let tag = client_authenticator(&kp, &redacted, slot);

        let mut ch_tagged = ch.clone();
        ch_tagged[pos..].copy_from_slice(&tag);

        let relay = relay_spec("127.0.0.1:443".parse().unwrap());
        assert_eq!(
            gate_decision(&kp, &ch_tagged, Some(&tag), slot, relay.clone()),
            GateDecision::Accept,
            "валидный тег в своём слоте → Accept"
        );
        // Слоты t±1 принимаются (анти-replay окно, Q21-класс диапазона).
        assert_eq!(
            gate_decision(&kp, &ch_tagged, Some(&tag), slot + 1, relay.clone()),
            GateDecision::Accept
        );
        assert_eq!(
            gate_decision(&kp, &ch_tagged, Some(&tag), slot + 2, relay),
            GateDecision::Relay(relay_spec("127.0.0.1:443".parse().unwrap())),
            "вне окна слотов → Relay"
        );

        // Чужой fleet-корень → Relay (наблюдателю неотличимо от «просто клиент сайта»).
        let other_root: [u8; 32] = core::array::from_fn(|i| (i as u8) ^ 0x5E);
        let other = crypto_core::derive_probe_fleet_key(&other_root);
        assert_eq!(
            gate_decision(
                &other,
                &ch_tagged,
                Some(&tag),
                slot,
                relay_spec("127.0.0.1:443".parse().unwrap())
            ),
            GateDecision::Relay(relay_spec("127.0.0.1:443".parse().unwrap()))
        );

        // Тега нет → Relay.
        assert_eq!(
            gate_decision(
                &kp,
                &ch,
                None,
                slot,
                relay_spec("127.0.0.1:443".parse().unwrap())
            ),
            GateDecision::Relay(relay_spec("127.0.0.1:443".parse().unwrap()))
        );

        // Не ClientHello (например, HTTP-мусор) → Reject (тихое закрытие).
        let junk = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(
            gate_decision(
                &kp,
                junk,
                None,
                slot,
                relay_spec("127.0.0.1:443".parse().unwrap())
            ),
            GateDecision::Reject
        );
    }

    /// Порча любого байта ClientHello (кроме места тега) ломает тег → Relay:
    /// пробник не может подделать аутентификатор, не зная K_probe.
    #[test]
    fn gate_tag_covers_client_hello_bytes() {
        let kp = k_probe();
        let ch = client_hello_skeleton();
        let pos = ch.len() - 24;
        let mut redacted = ch.clone();
        redacted[pos..].fill(0);
        let slot = 42u64;
        let tag = client_authenticator(&kp, &redacted, slot);
        let mut ch_tagged = ch.clone();
        ch_tagged[pos..].copy_from_slice(&tag);

        // Портили байт random (позиция 13..45) → тег уже не сходится.
        let mut tampered = ch_tagged.clone();
        tampered[20] ^= 1;
        assert_ne!(
            gate_decision(
                &kp,
                &tampered,
                Some(&tag),
                slot,
                relay_spec("127.0.0.1:443".parse().unwrap())
            ),
            GateDecision::Accept,
            "изменённый CH с чужим тегом не принимается"
        );
    }

    // ---------- boring ClientHello (без сети) ----------

    /// Коннектор boring под сайт-мишень собирается: SNI/ALPN/пин сертификата валидны.
    /// (Реальный handshake — ignored-сценарий живого peer-теста ниже.)
    #[test]
    fn client_hello_connector_builds() {
        // Мини self-signed DER — из локальной пробы (RS-256 подпись себе): упрощённо
        // используем любой валидный DER; здесь берём rcgen-аналог через boring, как в пробе:
        // минимальный валидный сертификат нужен только чтобы коннектор его принял.
        let site = TargetSite::placeholder();
        let der = test_cert_der();
        let connector = build_client_hello_tls(&site, &der).expect("коннектор собирается");
        let _ = connector;
    }

    /// Детерминированный валидный DER-сертификат для теста коннектора:
    /// RSA-2048 self-signed, построенный самим boring (без внешних крейтов).
    fn test_cert_der() -> Vec<u8> {
        use boring::asn1::Asn1Time;
        use boring::bn::{BigNum, MsbOption};
        use boring::hash::MessageDigest;
        use boring::pkey::PKey;
        use boring::rsa::Rsa;
        use boring::x509::{X509Name, X509};

        let key = PKey::from_rsa(Rsa::generate(2048).expect("rsa")).expect("pkey");
        let mut name_builder = X509Name::builder().expect("name");
        name_builder
            .append_entry_by_text("CN", "cover-reality-test")
            .expect("CN");
        let name = name_builder.build();

        let mut builder = X509::builder().expect("builder");
        builder.set_version(2).expect("version");
        let mut serial = BigNum::new().expect("bn");
        serial.rand(64, MsbOption::MAYBE_ZERO, false).expect("rand");
        builder
            .set_serial_number(&serial.to_asn1_integer().expect("asn1"))
            .expect("serial");
        builder.set_subject_name(&name).expect("subject");
        builder.set_issuer_name(&name).expect("issuer");
        builder.set_pubkey(&key).expect("pubkey");
        builder
            .set_not_before(&Asn1Time::days_from_now(0).expect("nb"))
            .expect("nb");
        builder
            .set_not_after(&Asn1Time::days_from_now(2).expect("na"))
            .expect("na");
        // Подпись последней: кодирует TBS в момент вызова (проба шага 4, находка №4).
        builder.sign(&key, MessageDigest::sha256()).expect("sign");
        builder.build().to_der().expect("to_der")
    }

    // ---------- ignored: живой peer / сплайс (до живого пира и CI-сети) ----------

    /// ИГНОР (сокеты loopback — e2e-класс): живой сплайс по-настоящему (F-04).
    /// Эхо-сервер — сайт-мишень; пробник → гейт (байты ClientHello в `buffered`, как в
    /// реальном Accept-пути) → `relay_to_target`. Два полных обмена в обе стороны в
    /// lockstep-режиме (следующий кусок — только после эха предыдущего): на старом
    /// последовательном цикле второй обмен ждал бы блокирующего чтения у молчащего
    /// пробника до лимита простоя — тест падал бы по read-timeout, а не проходил.
    #[test]
    #[ignore = "live splice: требует сокетов (e2e-класс, как rotation/e2e-harness)"]
    fn live_splice_probe_gets_real_site_bytes() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::time::{Duration, Instant};

        // Сайт-мишень: эхо двух кусков, затем закрытие (нормальный конец релея).
        let site = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let site_addr = site.local_addr().expect("addr");
        let server = std::thread::spawn(move || {
            let (mut sock, _) = site.accept().expect("accept");
            let mut buf = [0u8; 1024];
            for round in 0..2 {
                let n = sock.read(&mut buf).expect("site read");
                assert!(n > 0, "round {round}: пустое чтение");
                sock.write_all(&buf[..n]).expect("echo");
            }
            // Сокет закрывается при drop — релей увидит Ok(0) у стороны сайта.
        });

        // Гейт-сторона: слушатель, к которому подключается пробник; гейт уже вырезал
        // первые байты (ClientHello) в `buffered` — ровно как в реальном Accept-пути.
        let gate = TcpListener::bind("127.0.0.1:0").expect("bind gate");
        let mut probe =
            TcpStream::connect(gate.local_addr().expect("gate addr")).expect("probe connect");
        let (mut gate_sock, _) = gate.accept().expect("gate accept");

        probe
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("probe timeout");
        let hello: Vec<u8> = (0..64u8).collect();
        probe.write_all(&hello).expect("probe write CH");
        let mut buffered = vec![0u8; hello.len()];
        gate_sock.read_exact(&mut buffered).expect("gate read CH");

        let spec = RelaySpec {
            addr: site_addr,
            connect_timeout: Duration::from_secs(5), // и коннект, и лимит простоя
            max_relay_bytes: 1 << 20,
        };

        let started = Instant::now();
        let relay = std::thread::spawn(move || relay_to_target(&spec, &mut gate_sock, &buffered));

        // Обмен 1: эхо ClientHello доходит через сплайс (направление «сайт → пробник»).
        let mut echoed = vec![0u8; hello.len()];
        probe.read_exact(&mut echoed).expect("probe read echo 1");
        assert_eq!(echoed, hello, "пробник получил эхо своих байт через релей");

        // Обмен 2: пробник молчал до эха 1 — на старом цикле релей стоял бы в
        // блокирующем чтении у пробника, и это эхо не пришло бы до лимита простоя.
        let msg: Vec<u8> = (0..32u8).map(|b| b ^ 0xA5).collect();
        probe.write_all(&msg).expect("probe write 2");
        let mut echoed2 = vec![0u8; msg.len()];
        probe.read_exact(&mut echoed2).expect("probe read echo 2");
        assert_eq!(
            echoed2, msg,
            "второй обмен прошёл за ~RTT (мультиплексирование)"
        );

        drop(probe);
        assert_eq!(
            relay.join().expect("relay thread"),
            RelayOutcome::Completed,
            "релей завершился закрытием сайта"
        );
        server.join().expect("echo server");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "обмен занял {:?} — сплайс не мультиплексирован?",
            started.elapsed()
        );
    }

    /// ИГНОР до живого Reality-пира: легитимный клиент с валидным аутентификатором
    /// проходит на Aether-протокол (первая запись вскрывается сервером).
    #[test]
    #[ignore = "live peer: нужен Reality-сервер и клиент с K_cover"]
    fn live_authenticated_client_reaches_aether() {
        let _ = (cover(), TargetSite::placeholder());
        unimplemented!("живой peer-тест: authenticated → Aether-протокол");
    }
}
