//! `cover-ss2022` — обложка Phase 1, кусок 1: **Aether padded cover** (fallback-класс).
//!
//! **In:** уже sealed records frame-слоя (`frame_session::Record`), не сырой IP.
//! **Out:** кадры `len(4B BE) ‖ nonce(24B) ‖ AEAD(record ‖ pad)` в TCP-класс канал.
//! **Deps:** `crypto-core` (AEAD + KDF обложки), `frame-session` (типы записей),
//! `transport-mux` (контракт `CoverBinding`, `BindingCore`).
//!
//! ## Честное имя и границы клейма
//!
//! Внешних тест-векторов shadowsocks-2022 (фиксированные поля wire-формата, их salt/
//! derivation, EigenState-заголовок) у проекта нет, поэтому **клейм «SS-2022 interop»
//! не делается**: тип называется `SsPaddedBinding`, а формат — «Aether padded cover».
//! Если векторы появятся (отдельная запись леджера `crate-feasibility`), формат будет
//! заменён или переименован — до этого это обложка собственного протокола.
//!
//! ## Честный caps: почему no-HOL невозможен
//!
//! Кадры едут через упорядоченный канал stream-класса, поэтому застрявший в середине
//! кадр блокирует все последующие — как в Reality/TCP (`02 §2.2`). `caps()` отдаёт
//! `no_hol: false, datagram: false` **даже если физический канал UDP-подобный**:
//! семантика доставки здесь stream-класс, и врать no-HOL нельзя.
//!
//! ## Padding и duplicate-окно
//!
//! Бюджет `P` байт на record, включается флагом `with_padding(P)`: длина outgoing-кадра
//! ∈ `[plaintext+tag, plaintext+tag+P]`. Паддинг едет **внутри** шифротекста, поэтому его
//! точная длина скрыта (видна только сумма), а кадр аутентифицирован целиком (AAD —
//! заголовок кадра). Окно дедупа не затронуто: padding меняет **длину** кадра, а не `seq`
//! записи — дедуп узла по `(sid, seq)` (`02 §3.5`) видит те же записи.
//!
//! ## Ключи
//!
//! Ключ обложки — `derive_cover_key(sid, K_session)` с меткой `LABEL_COVER`: отдельный
//! слой, компрометация обложки не вскрывает `K_record`/`K_resume`. Nonce кадра —
//! системный CSPRNG (24 B, probabilistic AEAD): детерминированный xorshift-nonce был
//! прод-дефектом (аудит F-01) — общая последовательность у всех деплоев как DPI-отпечаток
//! и повтор nonce на одном `K_cover` при пересоздании байндинга (раскрытие keystream'ов).

#![deny(unsafe_code)]

use crypto_core::{KCover, KRecord, RecordAead, RecordCrypto, RecordNonce};
use frame_session::{Record, RecordError};
use transport_mux::{
    BindingCaps, BindingError, BindingFailure, CoverBinding, DEFAULT_OUTBOX_BYTES,
};

/// Профиль DPI этого байндинга: stream-обложка с собственным кадрированием.
/// (0x01 QUIC, 0x02 Reality-TCP, 0x03 MASQUE — заняты в transport-mux.)
pub const DPI_PROFILE_SS_PADDED: u8 = 0x04;

/// Максимальный бюджет padding на record: больше обложке не нужно (16 KiB ≈ 3 MTU).
pub const MAX_PADDING_BUDGET: usize = 16 * 1024;

/// Длина nonce XChaCha20-Poly1305 (24 B).
pub const NONCE_LEN: usize = 24;
/// Длина тега Poly1305 (16 B).
pub const TAG_LEN: usize = 16;
/// Длина префикса длины кадра (4 B BE, как в `transport_mux::encode_frame`).
pub const FRAME_LEN_BYTES: usize = 4;

/// Ошибка кадра обложки (`decode_cover_frame`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverFrameError {
    /// Кадр короче заголовка или `len` не совпадает с телом.
    BadLength,
    /// AEAD не прошёл аутентификацию (чужой ключ, порча байтов).
    OpenFailed,
    /// Запись внутри не разбирается.
    BadRecord,
}

/// Шифрует запись в кадр обложки: `len(4B BE) ‖ nonce(24B) ‖ AEAD(record ‖ pad)`.
///
/// `padding_budget` — верхняя граница случайной добавки (0 = без padding); обрезается
/// до `MAX_PADDING_BUDGET`. `rng_fill` заполняет буферы энтропией (в проде — системный
/// RNG; в тестах — детерминированный). Паддинг добавляется в конец plaintext и
/// аутентифицирован AEAD вместе с записью.
pub fn encode_cover_frame(
    cover: &KCover,
    record: &Record,
    padding_budget: usize,
    rng_fill: &mut dyn FnMut(&mut [u8]),
) -> Vec<u8> {
    let budget = padding_budget.min(MAX_PADDING_BUDGET);
    let mut nonce = [0u8; NONCE_LEN];
    rng_fill(&mut nonce);
    let mut pad_draw = [0u8; 2];
    rng_fill(&mut pad_draw);

    // Паддинг ∈ [0, budget]: два случайных байта сжимаются в диапазон.
    // При budget = 0 — ровно 0 (байты паддинга не генерируются вовсе).
    let padding = if budget == 0 {
        0
    } else {
        (usize::from(pad_draw[0]) << 8 | usize::from(pad_draw[1])) % (budget + 1)
    };

    let body = record.encode();
    let mut plaintext = Vec::with_capacity(body.len() + padding);
    plaintext.extend_from_slice(&body);
    plaintext.resize(body.len() + padding, 0);
    if padding > 0 {
        rng_fill(&mut plaintext[body.len()..]);
    }

    let aead = RecordAead;
    // AAD — заголовок кадра (префикс длины): аутентифицирует границу кадра.
    let aad = (NONCE_LEN + plaintext.len() + TAG_LEN) as u32;
    let ciphertext = aead.seal(
        &KRecord(cover.0),
        &RecordNonce(nonce),
        &aad.to_be_bytes(),
        &plaintext,
    );

    let mut frame = Vec::with_capacity(FRAME_LEN_BYTES + NONCE_LEN + ciphertext.len());
    frame.extend_from_slice(&((NONCE_LEN + ciphertext.len()) as u32).to_be_bytes());
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(&ciphertext);
    frame
}

/// Вскрывает кадр обложки и возвращает запись; паддинг отрезается по границе записи.
pub fn decode_cover_frame(cover: &KCover, frame: &[u8]) -> Result<Record, CoverFrameError> {
    let (prefix, rest) = frame
        .split_at_checked(4)
        .ok_or(CoverFrameError::BadLength)?;
    let declared =
        u32::from_be_bytes(prefix.try_into().map_err(|_| CoverFrameError::BadLength)?) as usize;
    if declared != rest.len() {
        return Err(CoverFrameError::BadLength);
    }
    let (nonce, ciphertext) = rest
        .split_at_checked(NONCE_LEN)
        .ok_or(CoverFrameError::BadLength)?;
    let mut nonce_arr = [0u8; NONCE_LEN];
    nonce_arr.copy_from_slice(nonce);

    // AAD — тот же префикс длины, что при seal.
    let aad = u32::from_be_bytes(prefix.try_into().map_err(|_| CoverFrameError::BadLength)?);
    let aead = RecordAead;
    let plaintext = aead
        .open(
            &KRecord(cover.0),
            &RecordNonce(nonce_arr),
            &aad.to_be_bytes(),
            ciphertext,
        )
        .map_err(|_| CoverFrameError::OpenFailed)?;

    // Паддинг — хвост plaintext: парсер записи ест ровно свои байты. `Record::decode`
    // требует точного совпадения длины, поэтому ищем границу записи перебором хвоста:
    // длина записи ≤ plaintext, паддинг ≤ MAX_PADDING_BUDGET.
    let mut err = CoverFrameError::BadRecord;
    for cut in (0..=plaintext.len()).rev() {
        match Record::decode(&plaintext[..cut]) {
            Ok(rec) => return Ok(rec),
            Err(RecordError::BadLayout) => continue,
            Err(_) => {
                err = CoverFrameError::BadRecord;
                break;
            }
        }
    }
    Err(err)
}

/// Aether padded cover — fallback-байндинг stream-класса (`03` §4).
///
/// Структура повторяет `QuicBinding`/`MemBinding`: `BindingCore` (очередь + async-отказы),
/// `send → Result`, `on_failure` между вызовами. Отличие от них: `BindingCore::enqueue`
/// кладёт **дефолтный** кадр `encode_frame`, а обложке нужен **свой** кадр
/// (`cover-AEAD + padding`), поэтому очередь (`Outbox`) здесь заполняется напрямую
/// cover-кадром — backpressure и потолок байтов при этом те же.
#[derive(Debug)]
pub struct SsPaddedBinding {
    cover: KCover,
    padding_budget: usize,
    outbox: transport_mux::Outbox,
    failure: Option<BindingFailure>,
    closed: bool,
}

impl SsPaddedBinding {
    /// Байндинг под ключом обложки `cover` без padding.
    pub fn new(cover: KCover) -> Self {
        Self::with_padding(cover, 0)
    }

    /// Байндинг с бюджетом padding `budget` байт на record.
    pub fn with_padding(cover: KCover, budget: usize) -> Self {
        Self {
            cover,
            padding_budget: budget.min(MAX_PADDING_BUDGET),
            outbox: transport_mux::Outbox::new(DEFAULT_OUTBOX_BYTES),
            failure: None,
            closed: false,
        }
    }

    /// Включённый бюджет padding.
    pub fn padding_budget(&self) -> usize {
        self.padding_budget
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

/// Тестовый/детерминированный источник энтропии: xorshift от `(counter, index)`.
/// НЕ крипто-RNG и НЕ достижим из прод-конструктора байндинга: доступен только
/// тестам этого крейта (приватен, в прод-пути `send()` используется CSPRNG).
/// Прод-дефект F-01 (аудит, High): раньше именно эта функция стояла в `send()`.
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

impl CoverBinding for SsPaddedBinding {
    fn send(&mut self, rec: &Record) -> Result<(), BindingError> {
        if self.closed {
            self.failure = Some(BindingFailure::Closed);
            return Err(BindingError::TransportDown);
        }
        // Nonce и padding — из системного CSPRNG (F-01): AEAD probabilistic, без
        // повторов nonce на ключе независимо от истории создания байндинга. Детерминированный
        // xorshift от счётчика давал одинаковую nonce-последовательность у всех клиентов
        // (DPI-отпечаток) и повтор nonce при пересоздании байндинга на том же `K_cover`
        // (реконнект/морф) — раскрытие keystream'ов и подделка Poly1305-тега.
        // `expect` допустим: единственная ошибка `getrandom::fill` — системный RNG
        // недоступен (тот же explicit-fail контракт, что в `ticket-mint::mint_at`).
        let frame = encode_cover_frame(
            &self.cover,
            rec,
            self.padding_budget,
            &mut |buf: &mut [u8]| {
                getrandom::fill(buf)
                    .expect("system CSPRNG unavailable: cannot encrypt a cover frame");
            },
        );
        // Кадр обложки кладём напрямую в Outbox (не через BindingCore::enqueue —
        // тот кодирует дефолтный кадр без AEAD/padding).
        self.outbox.push(rec.stream_id, frame)
    }

    fn supports(&self) -> BindingCaps {
        BindingCaps {
            no_hol: false,
            datagram: false,
            dpi_profile: DPI_PROFILE_SS_PADDED,
        }
    }

    fn on_failure(&mut self) -> Option<BindingFailure> {
        self.failure.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_core::{derive_session, KCover};
    use frame_session::{RecordType, Seq, StreamId};
    use transport_mux::BindingError;

    const SID: [u8; 16] = [0x5a; 16];

    fn cover() -> KCover {
        crypto_core::derive_cover_key(&SID, &derive_session(&SID, b"cover test hash"))
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

    /// Roundtrip: кадр обложки разбирается, запись восстанавливается байт в байт,
    /// в том числе с включённым padding; чужой ключ не вскрывает.
    #[test]
    fn cover_frame_roundtrip() {
        let cov = cover();
        for budget in [0usize, 16, 1024] {
            let rec = record(7, b"payload bytes");
            let mut fill = fixed_fill(0xAB);
            let frame = encode_cover_frame(&cov, &rec, budget, &mut fill);
            let decoded = decode_cover_frame(&cov, &frame).expect("кадр вскрывается");
            assert_eq!(decoded, rec, "запись восстановлена (budget={budget})");

            let wrong =
                crypto_core::derive_cover_key(&SID, &derive_session(&SID, b"other session"));
            assert_eq!(
                decode_cover_frame(&wrong, &frame),
                Err(CoverFrameError::OpenFailed)
            );
        }
    }

    /// Padding: длина outgoing-кадра ∈ [минимум, минимум+budget], при budget=0 ровно
    /// минимум; паддинг реально меняет размер; seq записи не трогается — duplicate-окно
    /// узла не затронуто. Минимум = len(4) + nonce(24) + record.encode() + tag(16),
    /// где encode() = header(type+seq+stream+flags+len varint'ы) + ciphertext(64).
    #[test]
    fn padding_bounds_and_window_neutrality() {
        let cov = cover();
        let payload = b"x".repeat(64);
        let rec = record(9, &payload);
        // Минимум считаем от фактического кодирования записи, а не руками:
        // header записи зависит от varint-длин seq/stream/len (первый прогон: 108 ≠ 113).
        let rec_len = rec.encode().len();
        let min_len = FRAME_LEN_BYTES + NONCE_LEN + rec_len + TAG_LEN;

        let mut fill = fixed_fill(0x11);
        let no_pad = encode_cover_frame(&cov, &rec, 0, &mut fill);
        assert_eq!(no_pad.len(), min_len, "budget=0 → ровно минимум");
        assert_eq!(decode_cover_frame(&cov, &no_pad).expect("вскрывается"), rec);

        let mut max_seen = min_len;
        for seed in 0..32u8 {
            let mut fill = fixed_fill(seed);
            let frame = encode_cover_frame(&cov, &rec, 200, &mut fill);
            assert!(frame.len() >= min_len, "кадр не короче минимума");
            assert!(frame.len() <= min_len + 200, "кадр не длиннее бюджета");
            assert_eq!(decode_cover_frame(&cov, &frame).expect("вскрывается"), rec);
            max_seen = max_seen.max(frame.len());
        }
        assert!(max_seen > min_len, "padding реально применялся");

        // Padding не меняет seq записи: дедуп узла по (sid, seq) видит те же записи.
        assert_eq!(rec.seq, Seq(9));
    }

    /// Битые кадры: обрезанный заголовок, несовпадение `len`, испорченный шифротекст —
    /// ошибки без паники.
    #[test]
    fn malformed_frames_are_errors() {
        let cov = cover();
        assert_eq!(
            decode_cover_frame(&cov, &[0u8; 3]),
            Err(CoverFrameError::BadLength)
        );
        let mut frame = {
            let mut fill = fixed_fill(0);
            encode_cover_frame(&cov, &record(1, b"abc"), 0, &mut fill)
        };
        frame[0] = frame[0].wrapping_add(1); // ломаем declared length
        assert_eq!(
            decode_cover_frame(&cov, &frame),
            Err(CoverFrameError::BadLength)
        );
        let mut corrupted = {
            let mut fill = fixed_fill(0);
            encode_cover_frame(&cov, &record(1, b"abc"), 0, &mut fill)
        };
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0xFF; // порча шифротекста → AEAD-тег не сходится
        assert_eq!(
            decode_cover_frame(&cov, &corrupted),
            Err(CoverFrameError::OpenFailed)
        );
    }

    /// Отказные пути как у QuicBinding/MemBinding: закрытый канал — синхронный
    /// `TransportDown` + асинхронный `Closed` ровно один раз; инжектированный отказ
    /// доходит до FSM.
    #[test]
    fn closed_channel_and_failure_paths() {
        let mut binding = SsPaddedBinding::new(cover());
        binding.mark_closed();
        assert_eq!(
            binding.send(&record(1, b"x")),
            Err(BindingError::TransportDown)
        );
        assert_eq!(binding.on_failure(), Some(BindingFailure::Closed));
        assert_eq!(binding.on_failure(), None, "событие отдаётся один раз");

        let mut binding = SsPaddedBinding::new(cover());
        binding.inject_failure(BindingFailure::Probed);
        assert_eq!(binding.on_failure(), Some(BindingFailure::Probed));
        assert_eq!(binding.on_failure(), None);
    }

    /// Капы не врут: stream-класс, без no-HOL и datagram (02 §2.2 tradeoff).
    #[test]
    fn caps_stream_class_not_no_hol() {
        let binding = SsPaddedBinding::new(cover());
        let caps = binding.supports();
        assert!(!caps.no_hol, "stream-класс: no-HOL отсутствует");
        assert!(!caps.datagram);
        assert_eq!(caps.dpi_profile, DPI_PROFILE_SS_PADDED);
        assert_ne!(caps.dpi_profile, transport_mux::DPI_PROFILE_MASQUE);
    }

    /// Байндинг в связке с фреймингом: записи, прошедшие через `send`, вынимаются
    /// из очереди как cover-кадры и вскрываются тем же ключом; backpressure —
    /// `WouldBlock` при переполнении (как у других байндингов).
    #[test]
    fn queue_roundtrip_and_backpressure() {
        let cov = cover();
        let mut binding = SsPaddedBinding::with_padding(cov, 128);

        for seq in 0..3u64 {
            binding
                .send(&record(seq, b"queued payload"))
                .expect("очередь не переполнена");
        }
        let pending = binding.take_pending();
        assert_eq!(pending.len(), 3, "три кадра в очереди");
        for (i, (stream, frame)) in pending.iter().enumerate() {
            assert_eq!(*stream, StreamId(0));
            let decoded = decode_cover_frame(&cov, frame).expect("cover-кадр вскрывается");
            assert_eq!(decoded.seq, Seq(i as u64), "порядок и seq сохранены");
            assert_eq!(decoded.ciphertext, b"queued payload");
        }
        assert!(binding.take_pending().is_empty(), "очередь вычерпана");

        // WouldBlock: переполнение ограниченной очереди — backpressure, не OOM.
        let mut small = SsPaddedBinding::with_padding(cov, 0);
        small.outbox = transport_mux::Outbox::new(64);
        let big_payload = vec![0u8; 200];
        assert_eq!(
            small.send(&record(1, &big_payload)),
            Err(BindingError::WouldBlock)
        );
    }

    /// F-01 (аудит, High): prod-nonce байндинга — CSPRNG, не детерминированный счётчик.
    /// Два инстанса байндинга на одном `K_cover` (реконнект/морф = пересоздание) НЕ
    /// повторяют nonce: до фикса второй байндинг начинал ту же xorshift-последовательность,
    /// что и первый, — повтор nonce на ключе (раскрытие keystream'ов XChaCha20).
    #[test]
    fn prod_nonce_never_repeats_across_binding_instances() {
        let cov = cover();
        let extract_nonce = |frame: &[u8]| -> [u8; NONCE_LEN] {
            let mut n = [0u8; NONCE_LEN];
            n.copy_from_slice(&frame[FRAME_LEN_BYTES..FRAME_LEN_BYTES + NONCE_LEN]);
            n
        };

        let mut seen: std::collections::HashSet<[u8; NONCE_LEN]> = std::collections::HashSet::new();
        let rec = record(0, b"nonce uniqueness probe");

        // Первое время жизни байндинга: N записей.
        let mut first = SsPaddedBinding::new(cov);
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
        let mut second = SsPaddedBinding::new(cov);
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
}
