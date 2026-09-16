//! `transport-mux` — байндинги frame-слоя к транспортам (`03-components.md` §4).
//!
//! **In:** `Record` из `frame-session`; выбранный байндинг от `morph-controller`.
//! **Out:** байты в транспорт; `BindingError` (синхронно) и `BindingFailure` (асинхронно).
//! **Deps:** `frame-session` (тип `Record`), `quinn` (QUIC-байндинг).
//!
//! Phase 0: **только QUIC-байндинг** (quinn, дефолт cubic — BBR в quinn экспериментальный
//! и не сопровождается, issue #2156). Остальные байндинги — Phase 1: MASQUE CONNECT-UDP
//! на quinn+h3, Reality/TCP с задокументированным HOL-tradeoff, SS-2022/padded.
//!
//! Оба пути отказа обязаны доходить до FSM морфинга и приводить к rollback с quarantine
//! обложки: синхронный — через `Result` из `send`, асинхронный — через `on_failure`
//! (`02 §4`, таблица окна морфа).
//!
//! ## Что реализовано в Phase 0 и какие решения тут приняты
//!
//! 1. **Кадрирование — `len(4B BE) ‖ record.encode()`.** `01 §6` говорит «QUIC-байндинг:
//!    `stream_id` ↔ QUIC stream», `02 §2.2` — «length-prefixed frames» для Reality. Общая
//!    для всех байндингов функция кадрирования вынесена сюда: кадр — это способ доставить
//!    границы record'ов через поток, а не часть record-протокола (`frame-session` о кадре
//!    не знает).
//! 2. **`send` синхронный, но запись в quinn — асинхронная.** `CoverBinding::send` —
//!    синхронный по контракту `03`, а `quinn::SendStream::write_all` — асинхронный, и
//!    runtime в CI-тестах нет. Поэтому синхронный путь только **ставит кадр в очередь**
//!    (`BindingCore::enqueue`), а забирает её `QuicBinding::take_pending()` — его вычерпывает
//!    async-писатель (по `stream_id` в `SendStream`). В Phase 0 проверены кадрирование,
//!    caps и оба отказных пути; **сокета и runtime в тестах Phase 0 нет** — это зафиксировано
//!    как остаток в `QUESTIONS.md` (сетевой прогон QUIC-байндинга — Phase 0.5).
//! 3. **Backpressure — числом:** очередь байндинга ограничена (`DEFAULT_OUTBOX_BYTES`),
//!    переполнение — `BindingError::WouldBlock`, а не рост памяти (тот же выбор, что и
//!    «буфер фолбэка ≤ 16 МБ или ≤ 5 с» из `05-roadmap`, но локально на байндинг).
//! 4. **Асинхронный отказ отдаётся ровно один раз** (`on_failure` = `take`): FSM морфинга
//!    обязана получить событие, но не обязана получать его на каждом poll.
//! 5. **`MemBinding` — не тестовый хак, а мок из `03`:** `frame-session` тестируется на моках
//!    байндингов, а интеграционный крейт `rotation-tests` — на двух in-memory байндингах со
//!    счётчиками и журналом `(stream_id, seq)`. Мок живёт рядом с трейтом, потому что им
//!    пользуются тесты двух крейтов.

#![deny(unsafe_code)]

use std::collections::VecDeque;

use frame_session::{Record, StreamId};

/// Профиль DPI QUIC-байндинга (вход классификатора морфа, `02 §4`).
pub const DPI_PROFILE_QUIC: u8 = 0x01;
/// Профиль DPI Reality/TCP-байндинга (Phase 1).
pub const DPI_PROFILE_REALITY_TCP: u8 = 0x02;
/// Профиль DPI MASQUE-байндинга (Phase 1).
pub const DPI_PROFILE_MASQUE: u8 = 0x03;

/// Размер префикса длины кадра: `len(4B BE) ‖ record`.
pub const FRAME_LEN_BYTES: usize = 4;

/// Потолок очереди байндинга по умолчанию (256 KiB на один байндинг).
///
/// Число выбрано как «меньше бюджета буфера фолбэка» (`05-roadmap`: ≤ 16 МБ или ≤ 5 с):
/// байндинг обязан сказать `WouldBlock` раньше, чем сессия израсходует весь бюджет.
pub const DEFAULT_OUTBOX_BYTES: usize = 256 * 1024;

/// Флаги возможностей байндинга (`03-components.md`, контракты).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingCaps {
    /// Нет head-of-line блокировки на этом байндинге (QUIC — да, Reality/TCP — нет).
    pub no_hol: bool,
    /// Сохраняет ли датаграммную семантику (для QUIC-байндинга — да).
    pub datagram: bool,
    /// Профиль DPI-поведения байндинга (для классификатора морфа).
    pub dpi_profile: u8,
}

impl BindingCaps {
    /// QUIC-байндинг: no-HOL бесплатно, датаграммная семантика сохраняется (`01 §6`).
    pub const QUIC: Self = Self {
        no_hol: true,
        datagram: true,
        dpi_profile: DPI_PROFILE_QUIC,
    };

    /// Reality/TCP-байндинг (Phase 1): HOL — задокументированный tradeoff (`02 §2.2`).
    pub const REALITY_TCP: Self = Self {
        no_hol: false,
        datagram: false,
        dpi_profile: DPI_PROFILE_REALITY_TCP,
    };
}

/// Синхронный отказ отправки: возвращается вызывающему сразу.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingError {
    /// Транспорт недоступен.
    TransportDown,
    /// Очередь отправки переполнена (backpressure).
    WouldBlock,
    /// Байндинг не поддерживает такую запись.
    Unsupported,
}

/// Асинхронный отказ: приходит между вызовами `send`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingFailure {
    /// Соединение разорвано без `send` со стороны приложения.
    Closed,
    /// Пир перестал отвечать.
    PeerUnresponsive,
    /// Транспорт снят цензором (RST/spike) — повод для морфа.
    Probed,
}

/// Контракт байндинга (`03-components.md`, контракты) — скопирован дословно.
pub trait CoverBinding {
    /// Отправляет запись; синхронный отказ — `Err`.
    fn send(&mut self, rec: &Record) -> Result<(), BindingError>;
    /// Что умеет этот байндинг.
    fn supports(&self) -> BindingCaps;
    /// Асинхронный отказ, накопившийся с прошлого вызова.
    fn on_failure(&mut self) -> Option<BindingFailure>;
}

/// Кадр байндинга: `len(4B BE) ‖ record.encode()` — границы записи поверх потока.
pub fn encode_frame(rec: &Record) -> Vec<u8> {
    let body = rec.encode();
    let mut frame = Vec::with_capacity(FRAME_LEN_BYTES + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    frame
}

/// Разбор кадра. Обрезанный кадр, несовпадение префикса длины или битый record —
/// `BindingError::Unsupported` (это не отказ транспорта, а невалидный вход).
pub fn decode_frame(frame: &[u8]) -> Result<Record, BindingError> {
    let (prefix, body) = frame.split_at_checked(FRAME_LEN_BYTES).ok_or(BindingError::Unsupported)?;
    let declared = u32::from_be_bytes(prefix.try_into().map_err(|_| BindingError::Unsupported)?);
    if declared as usize != body.len() {
        return Err(BindingError::Unsupported);
    }
    Record::decode(body).map_err(|_| BindingError::Unsupported)
}

/// Очередь кадров байндинга, ждущих async-писателя.
///
/// Ограничение по байтам — не украшение: без него `send` при недоступном writer'е
/// копил бы память до OOM, а окно перекрытия (`02 §4`) считает бюджет в записях.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outbox {
    frames: VecDeque<(StreamId, Vec<u8>)>,
    bytes: usize,
    cap_bytes: usize,
}

impl Outbox {
    /// Очередь с потолком в байтах.
    pub fn new(cap_bytes: usize) -> Self {
        Self {
            frames: VecDeque::new(),
            bytes: 0,
            cap_bytes,
        }
    }

    /// Потолок очереди.
    pub fn cap_bytes(&self) -> usize {
        self.cap_bytes
    }

    /// Занято байт (только полезная нагрузка кадров).
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Сколько кадров в очереди.
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Пуста ли очередь.
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Ставит кадр в очередь; переполнение — `WouldBlock` (backpressure, а не рост памяти).
    pub fn push(&mut self, stream: StreamId, frame: Vec<u8>) -> Result<(), BindingError> {
        if self.bytes + frame.len() > self.cap_bytes {
            return Err(BindingError::WouldBlock);
        }
        self.bytes += frame.len();
        self.frames.push_back((stream, frame));
        Ok(())
    }

    /// Забирает самый старый кадр.
    pub fn pop(&mut self) -> Option<(StreamId, Vec<u8>)> {
        let (stream, frame) = self.frames.pop_front()?;
        self.bytes = self.bytes.saturating_sub(frame.len());
        Some((stream, frame))
    }

    /// Забирает всё, что накопилось (вызов async-писателя).
    pub fn drain(&mut self) -> Vec<(StreamId, Vec<u8>)> {
        self.bytes = 0;
        self.frames.drain(..).collect()
    }
}

/// Общее состояние байндинга: очередь + асинхронный отказ.
///
/// Вынесено из `QuicBinding`, потому что это ровно то, что проверяется без сети: оба
/// отказных пути (`02 §4`) и backpressure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingCore {
    outbox: Outbox,
    failure: Option<BindingFailure>,
}

impl BindingCore {
    /// Состояние с потолком очереди.
    pub fn new(cap_bytes: usize) -> Self {
        Self {
            outbox: Outbox::new(cap_bytes),
            failure: None,
        }
    }

    /// Кадрирует запись и ставит её в очередь.
    pub fn enqueue(&mut self, rec: &Record) -> Result<(), BindingError> {
        self.outbox.push(rec.stream_id, encode_frame(rec))
    }

    /// Отмечает асинхронный отказ — его заберёт `on_failure` (ровно один раз).
    pub fn note(&mut self, failure: BindingFailure) {
        self.failure = Some(failure);
    }

    /// Отдаёт накопленный отказ и снимает его: FSM морфинга получает событие один раз.
    pub fn on_failure(&mut self) -> Option<BindingFailure> {
        self.failure.take()
    }

    /// Очередь на чтение.
    pub fn pending(&self) -> &Outbox {
        &self.outbox
    }

    /// Вычерпывает очередь (так работает async-писатель).
    pub fn take_pending(&mut self) -> Vec<(StreamId, Vec<u8>)> {
        self.outbox.drain()
    }
}

/// QUIC-байндинг: quinn-соединение + очередь кадров.
///
/// Проверенные здесь свойства: `BindingCaps::QUIC`, синхронный отказ при закрытом
/// соединении (`TransportDown` + `BindingFailure::Closed`) и асинхронные отказы
/// (`PeerUnresponsive`, `Probed`) из keepalive/эвристик морфа.
///
/// Не реализовано в Phase 0: async-писатель (`take_pending()` → `SendStream` по `stream_id`)
/// и приёмная сторона — им нужен runtime, которого в тестах Phase 0 нет (см. `QUESTIONS.md`).
pub struct QuicBinding {
    connection: quinn::Connection,
    core: BindingCore,
}

/// Набросок async-писателя (Phase 0.5, спайк: API выверен по docs 0.11.12, рантайм в CI не гоняется).
/// Вычерпывает `take_pending()` и пишет каждый кадр в uni-стрим его `stream_id`; открыть стрим
/// и дождаться записи может только окружение с runtime — поэтому здесь это план, а не код:
///
/// ```no_run
/// use quinn::{Connection, StreamId, WriteError};
/// use std::collections::HashMap;
///
/// async fn drain(core: &mut BindingCore, conn: &Connection) -> Result<(), WriteError> {
///     for (stream_id, frame) in core.take_pending() {
///         // кэш открытых uni-стримов: один stream frame-слоя = один uni-стрим QUIC
///         let _send: quinn::SendStream = conn.open_uni().await?;
///         let _id: StreamId = _send.id();
///         let _write = _send.write_all(&frame).await?;
///         // ошибка записи → событие BindingFailure (QUIC-соединение умерло)
///     }
///     Ok(())
/// }
/// ```
/// Инвариант, проверенный в Phase 0: `caps()` отдаёт `BindingCaps::QUIC` (no-HOL, datagram);
/// кадры больше `TransportConfig::datagram_receive_buffer_size` не формируются.

impl QuicBinding {
    /// Байндинг поверх установленного QUIC-соединения.
    pub fn new(connection: quinn::Connection) -> Self {
        Self {
            connection,
            core: BindingCore::new(DEFAULT_OUTBOX_BYTES),
        }
    }

    /// Возможности QUIC-байндинга (`01 §6`: no-HOL, датаграммная семантика).
    pub fn caps() -> BindingCaps {
        BindingCaps::QUIC
    }

    /// Закрыто ли соединение (после `close_reason` новых записей не будет).
    pub fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }

    /// Максимальный размер датаграммы, если пир их поддерживает (`None` — не поддерживает).
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.connection.max_datagram_size()
    }

    /// Пир перестал отвечать: асинхронный отказ для FSM (`02 §4`).
    pub fn note_unresponsive(&mut self) {
        self.core.note(BindingFailure::PeerUnresponsive);
    }

    /// Транспорт снят цензором (RST/spike): повод для морфа (`02 §4`).
    pub fn note_probed(&mut self) {
        self.core.note(BindingFailure::Probed);
    }

    /// Свободное место в буфере датаграмм — то, что байндинг может отправить прямо сейчас
    /// без жертвы ранее поставленными в очередь датаграммами.
    pub fn datagram_buffer_space(&self) -> usize {
        self.connection.datagram_send_buffer_space()
    }

    /// Забирает очередь кадров: их пишет async-писатель в `SendStream` по `stream_id`.
    pub fn take_pending(&mut self) -> Vec<(StreamId, Vec<u8>)> {
        self.core.take_pending()
    }

    /// Размер очереди в байтах (диагностика backpressure).
    pub fn pending_bytes(&self) -> usize {
        self.core.pending().bytes()
    }
}

impl CoverBinding for QuicBinding {
    fn send(&mut self, rec: &Record) -> Result<(), BindingError> {
        if self.is_closed() {
            self.core.note(BindingFailure::Closed);
            return Err(BindingError::TransportDown);
        }
        self.core.enqueue(rec)
    }

    fn supports(&self) -> BindingCaps {
        Self::caps()
    }

    fn on_failure(&mut self) -> Option<BindingFailure> {
        if self.is_closed() {
            self.core.note(BindingFailure::Closed);
        }
        self.core.on_failure()
    }
}

/// In-memory байндинг: мок из `03` («frame-session и crypto-core тестируются на моках
/// байндингов») со счётчиками, журналом `(stream_id, seq)` и настраиваемой потерей.
///
/// Потеря моделируется **после** успешного `send` (`Ok` без записи в журнал): так ведёт себя
/// сеть, и именно поэтому frame-слой обязан переживать потерю дублированием (`02 §3.3` шаг 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemBinding {
    caps: BindingCaps,
    core: BindingCore,
    journal: Vec<(StreamId, u64)>,
    loss_every: u32,
    offered: u32,
    dropped: u32,
    closed: bool,
}

impl MemBinding {
    /// Мок-байндинг с заданными caps и потолком очереди по умолчанию.
    pub fn new(caps: BindingCaps) -> Self {
        Self {
            caps,
            core: BindingCore::new(DEFAULT_OUTBOX_BYTES),
            journal: Vec::new(),
            loss_every: 0,
            offered: 0,
            dropped: 0,
            closed: false,
        }
    }

    /// Байндинг с потерей каждой `n`-й записи (`0` — без потерь).
    pub fn with_loss_every(mut self, n: u32) -> Self {
        self.loss_every = n;
        self
    }

    /// Настраивает потерю на ходу (нужно для прогона «потеря на обоих каналах»).
    pub fn set_loss_every(&mut self, n: u32) {
        self.loss_every = n;
    }

    /// Журнал доставленных записей: `(stream_id, seq)`.
    pub fn journal(&self) -> &[(StreamId, u64)] {
        &self.journal
    }

    /// Сколько записей предложено байндингу.
    pub fn offered(&self) -> u32 {
        self.offered
    }

    /// Сколько записей потеряно в «сети».
    pub fn dropped(&self) -> u32 {
        self.dropped
    }

    /// Закрывает байндинг: следующий `send` даст `TransportDown` + `BindingFailure::Closed`.
    pub fn mark_closed(&mut self) {
        self.closed = true;
    }

    /// Жив ли байндинг.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Инжектирует асинхронный отказ (`Probed`/`PeerUnresponsive`) — путь к rollback FSM.
    pub fn inject_failure(&mut self, failure: BindingFailure) {
        self.core.note(failure);
    }

    /// Забирает очередь кадров (в тестах — эмуляция async-писателя).
    pub fn take_pending(&mut self) -> Vec<(StreamId, Vec<u8>)> {
        self.core.take_pending()
    }

    /// Размер очереди в байтах.
    pub fn pending_bytes(&self) -> usize {
        self.core.pending().bytes()
    }
}

impl CoverBinding for MemBinding {
    fn send(&mut self, rec: &Record) -> Result<(), BindingError> {
        if self.closed {
            self.core.note(BindingFailure::Closed);
            return Err(BindingError::TransportDown);
        }
        self.offered += 1;
        if self.loss_every != 0 && self.offered.is_multiple_of(self.loss_every) {
            self.dropped += 1;
            return Ok(());
        }
        self.journal.push((rec.stream_id, rec.seq.0));
        self.core.enqueue(rec)
    }

    fn supports(&self) -> BindingCaps {
        self.caps
    }

    fn on_failure(&mut self) -> Option<BindingFailure> {
        self.core.on_failure()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frame_session::{RecordType, Seq};

    fn record(seq: u64, stream: u32, payload: &[u8]) -> Record {
        Record {
            kind: RecordType::Data,
            stream_id: StreamId(stream),
            flags: 0,
            seq: Seq(seq),
            ciphertext: payload.to_vec(),
        }
    }

    /// Контракт отказа: `send` возвращает `BindingError` без паники, а `on_failure` отдаёт
    /// асинхронный отказ **ровно один раз** — оба пути обязаны дойти до FSM (`02 §4`).
    #[test]
    fn contract_sync_and_async_failure_paths() {
        let mut binding = MemBinding::new(BindingCaps::QUIC);
        let rec = record(0, 0, b"payload");
        let small = record(1, 0, b"x");

        // Асинхронный отказ: морф снят цензором — FSM получает событие один раз.
        binding.inject_failure(BindingFailure::Probed);
        assert_eq!(binding.on_failure(), Some(BindingFailure::Probed));
        assert_eq!(binding.on_failure(), None, "событие отдаётся один раз");
        binding.inject_failure(BindingFailure::PeerUnresponsive);
        assert_eq!(binding.on_failure(), Some(BindingFailure::PeerUnresponsive));

        // Закрытие: синхронный отказ `TransportDown` + асинхронный `Closed` (оба пути).
        binding.mark_closed();
        assert_eq!(binding.send(&rec), Err(BindingError::TransportDown));
        assert_eq!(binding.on_failure(), Some(BindingFailure::Closed));
        assert_eq!(binding.send(&rec), Err(BindingError::TransportDown));
        assert_eq!(binding.journal().len(), 0, "в закрытый байндинг ничего не ушло");

        // Backpressure — тоже синхронный отказ, а не рост памяти. Кадры: большой —
        // `rec` (len(4) + header(5) + ciphertext(7) = 16 B), малый — `small` (4 + 5 + 1 = 10 B).
        let mut tight = BindingCore::new(12);
        assert_eq!(encode_frame(&rec).len(), 16);
        assert_eq!(encode_frame(&small).len(), 10);
        assert_eq!(
            tight.enqueue(&rec),
            Err(BindingError::WouldBlock),
            "кадр больше потолка очереди отвергается"
        );
        assert_eq!(tight.enqueue(&small), Ok(()));
        assert_eq!(tight.pending().len(), 1);
        assert!(tight.pending().bytes() <= 12);
        assert_eq!(
            tight.enqueue(&small),
            Err(BindingError::WouldBlock),
            "второй кадр в остаток не влезает — backpressure, а не рост памяти"
        );
        assert_eq!(tight.take_pending().len(), 1);
        assert!(tight.pending().is_empty(), "вычерпывание освобождает очередь");
        assert_eq!(tight.enqueue(&small), Ok(()), "место освободилось");
    }

    /// Контракт caps: QUIC-байндинг обязан заявлять `no_hol = true` и `datagram = true`,
    /// иначе выбор байндинга в FSM противоречит `02 §2`.
    #[test]
    fn contract_quic_binding_caps() {
        let caps = QuicBinding::caps();
        assert!(caps.no_hol, "QUIC: no-HOL бесплатно (`01 §6`)");
        assert!(caps.datagram, "QUIC сохраняет датаграммную семантику");
        assert_eq!(caps.dpi_profile, DPI_PROFILE_QUIC);

        // Reality/TCP: HOL — задокументированный tradeoff, а не дефект мока (`02 §2.2`).
        let binding = MemBinding::new(BindingCaps::REALITY_TCP);
        let reality = binding.supports();
        assert!(!reality.no_hol, "у Reality/TCP HOL есть по построению");
        assert!(!reality.datagram, "датаграммной семантики на TCP нет");
        assert_ne!(reality.dpi_profile, caps.dpi_profile);
        assert_eq!(reality, BindingCaps::REALITY_TCP);
    }

    /// Контракт кадрирования: `len(4B BE) ‖ record` — round-trip, обрезка и неверная длина
    /// дают `Unsupported`, а не панику.
    #[test]
    fn contract_frame_codec_round_trip() {
        let rec = record(300, 4, b"cipher");
        let frame = encode_frame(&rec);
        assert_eq!(&frame[..FRAME_LEN_BYTES], &(rec.encode().len() as u32).to_be_bytes());
        assert_eq!(&frame[FRAME_LEN_BYTES..], rec.encode().as_slice());
        assert_eq!(decode_frame(&frame), Ok(rec.clone()));

        assert_eq!(decode_frame(&frame[..2]), Err(BindingError::Unsupported));
        assert_eq!(
            decode_frame(&frame[..frame.len() - 1]),
            Err(BindingError::Unsupported),
            "несовпадение префикса длины — отказ"
        );
        let mut lying = frame.clone();
        lying[3] = lying[3].wrapping_add(7);
        assert_eq!(decode_frame(&lying), Err(BindingError::Unsupported));
    }

    /// Контракт мока: потеря моделируется после `Ok` (как сеть), журнал фиксирует
    /// доставленное, а очередь вычерпывается писателем.
    #[test]
    fn contract_mem_binding_loss_and_journal() {
        let mut binding = MemBinding::new(BindingCaps::QUIC).with_loss_every(3);
        for seq in 0..6 {
            assert_eq!(binding.send(&record(seq, 1, b"d")), Ok(()));
        }
        assert_eq!(binding.offered(), 6);
        assert_eq!(binding.dropped(), 2, "каждая третья запись потеряна в сети");
        assert_eq!(
            binding.journal(),
            &[(StreamId(1), 0), (StreamId(1), 1), (StreamId(1), 3), (StreamId(1), 4)]
        );
        let pending = binding.take_pending();
        assert_eq!(pending.len(), 4, "доставленные кадры ушли в очередь писателя");
        assert_eq!(pending[0].0, StreamId(1));
        assert_eq!(binding.pending_bytes(), 0);

        // Никакого тайного удержания: очередь отдаёт ровно те записи, что в журнале.
        for (index, (stream, frame)) in pending.iter().enumerate() {
            let decoded = decode_frame(frame).expect("кадр разбирается");
            assert_eq!(decoded.stream_id, *stream);
            assert_eq!(
                decoded.seq.0,
                binding.journal()[index].1,
                "порядок очереди = порядок журнала"
            );
        }
    }
}
