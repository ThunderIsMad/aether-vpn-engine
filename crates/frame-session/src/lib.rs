//! `frame-session` — record-протокол, носитель сессии (критический путь Phase 0).
//!
//! **In:** app flows от `policy-engine`; события морфа и ротации от вышестоящих модулей.
//! **Out:** records в активный байндинг; ACK/continuity события.
//! **State:** `stream_table`, `seq`, ratchet `K_record[n]`, duplicate-window (4096 записей, bitmap 512 B).
//! **Deps:** нет. Крейт транспортно-независим и тестируется на моках байндингов
//! (`design/03-components.md` §1, «Порядок зависимостей для сборки»).
//!
//! Формат записи (`design/02-protocols.md` §1):
//!
//! ```text
//! Record = type(1B) | seq(varint) | stream_id(varint) | flags(1B) | len(varint) | ciphertext
//! ciphertext = XChaCha20-Poly1305(K_record, nonce = seq(8B) || sid(16B), plaintext)
//! ```
//!
//! Сессия — это НЕ транспортное соединение: таблица потоков + ключи + счётчики, живущие
//! на клиенте и восстановимые на узле из ticket.
//!
//! ## Что реализовано в Phase 0 и где реализация разошлась со спекой
//!
//! 1. **`seq` добавлен в заголовок записи.** В `02 §1` заголовок — `type | stream_id | flags |
//!    len`; `seq` там нет. Но дедуп у узла — по `(sid, seq)` (`§3.5`), а `seq` входит в nonce,
//!    то есть получатель обязан знать его из заголовка, иначе дедуплицировать нечем. Layout стал
//!    `type(1B) | seq(varint) | stream_id(varint) | flags(1B) | len(varint) | ciphertext`.
//!    Это правка формата, а не вычитка: она вынесена в `QUESTIONS.md` (Phase 0 finding).
//! 2. **AAD записи — заголовок без поля `len`**: `type | seq | stream_id | flags`. Спека молчит
//!    про AAD; связывание заголовка аутентифицирует `type`/`seq`/`stream_id`/`flags` и делает
//!    «записи не теряются и порядок по `seq`» проверяемым, а не декларативным. `len` из AAD
//!    исключён сознательно: он выводится из шифротекста, и включение длины в один и тот же
//!    набор байтов до и после шифрования невозможно без завязки на размер тега AEAD.
//! 3. **Крипто-операции инжектируются трейтом `SessionCrypto`**, чтобы крейт остался
//!    без зависимостей (`03` §1: «Deps: нет», крейт транспортно-независим). Реализация трейта
//!    поверх `crypto-core` живёт в интеграционном крейте `rotation-tests`; юнит-тесты этого
//!    крейта используют мок. Проверка подписи узла (`ResumeError::BadNodeSignature`) —
//!    контракт `key-coordinator` (`03`, «Контракты»), здесь фиксируется уже принятый ACK.
//! 4. **`K_record[n]` — цепочка, а не хранилище секретов:** `K_record[n] = HKDF^n(K_record[0])`.
//!    Это ровно `K_record[n] = HKDF(K_record[n-1])` из `§1`, но записанное в форме, которую
//!    получатель может вычислить для произвольного `seq` (иначе после потери записи ratchet
//!    узла и клиента разъезжается, и «дедуп по `(sid, seq)`» несовместим с приёмом с гэпами).
//!    Член цепочки для приёма вычисляется итерацией от базы; кэш — оптимизация Phase 1.
//!
//! Открытые остатки (в `QUESTIONS.md`): слайд окна при выпадении битов проверен юнит-тестом,
//! но лимит итераций (`CHAIN_ITERATION_LIMIT`) — наша защита, а не норма спеки; политика
//! удержания `K_session` в at-rest — Phase 1 hardening (`03` §7).

#![deny(unsafe_code)]

/// Идентификатор прикладного потока (route rule / app flow).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowId(pub u64);

/// Идентификатор потока внутри сессии (`stream_id`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId(pub u32);

/// Монотонный счётчик записей сессии (не потока). Входит в nonce и в continuity point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Seq(pub u64);

/// 16-байтовый идентификатор сессии (`sid`). Входит в nonce каждой записи.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; 16]);

/// Публичный эфемерный ключ узла (`eph_node` X25519 pub, 32 B) из `RESUME_ACK` (`02 §3.3`).
///
/// Дублирует `key_coordinator::X25519Pub` сознательно: `frame-session` не зависит ни от кого
/// (крейт транспортно-независим и тестируется на моках). Сведение примитивов в общий крейт —
/// решение Phase 0 (`QUESTIONS.md` Q3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X25519Pub(pub [u8; 32]);

/// Подпись Ed25519 узла (`sig_node`, 64 B) над `RESUME_ACK` (`02 §3.3`).
///
/// Передаётся в сессию вместе с `eph_node`, потому что проверка подписи — часть контракта:
/// без неё скомпрометированный старый узел подсунул бы свой `eph_node` и сохранил чтение.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

/// Типы записей (`02 §1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    Data,
    Ack,
    Resume,
    ResumeAck,
    Rekey,
    Keepalive,
    CoverHint,
    Close,
}

impl RecordType {
    /// Код типа в заголовке (1 B).
    pub fn code(self) -> u8 {
        match self {
            RecordType::Data => 0x01,
            RecordType::Ack => 0x02,
            RecordType::Resume => 0x03,
            RecordType::ResumeAck => 0x04,
            RecordType::Rekey => 0x05,
            RecordType::Keepalive => 0x06,
            RecordType::CoverHint => 0x07,
            RecordType::Close => 0x08,
        }
    }

    /// Обратное отображение кода; неизвестный код — `RecordError::BadLayout`.
    pub fn from_code(code: u8) -> Result<Self, RecordError> {
        match code {
            0x01 => Ok(RecordType::Data),
            0x02 => Ok(RecordType::Ack),
            0x03 => Ok(RecordType::Resume),
            0x04 => Ok(RecordType::ResumeAck),
            0x05 => Ok(RecordType::Rekey),
            0x06 => Ok(RecordType::Keepalive),
            0x07 => Ok(RecordType::CoverHint),
            0x08 => Ok(RecordType::Close),
            _ => Err(RecordError::BadLayout),
        }
    }
}

/// Флаг FIN прикладного потока (`02 §1`, FIN-семантика через flags).
pub const FLAG_FIN: u8 = 0x01;

/// Зашифрованная запись: `type | seq | stream_id | flags | len | ciphertext`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Тип записи.
    pub kind: RecordType,
    /// Поток, которому принадлежит запись.
    pub stream_id: StreamId,
    /// Флаги (FIN-семантика прикладного потока — `02 §1`).
    pub flags: u8,
    /// Монотонный `seq` сессии: входит в nonce и служит ключом дедупа `(sid, seq)`.
    pub seq: Seq,
    /// XChaCha20-Poly1305 шифротекст; nonce = `seq || sid` (24 B, см. `crypto-core`).
    pub ciphertext: Vec<u8>,
}

impl Record {
    /// Заголовок записи — байты до `ciphertext`. Одновременно AAD записи.
    pub fn header_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16);
        out.push(self.kind.code());
        write_varint(&mut out, self.seq.0);
        write_varint(&mut out, u64::from(self.stream_id.0));
        out.push(self.flags);
        write_varint(&mut out, self.ciphertext.len() as u64);
        out
    }

    /// Байты для AAD: заголовок **без** поля `len`.
    ///
    /// `len` выводится из самого шифротекста при разборе, поэтому аутентифицировать его
    /// нечем и незачем: подмена `len` меняет границу `ciphertext`, и Poly1305-тег всё равно
    /// не сходится. Остальные поля заголовка (`type`, `seq`, `stream_id`, `flags`) —
    /// инвариантны на приёме, и именно они защищены AAD.
    pub fn aad_bytes(&self) -> Vec<u8> {
        let mut out = self.header_bytes();
        // Отрезаем последний varint — это `len` (он кодируется в 1..=9 байт; отрезаем по счётчику).
        let len_varint = varint_len(self.ciphertext.len() as u64);
        out.truncate(out.len() - len_varint);
        out
    }

    /// Полное кодирование записи (`02 §1`).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.header_bytes();
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Разбор записи. Обрезанный или неверный вход — `RecordError::BadLayout`, не паника.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut pos = 0usize;
        let kind = RecordType::from_code(*bytes.first().ok_or(RecordError::BadLayout)?)?;
        pos += 1;
        let seq = Seq(read_varint(bytes, &mut pos)?);
        let stream_id = StreamId(
            u32::try_from(read_varint(bytes, &mut pos)?).map_err(|_| RecordError::BadLayout)?,
        );
        let flags = *bytes.get(pos).ok_or(RecordError::BadLayout)?;
        pos += 1;
        let len =
            usize::try_from(read_varint(bytes, &mut pos)?).map_err(|_| RecordError::BadLayout)?;
        let end = pos.checked_add(len).ok_or(RecordError::BadLayout)?;
        let ciphertext = bytes.get(pos..end).ok_or(RecordError::BadLayout)?.to_vec();
        if end != bytes.len() {
            return Err(RecordError::BadLayout);
        }
        Ok(Self {
            kind,
            stream_id,
            flags,
            seq,
            ciphertext,
        })
    }
}

/// Nonce записи: `seq(8B, big-endian) || sid(16B)` — 24 B под XChaCha20-Poly1305 (`02 §1`).
pub fn record_nonce(seq: Seq, session_id: &SessionId) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..8].copy_from_slice(&seq.0.to_be_bytes());
    nonce[8..].copy_from_slice(&session_id.0);
    nonce
}

/// Длина ULEB128-varint для значения — нужна, чтобы отрезать поле `len` при сборке AAD.
fn varint_len(mut value: u64) -> usize {
    let mut bytes = 1usize;
    while value >= 0x80 {
        value >>= 7;
        bytes += 1;
    }
    bytes
}

/// ULEB128-varint (`02 §1` называет поля varint, не фиксируя ширину).
fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Чтение ULEB128-varint; неполный вход — `BadLayout`.
fn read_varint(bytes: &[u8], pos: &mut usize) -> Result<u64, RecordError> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *bytes.get(*pos).ok_or(RecordError::BadLayout)?;
        *pos += 1;
        if shift >= 64 {
            return Err(RecordError::BadLayout);
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

/// Ошибка record-слоя.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    /// Запись не разбирается: обрезанный или неверный заголовок.
    BadLayout,
    /// Вскрытие не прошло аутентификацию.
    OpenFailed,
    /// Запись ссылается на неизвестный поток.
    StreamUnknown,
    /// `seq` слишком далеко от базы цепочки — вывод ключа отвергнут защитой.
    TooFar,
}

/// Крипто-операции record-слоя. Реализуется поверх `crypto-core`; сам крейт зависимостей
/// не имеет (`03` §1). Все операции — из `02 §1`: ratchet, seal, open.
pub trait SessionCrypto {
    /// Один шаг ratchet: `K_record[n] = HKDF(K_record[n-1])` (`02 §1`).
    fn ratchet(&self, session_id: &[u8; 16], k_record: &[u8; 32]) -> [u8; 32];

    /// `XChaCha20-Poly1305(K_record, nonce = seq(8B) || sid(16B), aad)` (`02 §1`).
    fn seal(&self, k_record: &[u8; 32], nonce: [u8; 24], aad: &[u8], plaintext: &[u8]) -> Vec<u8>;

    /// Открытие записи; отказ — `RecordError::OpenFailed`, не паника.
    fn open(
        &self,
        k_record: &[u8; 32],
        nonce: [u8; 24],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, RecordError>;
}

/// Окно дедупликации узла: 4096 записей, bitmap 512 B на сессию (`02 §3.5`).
///
/// Границы, которые узел подтверждает в `RESUME_ACK`; `seq < lo` → drop,
/// повтор `seq` внутри окна → drop без сдвига `continuity_point`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplicateWindow {
    /// Нижняя граница окна: `max(пол из ticket, last_seq − 4096)`.
    pub lo: Seq,
    /// Верхняя граница окна (`continuity_point`).
    pub hi: Seq,
}

/// Размер окна дубликатов в записях (`02 §3.5`; тот же бюджет используется как `N`
/// в окне морфа — `02 §4`).
pub const DUPLICATE_WINDOW_RECORDS: u32 = 4096;

/// Размер bitmap окна дедупа: 4096 бит = 512 B на сессию (`02 §3.5`).
pub const DUPLICATE_WINDOW_BYTES: usize = (DUPLICATE_WINDOW_RECORDS as usize) / 8;

/// Итог приёма `seq` окном дедупа (`02 §3.5`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupOutcome {
    /// Запись новая: доставить приложению.
    Accepted,
    /// Повтор внутри окна: drop, `continuity_point` не двигается.
    Duplicate,
    /// `seq < window_lo`: drop + счётчик аномалии.
    BelowWindow,
}

/// Живое окно дедупа узла (`02 §3.5`): пол окна, `continuity_point`, bitmap и счётчик аномалий.
///
/// Живёт только на время сессии; состояния, переживающего ротацию, у узла нет
/// (`§3.5`, `§3.6`). При рестарте окно восстанавливается из подписанного клиентом `last_seq`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DedupWindow {
    floor: Seq,
    lo: Seq,
    hi: Seq,
    seen: [u8; DUPLICATE_WINDOW_BYTES],
    anomalies: u64,
    restored: bool,
}

impl DedupWindow {
    /// Новое окно с полом из ticket (`§3.5`: `max(пол из ticket, last_seq − 4096)`).
    pub fn new(floor: Seq, last_seq: Seq) -> Self {
        let lo = Self::slide_lo(floor, last_seq);
        Self {
            floor,
            lo,
            hi: last_seq,
            seen: [0u8; DUPLICATE_WINDOW_BYTES],
            anomalies: 0,
            restored: false,
        }
    }

    /// Восстановление окна из подписанного клиентом `last_seq` (`§3.5`, строка «Потеря состояния»).
    ///
    /// Всё, что `≤ last_seq`, считается уже доставленным: клиент подписал этот `last_seq`, значит
    /// узел подтвердил continuity point по нему. Поэтому в восстановленном окне повтор `≤ hi`
    /// — `Duplicate`, а не новая запись: это и есть at-most-once (`§3.5`) без глобального
    /// exactly-once.
    pub fn restore_from_signed_last_seq(last_seq: Seq) -> Self {
        let mut window = Self::new(Seq(0), last_seq);
        window.restored = true;
        window
    }

    fn slide_lo(floor: Seq, last_seq: Seq) -> Seq {
        let lowest = last_seq.0.saturating_add(1).saturating_sub(u64::from(DUPLICATE_WINDOW_RECORDS));
        Seq(lowest.max(floor.0))
    }

    /// Текущее окно для подписи/ACK (`§3.3`, `§3.5`).
    pub fn window(&self) -> DuplicateWindow {
        DuplicateWindow {
            lo: self.lo,
            hi: self.hi,
        }
    }

    /// Подтверждённый continuity point (монотонный, `§3.5`).
    pub fn continuity_point(&self) -> Seq {
        self.hi
    }

    /// Счётчик аномалий `seq < window_lo` (`§3.5`).
    pub fn anomalies(&self) -> u64 {
        self.anomalies
    }

    /// Размер bitmap в байтах (512 B на сессию — `§3.5`).
    pub fn bitmap_bytes(&self) -> usize {
        DUPLICATE_WINDOW_BYTES
    }

    fn bit(&self, index: usize) -> bool {
        index < DUPLICATE_WINDOW_RECORDS as usize
            && self.seen[index / 8] & (1u8 << (index % 8)) != 0
    }

    fn mark(&mut self, index: usize) {
        if index < DUPLICATE_WINDOW_RECORDS as usize {
            self.seen[index / 8] |= 1u8 << (index % 8);
        }
    }

    fn slide_to(&mut self, new_lo: Seq) {
        if new_lo <= self.lo {
            return;
        }
        let delta = (new_lo.0 - self.lo.0) as usize;
        if delta >= DUPLICATE_WINDOW_RECORDS as usize {
            self.seen = [0u8; DUPLICATE_WINDOW_BYTES];
        } else {
            let mut shifted = [0u8; DUPLICATE_WINDOW_BYTES];
            for index in delta..DUPLICATE_WINDOW_RECORDS as usize {
                if self.bit(index) {
                    shifted[(index - delta) / 8] |= 1u8 << ((index - delta) % 8);
                }
            }
            self.seen = shifted;
        }
        self.lo = new_lo;
    }

    /// Принимает `seq` (`§3.5`): drop ниже пола и повторов, `continuity_point` двигает только
    /// запись выше `hi`.
    pub fn accept(&mut self, seq: Seq) -> DedupOutcome {
        if seq < self.floor || seq < self.lo {
            self.anomalies += 1;
            return DedupOutcome::BelowWindow;
        }
        if seq <= self.hi {
            if self.restored {
                return DedupOutcome::Duplicate;
            }
            let index = (seq.0 - self.lo.0) as usize;
            if self.bit(index) {
                return DedupOutcome::Duplicate;
            }
            self.mark(index);
            return DedupOutcome::Accepted;
        }
        self.slide_to(Self::slide_lo(self.floor, seq));
        let index = (seq.0 - self.lo.0) as usize;
        self.mark(index);
        self.hi = seq;
        DedupOutcome::Accepted
    }
}

/// Таймаут и бюджет окна перекрытия (`02 §4`, владелец — FrameSession).
pub const T_MORPH_MIN_MS: u64 = 200;
/// Верхний клип `T_morph` (`02 §4`).
pub const T_MORPH_MAX_MS: u64 = 2_000;
/// `T_quar` — обложка не выбирается 5 мин (`02 §4`).
pub const T_QUARANTINE_MS: u64 = 5 * 60 * 1_000;

/// `T_morph` = 2 × SRTT, клип [200 ms, 2 s] (`02 §4`).
pub fn t_morph_ms(srtt_ms: u64) -> u64 {
    srtt_ms.saturating_mul(2).clamp(T_MORPH_MIN_MS, T_MORPH_MAX_MS)
}

/// `T_ack` = 2 × SRTT, клип [200 ms, 2 s] (`02 §3.7`); владелец таймера — FrameSession.
pub fn t_ack_ms(srtt_ms: u64) -> u64 {
    t_morph_ms(srtt_ms)
}

/// Всего попыток `RESUME` на один ticket: первая + одна повторная, затем откат на старый
/// канал (`02 §3.7`, Q18: «не более двух попыток» — формулировка спеки, не «два ретрая»).
pub const MAX_RESUME_ATTEMPTS: u8 = 2;

/// Шаг дублирования в окне перекрытия.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuplicateStep {
    /// Запись продублирована на оба канала.
    Duplicated,
    /// Бюджет исчерпан (`N ≥ 4096` или `T_morph`): `MorphFailed` → откат + quarantine (`02 §4`).
    Exhausted,
}

/// Окно перекрытия при морфе/ротации (`02 §4`): двойной бюджет — записи **или** время,
/// что раньше; закрывается только валидным ACK по новому байндингу.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverlapWindow {
    timeout_ms: u64,
    duplicated: u32,
    closed: bool,
    exhausted: bool,
}

impl OverlapWindow {
    /// Открывает окно по измеренному SRTT: `T_morph` = 2 × SRTT, клип [200 ms, 2 s].
    pub fn new(srtt_ms: u64) -> Self {
        Self {
            timeout_ms: t_morph_ms(srtt_ms),
            duplicated: 0,
            closed: false,
            exhausted: false,
        }
    }

    /// Таймаут окна (`T_morph`).
    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    /// Бюджет дублирования в записях (`N ≤ 4096`).
    pub fn budget_records(&self) -> u32 {
        DUPLICATE_WINDOW_RECORDS
    }

    /// Сколько записей продублировано.
    pub fn duplicated_records(&self) -> u32 {
        self.duplicated
    }

    /// Продублирована ли запись в бюджет окна (`02 §4`).
    pub fn duplicate(&mut self, elapsed_ms: u64) -> DuplicateStep {
        if self.exhausted
            || elapsed_ms >= self.timeout_ms
            || self.duplicated >= DUPLICATE_WINDOW_RECORDS
        {
            self.exhausted = true;
            return DuplicateStep::Exhausted;
        }
        self.duplicated += 1;
        DuplicateStep::Duplicated
    }

    /// Исчерпан ли бюджет (повод для `MorphFailed`, `02 §4`).
    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// Условие закрытия — **валидный** ACK по новому байндингу (`02 §4`). Невалидный ACK окно
    /// не закрывает (иначе rollback-ветка FSM осталась бы без дублей).
    pub fn close_on_ack(&mut self, ack_valid: bool) -> bool {
        if ack_valid {
            self.closed = true;
        }
        self.closed
    }

    /// Закрыто ли окно.
    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

/// Ветки `RESUME_NAK` (`02 §3.7`) — ровно четыре, без расширения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeNak {
    /// `sig_client` неверна: ticket не консумируется, инцидент в телеметрию узла.
    BadPop,
    /// Повтор ticket на том же узле (`consumed-set` эпохи, `02 §3.6`).
    Replay,
    /// `epoch_id` не совпал → фолбэк: полный IK-handshake (`02 §5`).
    Epoch,
    /// `exp` истёк → фолбэк: полный handshake.
    Expired,
}

impl ResumeNak {
    /// Требует ли ветка фолбэка на полный IK-handshake (`02 §3.7`).
    pub fn requires_full_handshake(self) -> bool {
        matches!(self, ResumeNak::Epoch | ResumeNak::Expired)
    }
}

/// Принятый `RESUME_ACK` после проверки `sig_node` (`02 §3.3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmedAck {
    /// Подтверждённый continuity point.
    pub continuity_point: Seq,
    /// Окно нового узла.
    pub window: DuplicateWindow,
    /// `eph_node` — вход пост-ротационного re-key (`§3.3`).
    pub eph_node: X25519Pub,
    /// `sig_node`, которой ACK был подтверждён (`§3.3`).
    pub sig_node: Signature,
}

/// Предел итераций при выводе члена цепочки для произвольного `seq`: защита от
/// `seq`-фантазий в заголовке (спека такого предела не задаёт — наша защита).
pub const CHAIN_ITERATION_LIMIT: u64 = 1 << 20;

/// Носитель сессии: таблица потоков, `seq`, цепочка `K_record`, окно дедупа, окно перекрытия.
///
/// Инвариант (`02 §1`, `§3.8`): сессия живёт, пока жив `(K_session, stream_table, seq)`.
/// Морф байндинга и ротация узла эти три вещи не сбрасывают — иначе «сессия не рвётся»
/// было бы неправдой.
pub struct Session {
    session_id: SessionId,
    chain_base: [u8; 32],
    chain_cursor: u64,
    chain_key: [u8; 32],
    next_seq: u64,
    streams: Vec<(FlowId, StreamId)>,
    crypto: Box<dyn SessionCrypto>,
    dedup: DedupWindow,
    overlap: Option<OverlapWindow>,
    ack: Option<ConfirmedAck>,
    nak: Option<ResumeNak>,
    ratchet_restarts: u32,
}

impl Session {
    /// Новая сессия от `K_session`: цепочка `K_record` стартует от него (`02 §1`).
    pub fn new(session_id: SessionId, k_session: [u8; 32], crypto: Box<dyn SessionCrypto>) -> Self {
        let chain_base = crypto.ratchet(&session_id.0, &k_session);
        Self {
            session_id,
            chain_base,
            chain_cursor: 0,
            chain_key: chain_base,
            next_seq: 0,
            streams: Vec::new(),
            crypto,
            dedup: DedupWindow::new(Seq(0), Seq(0)),
            overlap: None,
            ack: None,
            nak: None,
            ratchet_restarts: 0,
        }
    }

    /// Идентификатор сессии.
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Последний выданный `seq` (0 — ни одной записи).
    pub fn last_seq(&self) -> Seq {
        Seq(self.next_seq.saturating_sub(1))
    }

    /// Таблица потоков сессии — то, что ротация обязана сохранить (`02 §1`).
    pub fn stream_table(&self) -> &[(FlowId, StreamId)] {
        &self.streams
    }

    /// Окно дедупа этой стороны (`02 §3.5`).
    pub fn dedup(&self) -> &DedupWindow {
        &self.dedup
    }

    /// Принятый `RESUME_ACK` (после проверки `sig_node` вызывающим).
    pub fn confirmed_ack(&self) -> Option<ConfirmedAck> {
        self.ack
    }

    /// Последний `RESUME_NAK` (`02 §3.7`); сессия остаётся на старом канале.
    pub fn last_nak(&self) -> Option<ResumeNak> {
        self.nak
    }

    /// Текущее окно перекрытия, если морф/ротация в процессе (`02 §4`).
    pub fn overlap(&self) -> Option<&OverlapWindow> {
        self.overlap.as_ref()
    }

    /// Сколько раз цепочка `K_record` перезапускалась от нового `K_session'` (`§3.3`).
    pub fn ratchet_restarts(&self) -> u32 {
        self.ratchet_restarts
    }

    /// Регистрирует прикладной поток и возвращает его `stream_id` (`03`, контракт FrameSession).
    /// Повторный вызов для того же `FlowId` возвращает прежний `stream_id` — поток не
    /// переоткрывается, FIN-семантика не сбрасывается (`02 §1`).
    pub fn open_stream(&mut self, flow: FlowId) -> StreamId {
        if let Some((_, id)) = self.streams.iter().find(|(f, _)| *f == flow) {
            return *id;
        }
        let id = StreamId(self.streams.len() as u32);
        self.streams.push((flow, id));
        id
    }

    /// Член цепочки `K_record[seq]` — итерацией от базы (`02 §1`).
    fn chain_at(&self, seq: Seq) -> Result<[u8; 32], RecordError> {
        if seq.0 > CHAIN_ITERATION_LIMIT {
            return Err(RecordError::TooFar);
        }
        let mut key = self.chain_base;
        for _ in 0..seq.0 {
            key = self.crypto.ratchet(&self.session_id.0, &key);
        }
        Ok(key)
    }

    /// Запечатывает данные в record под текущим `K_record[n]` (`03`, контракт FrameSession).
    ///
    /// `seq` выдаётся монотонно по сессии (не по потоку), nonce = `seq || sid`, AAD — заголовок.
    pub fn seal_record(&mut self, stream: StreamId, data: &[u8]) -> Record {
        let seq = Seq(self.next_seq);
        self.next_seq = self.next_seq.saturating_add(1);
        while self.chain_cursor < seq.0 {
            self.chain_key = self.crypto.ratchet(&self.session_id.0, &self.chain_key);
            self.chain_cursor += 1;
        }
        let mut record = Record {
            kind: RecordType::Data,
            stream_id: stream,
            flags: 0,
            seq,
            ciphertext: Vec::new(),
        };
        let aad = record.aad_bytes();
        record.ciphertext = self.crypto.seal(
            &self.chain_key,
            record_nonce(seq, &self.session_id),
            &aad,
            data,
        );
        record
    }

    /// Принимает запись: дедуп по `(sid, seq)` (`02 §3.5`) и вскрытие.
    ///
    /// `Ok(None)` — запись отброшена дедупом (повтор или `seq` ниже пола окна);
    /// `Ok(Some(plaintext))` — доставить приложению.
    pub fn recv_record(&mut self, record: &Record) -> Result<Option<Vec<u8>>, RecordError> {
        if record.kind == RecordType::Data
            && !self.streams.iter().any(|(_, id)| *id == record.stream_id)
        {
            return Err(RecordError::StreamUnknown);
        }
        match self.dedup.accept(record.seq) {
            DedupOutcome::Duplicate | DedupOutcome::BelowWindow => Ok(None),
            DedupOutcome::Accepted => {
                let key = self.chain_at(record.seq)?;
                let plaintext = self.crypto.open(
                    &key,
                    record_nonce(record.seq, &self.session_id),
                    &record.aad_bytes(),
                    &record.ciphertext,
                )?;
                Ok(Some(plaintext))
            }
        }
    }

    /// Открывает окно перекрытия по SRTT (`02 §4`): дубли идут на оба канала до валидного ACK.
    pub fn begin_overlap(&mut self, srtt_ms: u64) -> &OverlapWindow {
        self.overlap = Some(OverlapWindow::new(srtt_ms));
        self.overlap
            .as_ref()
            .expect("окно только что установлено")
    }

    /// Продублировать запись в бюджет окна (`02 §4`).
    pub fn duplicate(&mut self, elapsed_ms: u64) -> DuplicateStep {
        match self.overlap.as_mut() {
            Some(window) => window.duplicate(elapsed_ms),
            None => DuplicateStep::Exhausted,
        }
    }

    /// Закрыть окно валидным ACK (`02 §4`).
    pub fn close_overlap_on_ack(&mut self, ack_valid: bool) -> bool {
        match self.overlap.as_mut() {
            Some(window) => window.close_on_ack(ack_valid),
            None => false,
        }
    }

    /// Принимает `RESUME_ACK` нового узла (`03`, контракт FrameSession): его `continuity_point`,
    /// его окно, `eph_node` и `sig_node`; возвращает собственное окно дубликатов клиента.
    ///
    /// `continuity_point` монотонен (`02 §3.5`): меньший ACK не откатывает подтверждённую
    /// границу. Валидность `sig_node` проверяет вызывающий (`key-coordinator`,
    /// `ResumeError::BadNodeSignature`) — сюда попадает уже принятый ACK; `eph_node`/`sig_node`
    /// сохраняются, потому что пост-ротационный re-key обязан использовать проверенный `eph_node`.
    pub fn on_resume_ack(
        &mut self,
        continuity_point: Seq,
        window: DuplicateWindow,
        eph_node: X25519Pub,
        sig_node: Signature,
    ) -> DuplicateWindow {
        let confirmed = continuity_point.max(self.dedup.continuity_point());
        self.dedup = DedupWindow::new(window.lo, confirmed);
        self.ack = Some(ConfirmedAck {
            continuity_point: confirmed,
            window,
            eph_node,
            sig_node,
        });
        self.nak = None;
        self.close_overlap_on_ack(true);
        self.dedup.window()
    }

    /// Принимает `RESUME_NAK` (`03`, контракт FrameSession): сессия остаётся на старом канале.
    ///
    /// `Epoch`/`Expired` означают фолбэк на полный IK-handshake (`02 §3.7`); при этом
    /// `K_session`, `stream_table` и `seq` не сбрасываются, пока фолбэк не удался (`02 §3.8`).
    pub fn on_resume_nak(&mut self, nak: ResumeNak) {
        self.nak = Some(nak);
    }

    /// Перезапускает цепочку `K_record` от пост-ротационного `K_session'` (`02 §3.3`).
    ///
    /// `seq` при этом **не** сбрасывается: сессия не соединение (`§1`), новый узел получает
    /// продолжение нумерации через `continuity_point`.
    pub fn ratchet_from(&mut self, k_session_prime: &[u8; 32]) {
        self.chain_base = self.crypto.ratchet(&self.session_id.0, k_session_prime);
        self.chain_key = self.chain_base;
        self.chain_cursor = 0;
        self.ratchet_restarts = self.ratchet_restarts.saturating_add(1);
    }
}

/// Контракт носителя сессии (`design/03-components.md` §1).
///
/// Инвариант: сессия живёт, пока жив `(K_session, stream_table, seq)`. Транспортные
/// соединения (outer) приходят и уходят — обложки, узлы, even протоколы (`02 §1`).
///
/// Клейм дедупа: идемпотентный дедуп по `(sid, seq)`, **at-most-once на узел**;
/// при ротации — at-least-once (duplicate-окно, `02 §3.5`/`§3.9`). Exactly-once не заявляется.
pub trait FrameSession {
    /// Регистрирует прикладной поток и возвращает его `stream_id`.
    fn open_stream(&mut self, flow: FlowId) -> StreamId;

    /// Запечатывает данные в record под текущим `K_record[n]`.
    fn seal_record(&mut self, stream: StreamId, data: &[u8]) -> Record;

    /// Принимает `RESUME_ACK` нового узла (`02 §3.3`): его `continuity_point`, его окно,
    /// `eph_node` и `sig_node`; возвращает собственное окно дубликатов клиента.
    fn on_resume_ack(
        &mut self,
        continuity_point: Seq,
        window: DuplicateWindow,
        eph_node: X25519Pub,
        sig_node: Signature,
    ) -> DuplicateWindow;

    /// Принимает `RESUME_NAK` (`02 §3.7`): узел отклонил резюм — сессия остаётся на старом
    /// канале, ветка `Epoch`/`Expired` означает фолбэк на полный IK-handshake (`02 §5`).
    fn on_resume_nak(&mut self, nak: ResumeNak);
}

impl FrameSession for Session {
    fn open_stream(&mut self, flow: FlowId) -> StreamId {
        Session::open_stream(self, flow)
    }

    fn seal_record(&mut self, stream: StreamId, data: &[u8]) -> Record {
        Session::seal_record(self, stream, data)
    }

    fn on_resume_ack(
        &mut self,
        continuity_point: Seq,
        window: DuplicateWindow,
        eph_node: X25519Pub,
        sig_node: Signature,
    ) -> DuplicateWindow {
        Session::on_resume_ack(self, continuity_point, window, eph_node, sig_node)
    }

    fn on_resume_nak(&mut self, nak: ResumeNak) {
        Session::on_resume_nak(self, nak)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Мок-крипто для юнит-тестов каркаса: ratchet — детерминированная XOR-функция,
    /// seal — префикс AAD + plaintext. Реальная пара (`crypto-core`) подключается
    /// в интеграционном крейте `rotation-tests`; здесь проверяется каркас, не крипто.
    struct MockCrypto;

    impl SessionCrypto for MockCrypto {
        fn ratchet(&self, session_id: &[u8; 16], k_record: &[u8; 32]) -> [u8; 32] {
            let mut out = [0u8; 32];
            for (index, byte) in k_record.iter().enumerate() {
                out[index] = byte ^ session_id[index % session_id.len()] ^ 0x5a;
            }
            out
        }

        fn seal(&self, _k: &[u8; 32], _nonce: [u8; 24], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
            let mut out = aad.to_vec();
            out.extend_from_slice(plaintext);
            out
        }

        fn open(
            &self,
            _k: &[u8; 32],
            _nonce: [u8; 24],
            aad: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, RecordError> {
            match ciphertext.strip_prefix(aad) {
                Some(plaintext) => Ok(plaintext.to_vec()),
                None => Err(RecordError::OpenFailed),
            }
        }
    }

    /// Контракт record-слоя: запись кодируется в `type | seq | stream_id | flags | len |
    /// ciphertext`, nonce собирается как `seq(8B) || sid(16B)`, `seq` монотонен в пределах сессии.
    #[test]
    fn contract_record_layout_and_nonce() {
        let sid = SessionId([0x33; 16]);
        let mut session = Session::new(sid, [0x44; 32], Box::new(MockCrypto));
        let stream = session.open_stream(FlowId(7));
        assert_eq!(session.open_stream(FlowId(7)), stream, "поток не переоткрывается");

        let record = session.seal_record(stream, b"hello");
        assert_eq!(record.kind, RecordType::Data);
        assert_eq!(record.seq, Seq(0), "нумерация сессии начинается с 0");
        assert_eq!(record.stream_id, stream);

        let nonce = record_nonce(record.seq, &sid);
        assert_eq!(nonce.len(), 24, "nonce XChaCha20-Poly1305 — 24 B");
        assert_eq!(&nonce[..8], &0u64.to_be_bytes(), "nonce: seq(8B) впереди");
        assert_eq!(&nonce[8..], &sid.0, "nonce: sid(16B) следом");

        let bytes = record.encode();
        assert_eq!(bytes[0], RecordType::Data.code(), "layout: type(1B) первым");
        assert_eq!(bytes[1], 0x00, "layout: seq(varint) вторым (0 — один байт)");
        assert_eq!(
            bytes[2], record.stream_id.0 as u8,
            "layout: stream_id(varint) третьим"
        );
        assert_eq!(bytes[3], 0x00, "layout: flags(1B)");
        let decoded = Record::decode(&bytes).expect("round-trip");
        assert_eq!(decoded, record);
        assert_eq!(decoded.header_bytes(), record.header_bytes());
        assert_eq!(
            decoded.aad_bytes(),
            record.aad_bytes(),
            "AAD одинаков до и после шифрования (заголовок без len)"
        );
        assert_eq!(
            record.aad_bytes().len(),
            4,
            "AAD = type + seq + stream_id + flags"
        );

        // Seq монотонен по сессии, а не по потоку: второй поток продолжает нумерацию.
        let other = session.open_stream(FlowId(9));
        let second = session.seal_record(other, b"world");
        assert!(second.seq > record.seq, "seq монотонен в пределах сессии");

        // Обрезанный и испорченный вход — BadLayout, не паника.
        assert_eq!(
            Record::decode(&bytes[..bytes.len() - 1]),
            Err(RecordError::BadLayout)
        );
        assert_eq!(Record::decode(&[0xff]), Err(RecordError::BadLayout));

        // Приём собственной записи: один и тот же seq открывается, но второй раз — дедуп.
        let mut receiver = Session::new(sid, [0x44; 32], Box::new(MockCrypto));
        receiver.open_stream(FlowId(7));
        assert_eq!(
            receiver.recv_record(&record).expect("первая запись"),
            Some(b"hello".to_vec())
        );
        assert_eq!(
            receiver.recv_record(&record).expect("повтор"),
            None,
            "повтор (sid, seq) отброшен дедупом"
        );
        assert_eq!(receiver.dedup().continuity_point(), Seq(0));
    }

    /// Контракт дедупа: окно 4096 записей, `seq < window_lo` → drop,
    /// повтор внутри окна → drop без сдвига `continuity_point`; восстановление окна
    /// из подписанного клиентом `last_seq` после рестарта узла.
    #[test]
    fn contract_dedup_window_boundaries() {
        assert_eq!(DUPLICATE_WINDOW_RECORDS, 4096);
        assert_eq!(DUPLICATE_WINDOW_BYTES, 512);
        let mut fresh = DedupWindow::new(Seq(0), Seq(0));
        assert_eq!(fresh.bitmap_bytes(), 512, "bitmap 512 B на сессию");
        assert_eq!(fresh.accept(Seq(0)), DedupOutcome::Accepted);
        assert_eq!(fresh.accept(Seq(0)), DedupOutcome::Duplicate);
        assert_eq!(fresh.continuity_point(), Seq(0), "повтор не двигает границу");
        assert_eq!(fresh.accept(Seq(5)), DedupOutcome::Accepted);
        assert_eq!(fresh.continuity_point(), Seq(5));
        assert_eq!(
            fresh.accept(Seq(2)),
            DedupOutcome::Accepted,
            "поздняя запись внутри окна — новая, а не дубль"
        );
        assert_eq!(
            fresh.continuity_point(),
            Seq(5),
            "запись внутри окна не двигает continuity_point"
        );
        assert_eq!(fresh.accept(Seq(3)), DedupOutcome::Accepted);

        // Пол окна слайдится: первая запись за пределами 4096 вытесняет нижние.
        let last = Seq(u64::from(DUPLICATE_WINDOW_RECORDS) + 10);
        assert_eq!(fresh.accept(last), DedupOutcome::Accepted);
        assert_eq!(fresh.window().lo, Seq(last.0 + 1 - u64::from(DUPLICATE_WINDOW_RECORDS)));
        assert_eq!(fresh.window().hi, last);
        assert_eq!(fresh.accept(Seq(5)), DedupOutcome::BelowWindow);
        assert_eq!(fresh.anomalies(), 1, "seq ниже пола считается аномалией");

        // Восстановление из подписанного last_seq (`§3.5`, строка «Потеря состояния»).
        let mut restored = DedupWindow::restore_from_signed_last_seq(Seq(10_000));
        assert_eq!(restored.continuity_point(), Seq(10_000));
        assert_eq!(
            restored.window().lo,
            Seq(10_000 + 1 - u64::from(DUPLICATE_WINDOW_RECORDS))
        );
        assert_eq!(
            restored.accept(Seq(6_000)),
            DedupOutcome::Duplicate,
            "всё ≤ подписанного last_seq уже доставлено (at-most-once)"
        );
        assert_eq!(restored.continuity_point(), Seq(10_000));
        assert_eq!(restored.accept(Seq(10_001)), DedupOutcome::Accepted);
        assert_eq!(restored.accept(Seq(10_001)), DedupOutcome::Duplicate);
        assert_eq!(restored.accept(Seq(1)), DedupOutcome::BelowWindow);

        // Пол из ticket не понижается (`§3.5`: window_lo = max(пол из ticket, last_seq − 4096)).
        let mut floored = DedupWindow::new(Seq(9_000), Seq(9_000));
        assert_eq!(floored.window().lo, Seq(9_000));
        assert_eq!(floored.accept(Seq(8_999)), DedupOutcome::BelowWindow);
    }

    /// Контракт окна морфа (`02 §4`): `T_morph` = 2 × SRTT с клипом, бюджет
    /// `N ≤ 4096` **или** `T_morph` — что раньше; закрытие только валидным ACK.
    #[test]
    fn contract_overlap_window_budget_and_ack_closure() {
        assert_eq!(t_morph_ms(10), T_MORPH_MIN_MS, "клип снизу 200 ms");
        assert_eq!(t_morph_ms(500), 1_000, "2 × SRTT внутри клипа");
        assert_eq!(t_morph_ms(5_000), T_MORPH_MAX_MS, "клип сверху 2 s");
        assert_eq!(t_ack_ms(500), 1_000, "T_ack = 2 × SRTT (`02 §3.7`)");
        assert_eq!(MAX_RESUME_ATTEMPTS, 2, "первая попытка + одна повторная (`02 §3.7`, Q18)");
        assert_eq!(T_QUARANTINE_MS, 300_000, "T_quar = 5 мин (`02 §4`)");

        let mut window = OverlapWindow::new(500);
        assert_eq!(window.timeout_ms(), 1_000);
        assert_eq!(window.budget_records(), 4096);
        assert_eq!(window.duplicate(0), DuplicateStep::Duplicated);
        assert!(!window.close_on_ack(false), "невалидный ACK окно не закрывает");
        assert!(!window.is_closed());
        assert!(window.close_on_ack(true), "валидный ACK закрывает окно");
        assert!(window.is_closed());

        // Бюджет по времени: исчерпание — `MorphFailed`, а не «деградация» (`02 §4`).
        let mut timed_out = OverlapWindow::new(500);
        assert_eq!(timed_out.duplicate(999), DuplicateStep::Duplicated);
        assert_eq!(timed_out.duplicate(1_000), DuplicateStep::Exhausted);
        assert!(timed_out.is_exhausted());

        // Бюджет по записям.
        let mut by_records = OverlapWindow::new(500);
        for _ in 0..DUPLICATE_WINDOW_RECORDS {
            assert_eq!(by_records.duplicate(0), DuplicateStep::Duplicated);
        }
        assert_eq!(by_records.duplicate(0), DuplicateStep::Exhausted);
        assert_eq!(by_records.duplicated_records(), DUPLICATE_WINDOW_RECORDS);
    }

    /// Контракт ротации на frame-слое (`02 §3.3`, §3.5, §3.8): сессия и таблица потоков
    /// переживают ротацию, `continuity_point` монотонен, `seq` продолжается, re-key
    /// перезапускает цепочку, NAK не сбрасывает состояние.
    #[test]
    fn contract_session_survives_rotation() {
        let sid = SessionId([0x55; 16]);
        let mut session = Session::new(sid, [0x66; 32], Box::new(MockCrypto));
        let stream = session.open_stream(FlowId(1));
        let first = session.seal_record(stream, b"before");

        let window = session.begin_overlap(500);
        assert_eq!(window.timeout_ms(), 1_000);
        assert_eq!(session.duplicate(100), DuplicateStep::Duplicated);

        let client_window = session.on_resume_ack(
            Seq(0),
            DuplicateWindow {
                lo: Seq(0),
                hi: Seq(0),
            },
            X25519Pub([0x77; 32]),
            Signature([0x88; 64]),
        );
        assert_eq!(client_window.hi, Seq(0));
        assert!(
            session.overlap().expect("окно открыто").is_closed(),
            "валидный ACK закрывает окно перекрытия (02 §4)"
        );
        let ack = session.confirmed_ack().expect("ACK принят");
        assert_eq!(ack.eph_node, X25519Pub([0x77; 32]));
        assert_eq!(ack.sig_node, Signature([0x88; 64]));

        // Монотонность: меньший ACK не откатывает подтверждённую границу (`§3.5`).
        let stale = session.on_resume_ack(
            Seq(0),
            DuplicateWindow {
                lo: Seq(0),
                hi: Seq(0),
            },
            X25519Pub([0x99; 32]),
            Signature([0xaa; 64]),
        );
        assert_eq!(stale.hi, Seq(0));

        // Re-key: цепочка перезапускается от K_session', seq и потоки не сбрасываются.
        session.ratchet_from(&[0xbb; 32]);
        assert_eq!(session.ratchet_restarts(), 1);
        let after = session.seal_record(stream, b"after");
        assert!(after.seq > first.seq, "seq продолжается после ротации");
        assert_eq!(session.stream_table(), &[(FlowId(1), stream)]);

        // NAK: сессия остаётся на старом канале, состояние не сбрасывается.
        session.on_resume_nak(ResumeNak::Replay);
        assert_eq!(session.last_nak(), Some(ResumeNak::Replay));
        assert!(!ResumeNak::Replay.requires_full_handshake());
        assert!(ResumeNak::Epoch.requires_full_handshake());
        assert!(ResumeNak::Expired.requires_full_handshake());
        assert!(!ResumeNak::BadPop.requires_full_handshake());
        assert_eq!(session.last_seq(), after.seq);
        assert_eq!(session.stream_table().len(), 1);
    }
}
