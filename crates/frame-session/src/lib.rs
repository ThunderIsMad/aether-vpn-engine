//! `frame-session` — record-протокол, носитель сессии (критический путь Phase 0).
//!
//! **In:** app flows от `policy-engine`; события морфа и ротации от вышестоящих модулей.
//! **Out:** records в активный байндинг; ACK/continuity события.
//! **State:** `stream_table`, `seq`, поколение `K_session` для `K_record`, duplicate-window (4096 записей, bitmap 512 B).
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
//! 4. **`K_record[n]` — константный вывод, а не хранилище секретов** (F-02, аудит 3):
//!    `K_record[n] = HKDF(salt = sid, ikm = K_session, info = LABEL_RECORD ‖ be64(n))`.
//!    Член для произвольного `seq` — один шаг HKDF (`RecordCrypto::record_key_at`):
//!    приём O(1), прежняя O(seq)-цепочка (~50 мс/запись при seq = 1e5) и её лимит
//!    итераций убраны. Forward-изоляция членов даже сильнее цепочки: утечка
//!    `K_record[n]` не даёт ни прошлых, ни будущих членов; компрометация `K_session`
//!    раскрывает всё поколение — средство сужения окна: внутри-сессионный re-key
//!    (`RecordType::Rekey`; реализован в Q25: пороги поколений, seq-сплит базы) и ротация.
//!
//! Открытые остатки (в `QUESTIONS.md`): слайд окна при выпадении битов проверен юнит-тестом;
//! периодический re-key реализован (`RecordType::Rekey`, Q25 — политика `REKEY_TRIGGER_BYTES`);
//! политика
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

/// Политика триггера re-key (Q25): смена поколения `K_record` назревает за четверть
/// потолка до него (`REKEY_POLICY_LIMIT / 4 * 3`) и повторяется раз в это окно —
/// смена поколения происходит до лимита по решению владельца сессии
/// (`needs_rekey()`/`begin_rekey`), а не аварийным обрывом на самом лимите.
pub const REKEY_TRIGGER_BYTES: u64 = REKEY_POLICY_LIMIT / 4 * 3;

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

/// Чтение ULEB128-varint; неполный вход — `BadLayout`. Неканонические (overlong)
/// кодировки отклоняются (аудит F-12): одно значение обязано иметь ровно один проводной
/// вид, иначе AAD-сборка по «отрезанному len» даёт неоднозначность и нестандартные
/// кодировки становятся скрытым каналом расхождений между отправителем и приёмником.
fn read_varint(bytes: &[u8], pos: &mut usize) -> Result<u64, RecordError> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *bytes.get(*pos).ok_or(RecordError::BadLayout)?;
        *pos += 1;
        if shift >= 64 {
            return Err(RecordError::BadLayout);
        }
        let is_last = byte & 0x80 == 0;
        value |= u64::from(byte & 0x7f) << shift;
        if is_last {
            // Каноничность (аудит F-12): кодировка n байтов допускается только для значений,
            // не помещающихся в n−1 байтов, т.е. значащая часть последнего байта обязана
            // иметь биты выше (n−1)·7. Пример: [0x85, 0x00] → 5 в двухбайтовой форме —
            // overlong, отвергаем. `shift` здесь — число бит предыдущих групп: значащие
            // биты последнего байта — (byte & 0x7f) != 0, и они обязаны выходить за shift.
            if shift > 0 && byte & 0x7f == 0 {
                return Err(RecordError::BadLayout);
            }
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
    /// `seq` за политическим потолком `REKEY_POLICY_LIMIT` — вывод ключа отвергнут.
    TooFar,
}

/// Крипто-операции record-слоя. Реализуется поверх `crypto-core`; сам крейт зависимостей
/// не имеет (`03` §1). Все операции — из `02 §1`: record_key_at, seal, open.
pub trait SessionCrypto {
    /// Член `K_record[seq]` для произвольного `seq` — ОДИН шаг (F-02, аудит 3):
    /// в прод-адаптере — `crypto_core::derive_record_key` (`HKDF(salt = sid,
    /// ikm = base, info = LABEL_RECORD ‖ be64(seq))`). Приёмная сторона не итерирует от
    /// базы: прежний O(seq)-вывод давал само-DoS (~50 мс/запись при seq = 1e5) и жёсткий
    /// обрыв на лимите итераций. `base` — `K_session` (после re-key — `K_session'` этого
    /// поколения цепочки).
    fn record_key_at(&self, session_id: &[u8; 16], base: &[u8; 32], seq: u64) -> [u8; 32];

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

    /// Поколение внутри-сессионного re-key (Q25): обе стороны выводят ОДИНАКОВЫЙ ключ
    /// поколения из старой базы и `rekey_nonce`, вскрываемого из rekey-записи. Домен
    /// отделён от `record_key_at` (в прод-адаптере — `LABEL_REKEY`) и от
    /// пост-ротационного вывода: одинаковый вход в разных механизмах даёт разные ключи.
    fn derive_rekey_generation(
        &self,
        session_id: &[u8; 16],
        base: &[u8; 32],
        rekey_nonce: &[u8; 32],
    ) -> [u8; 32];
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

/// Политический потолок `seq` одной сессии (F-02/Q25): вычисление члена теперь O(1),
/// поэтому потолок — не защита от само-DoS (её больше не нужно), а политика re-key:
/// к этому количеству записей сессия обязана сменить поколение `K_record` —
/// реализовано (`begin_rekey`/`needs_rekey`, Q25): `REKEY_TRIGGER_BYTES` назревает
/// смену заранее, потолок — жёсткая граница seq (в т.ч. для самой rekey-записи).
pub const REKEY_POLICY_LIMIT: u64 = 1 << 20;

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
    /// **Семантика `last_seq` (Q26/F-12): «выданный потолок», не «факт приёма»** — клиент
    /// подписывает в RESUME последний **выданный** seq своего отправителя; рестартовавший
    /// узел факт приёма не проверяет и не заявляет. Всё, что `≤ last_seq`, считается уже
    /// доставленным (повтор `≤ hi` — `Duplicate`): at-most-once сохранён, зазор между
    /// реально принятым узлом и потолком теряется из доставки — осознанная потеря
    /// availability при рестарте, не целостности (`§3.5`). `floor` — пол из ticket:
    /// `window_lo = max(пол из ticket, last_seq − 4096)`; раньше пол терялся здесь
    /// (принудительный ноль), что противоречило `§3.5` (Q26/F-12).
    pub fn restore_from_signed_last_seq(floor: Seq, last_seq: Seq) -> Self {
        let mut window = Self::new(floor, last_seq);
        window.restored = true;
        window
    }

    fn slide_lo(floor: Seq, last_seq: Seq) -> Seq {
        let lowest = last_seq
            .0
            .saturating_add(1)
            .saturating_sub(u64::from(DUPLICATE_WINDOW_RECORDS));
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

    /// Проверка «новая ли запись» БЕЗ двигания окна (F-02): та же классификация, что
    /// `accept`, но без отметки бита/сдвига `hi`. Сессия вскрывает запись (AEAD-open) и
    /// только потом коммитит слот через `accept` — отказ вскрытия не consume слот,
    /// поддельный кадр не двигает пол и не выжигает окно.
    pub fn is_new(&self, seq: Seq) -> bool {
        if seq < self.floor || seq < self.lo {
            return false;
        }
        if seq <= self.hi {
            if self.restored {
                return false;
            }
            let index = (seq.0 - self.lo.0) as usize;
            return !self.bit(index);
        }
        true
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
    srtt_ms
        .saturating_mul(2)
        .clamp(T_MORPH_MIN_MS, T_MORPH_MAX_MS)
}

/// `T_ack` = 2 × SRTT, клип [200 ms, 2 s] (`02 §3.7`); владелец таймера — FrameSession.
pub fn t_ack_ms(srtt_ms: u64) -> u64 {
    t_morph_ms(srtt_ms)
}

/// Всего попыток `RESUME` на один ticket: первая + одна повторная, затем откат на старый
/// канал (`02 §3.7`, Q18: «не более двух попыток» — формулировка спеки, не «два ретрая»).
/// Авторитетный счётчик — consumed-запись тикета на узле (Задача 3.1, Q26); копии
/// константы в `ticket-mint` (узел считает бюджет) и `key-coordinator` (локальное зеркало
/// клиента, не авторитет) обязаны совпадать — проверяет контракт-тест `rotation-tests`.
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

/// Ветки `RESUME_NAK` (`02 §3.7`) — ровно пять, без расширения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeNak {
    /// `sig_client` неверна: ticket не консумируется, инцидент в телеметрию узла.
    BadPop,
    /// Байт-в-байт повтор уже принятой попытки RESUME (consumed-запись тикета,
    /// `02 §3.6`; Задача 3.1 — счётчик попыток в consumed-записи).
    Replay,
    /// `epoch_id` не совпал → фолбэк: полный IK-handshake (`02 §5`).
    Epoch,
    /// `exp` истёк → фолбэк: полный handshake.
    Expired,
    /// Бюджет попыток `RESUME` по тикету исчерпан (Задача 3.1, Q26): узел счётчик
    /// санкционированных попыток в consumed-записи (`02 §3.6`). Без фолбэка на
    /// полный handshake — клиент откатывается на старый канал и не тратит тикет заново.
    Budget,
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

/// Носитель сессии: таблица потоков, `seq`, поколение `K_session` для `K_record`, окно
/// дедупа, окно перекрытия.
///
/// Инвариант (`02 §1`, `§3.8`): сессия живёт, пока жив `(K_session, stream_table, seq)`.
/// Морф байндинга и ротация узла эти три вещи не сбрасывают — иначе «сессия не рвётся»
/// было бы неправдой.
pub struct Session {
    session_id: SessionId,
    /// База членов `K_record`: `K_session` текущего поколения (`K_session'` после re-key).
    chain_base: [u8; 32],
    /// Следующий выделяемый seq отправителя (Q26/F-12): монотонен, откат запрещён —
    /// продолжение живого sid возможно только через `resume_as_sender` с явным счётчиком
    /// (персистится клиентом рядом с `K_session`; sync-запись на каждый seal).
    next_seq: u64,
    /// История порогов поколений `K_record` (Q25): `(seq rekey-записи, поколение)`,
    /// от новейшего к старейшему. Seq-сплит базы держит in-flight окно старый/новый
    /// ключ без перебора ключей; ротация (`ratchet_from`) чистит историю.
    gen_bases: Vec<(u64, [u8; 32])>,
    streams: Vec<(FlowId, StreamId)>,
    crypto: Box<dyn SessionCrypto>,
    dedup: DedupWindow,
    overlap: Option<OverlapWindow>,
    ack: Option<ConfirmedAck>,
    nak: Option<ResumeNak>,
    ratchet_restarts: u32,
}

impl Session {
    /// Новая сессия от `K_session`: база членов `K_record` (`02 §1`, F-02).
    ///
    /// Базой служит сам `K_session`: член `K_record[seq]` выводится из него одним шагом
    /// с `seq` в info — отдельный «шаг 0» (бывший `HKDF(K_session)` перед цепочкой) больше
    /// не нужен. Домен не менялся: прежний член №0 был `HKDF(sid, K_session, LABEL_RECORD)`,
    /// новый член №0 — `HKDF(sid, K_session, LABEL_RECORD ‖ 0)` — другой байт info,
    /// та же сила вывода. Сессии Phase 0/1 не переживают этот смену формата (новая эпоха).
    pub fn new(session_id: SessionId, k_session: [u8; 32], crypto: Box<dyn SessionCrypto>) -> Self {
        Self {
            session_id,
            chain_base: k_session,
            next_seq: 0,
            gen_bases: Vec::new(),
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

    /// Сколько раз база `K_record` уже менялась внутри живой сессии (Q25): число
    /// обработанных rekey-поколений (0 — начальная база).
    pub fn rekey_generations(&self) -> usize {
        self.gen_bases.len()
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

    /// Член `K_record[seq]` от указанной базы (Q25: база выбирается seq-сплитом
    /// поколения, `base_for`). Член — один шаг HKDF для любого `seq`
    /// (`RecordCrypto::record_key_at`, F-02). Политический потолок осмысленности `seq`
    /// — `REKEY_POLICY_LIMIT` (Q25): это политика re-key, а не «защита от краха CPU».
    fn record_key_for(&self, base: [u8; 32], seq: Seq) -> Result<[u8; 32], RecordError> {
        if seq.0 > REKEY_POLICY_LIMIT {
            return Err(RecordError::TooFar);
        }
        Ok(self.crypto.record_key_at(&self.session_id.0, &base, seq.0))
    }

    /// Запечатывает данные в record под `K_record[seq]` (`03`, контракт FrameSession).
    ///
    /// `seq` выдаётся монотонно по сессии (не по потоку), nonce = `seq || sid`, AAD — заголовок.
    /// Отправка всегда O(1): ключ выводится на месте, курсоров и предвычислений больше нет.
    ///
    /// Q25: база членов — по seq-сплиту поколения (`base_for`): записи после rekey-записи
    /// шифруются уже новым поколением. Сам выпуск rekey — явный (`begin_rekey` при
    /// `needs_rekey()`): авто-магия в data-пути потребовала бы RNG в этом крейте
    /// (`Deps: нет`) и скрыла бы смену ключевого материала от владельца сессии.
    pub fn seal_record(&mut self, stream: StreamId, data: &[u8]) -> Record {
        let seq = Seq(self.next_seq);
        self.next_seq = self.next_seq.saturating_add(1);
        let base = self.base_for(seq);
        let key = self
            .record_key_for(base, seq)
            .expect("seq выдаётся сессией монотонно и внутри политического потолка");
        let mut record = Record {
            kind: RecordType::Data,
            stream_id: stream,
            flags: 0,
            seq,
            ciphertext: Vec::new(),
        };
        let aad = record.aad_bytes();
        record.ciphertext = self
            .crypto
            .seal(&key, record_nonce(seq, &self.session_id), &aad, data);
        record
    }

    /// Принимает запись: дедуп по `(sid, seq)` (`02 §3.5`) и вскрытие.
    ///
    /// Порядок проверок — F-02: дедуп-ОКНО и база поколения не двигаются до тех пор,
    /// пока запись реально не вскрылась (вычисление ключа — O(1), но AEAD-open может
    /// отказаться): поддельный поток кадров не сдвигает пол окна, не расходует больше
    /// одного HKDF+open на кадр и НЕ переключает поколение ключей (Q25).
    ///
    /// `Ok(None)` — запись отброшена дедупом или это rekey-запись (управление ключами,
    /// приложению не доставляется); `Ok(Some(plaintext))` — доставить приложению.
    pub fn recv_record(&mut self, record: &Record) -> Result<Option<Vec<u8>>, RecordError> {
        if record.kind == RecordType::Data
            && !self.streams.iter().any(|(_, id)| *id == record.stream_id)
        {
            return Err(RecordError::StreamUnknown);
        }
        if !self.dedup.is_new(record.seq) {
            return Ok(None);
        }
        // Ключ и вскрытие ДО двигания окна и ДО переключения базы: отказ/open-failed
        // не consume слот дедупа и не меняет поколение ключей (Q25).
        let base = self.base_for(record.seq);
        let key = self.record_key_for(base, record.seq)?;
        let plaintext = self.crypto.open(
            &key,
            record_nonce(record.seq, &self.session_id),
            &record.aad_bytes(),
            &record.ciphertext,
        )?;
        self.dedup.accept(record.seq);
        // Реальная rekey-запись (Q25): plaintext — `rekey_nonce`; обе стороны выводят
        // из него одинаковое поколение и переключают базу на записи СТРОГО старше seq
        // этой записи (in-flight окно — seq-сплит, см. `base_for`).
        if record.kind == RecordType::Rekey {
            let nonce: [u8; 32] = plaintext
                .as_slice()
                .try_into()
                .map_err(|_| RecordError::BadLayout)?;
            let generation = self
                .crypto
                .derive_rekey_generation(&self.session_id.0, &base, &nonce);
            self.gen_bases.push((record.seq.0, generation));
            return Ok(None);
        }
        Ok(Some(plaintext))
    }

    /// Строит rekey-запись (Q25): шифруется ключом СТАРОГО поколения (`base_for(seq)`
    /// до записи нового порога), plaintext — `rekey_nonce`; база переключается только
    /// после построения записи — отказ вывода ключа не оставляет сессию наполовину
    /// переключённой.
    fn seal_rekey(
        &mut self,
        stream: StreamId,
        rekey_nonce: &[u8; 32],
    ) -> Result<Record, RecordError> {
        let seq = Seq(self.next_seq);
        self.next_seq = self.next_seq.saturating_add(1);
        let base = self.base_for(seq);
        let key = self.record_key_for(base, seq)?;
        let mut record = Record {
            kind: RecordType::Rekey,
            stream_id: stream,
            flags: 0,
            seq,
            ciphertext: Vec::new(),
        };
        let aad = record.aad_bytes();
        record.ciphertext =
            self.crypto
                .seal(&key, record_nonce(seq, &self.session_id), &aad, rekey_nonce);
        let generation =
            self.crypto
                .derive_rekey_generation(&self.session_id.0, &base, rekey_nonce);
        self.gen_bases.push((seq.0, generation));
        Ok(record)
    }

    /// База членов `K_record` для seq (Q25): seq-сплит поколения — все записи
    /// `seq ≤ N` (N — seq rekey-записи) шифруются/вскрываются старой базой,
    /// `seq > N` — поколением из этой rekey-записи. Стек порогов читается от
    /// новейшего: цепочка rekey даёт несколько порогов, in-flight окно —
    /// только между соседними; ветер короткий (одна запись на re-key).
    ///
    /// Ограничение Phase 0 (доступность, НЕ конфиденциальность/целостность):
    /// `gen_bases` живёт в памяти сессии и не персистится — после рестарта владельца
    /// сессии (`resume_as_sender` восстанавливает только `(sid, K_session, next_seq)`)
    /// стек порогов пуст, и записи предыдущего поколения, дошедшие в узком окне после
    /// рестарта, отбрасываются как недешифруемые (AEAD-отказ, слот дедупа не consumed —
    /// F-02). Это тот же класс принятых потерь, что зазор `§3.5`/`§3.7` («выдано, но
    /// не доставлено»): переиспользования ключей и nonce нет — пустой стек не откатывает
    /// базу вывода, а счётчик отправителя персистен. Персистентность порогов rekey (лог
    /// seq'ов + nonce'ов с cadence/crash-семантикой как у `next_seq`) — отдельное
    /// архитектурное решение, естественное место — Phase 1 персистентный store (тот же
    /// трек, что Q20/consumed-set); в рамках Q25 сознательно НЕ решается.
    fn base_for(&self, seq: Seq) -> [u8; 32] {
        if let Some((_, generation)) = self.gen_bases.iter().rev().find(|(n, _)| seq.0 > *n) {
            return *generation;
        }
        self.chain_base
    }

    /// Открывает окно перекрытия по SRTT (`02 §4`): дубли идут на оба канала до валидного ACK.
    pub fn begin_overlap(&mut self, srtt_ms: u64) -> &OverlapWindow {
        self.overlap = Some(OverlapWindow::new(srtt_ms));
        self.overlap.as_ref().expect("окно только что установлено")
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

    /// Восстанавливает окно дедупа из подписанного клиентом `last_seq` (`02 §3.5`, строка
    /// «Потеря состояния»): у узла, потерявшего состояние сессии, нет лучшего источника.
    ///
    /// Q26/F-12: `last_seq` здесь — **«выданный потолок»** отправителя, не «последний
    /// принятый узлом»: у рестартовавшего узла нет способа проверить факт приёма, и он его
    /// не заявляет (в ACK уходит потолок — `key-coordinator::build_resume_ack`, `02 §3.3`).
    /// Всё `≤ last_seq` — `Duplicate` (at-most-once сохранён, зазор до факта приёма теряется
    /// из доставки — availability); продолжение нумерации `> last_seq` принимается. `floor` —
    /// пол из ticket (`§3.5`: `window_lo = max(пол из ticket, last_seq − 4096)`).
    pub fn restore_dedup_from_signed_last_seq(&mut self, floor: Seq, last_seq: Seq) {
        self.dedup = DedupWindow::restore_from_signed_last_seq(floor, last_seq);
    }

    /// Назрел ли rekey по политике (Q25): раз в `REKEY_TRIGGER_BYTES` (¾ потолка) на
    /// поколение; после rekey окно политики начинается заново. Консультативный признак
    /// для владельца сессии: механический запрет в `begin_rekey` один — политический
    /// потолок `REKEY_POLICY_LIMIT` на seq самой rekey-записи.
    pub fn needs_rekey(&self) -> bool {
        let last_rekey = self.gen_bases.last().map(|(seq, _)| *seq).unwrap_or(0);
        self.next_seq.saturating_sub(last_rekey) > REKEY_TRIGGER_BYTES
    }

    /// Выпускает rekey-запись и переключает базу членов `K_record` на новое поколение
    /// (Q25, `02 §1`: `RecordType::Rekey` — это record, а не управление сеансом).
    ///
    /// Rekey-запись занимает очередной seq (тот же счётчик, что и данные — дедуп по
    /// `(sid, seq)` единого пространства) и шифруется ключом СТАРОГО поколения; её
    /// plaintext — `rekey_nonce` (свежая случайность вызывающего, `crypto_core::random_32`
    /// в прод-адаптере). ОБЕ стороны выводят из него одинаковое поколение:
    /// `K_session_gen = HKDF(sid, старая база ‖ rekey_nonce, LABEL_REKEY)` — ключи
    /// поколений по проводу не передаются, в открытом виде ходит только тип записи.
    /// Приёмник (`recv_record`) переключает базу ТОЛЬКО после аутентификации rekey-записи
    /// и коммита слота дедупа — подделанный REKEY поколение не меняет.
    ///
    /// In-flight окно (старый ключ жив для записей, уже выданных до rekey) решается
    /// детерминированным seq-сплитом (`base_for`) — без перебора ключей.
    pub fn begin_rekey(
        &mut self,
        stream: StreamId,
        rekey_nonce: &[u8; 32],
    ) -> Result<Record, RecordError> {
        if self.next_seq >= REKEY_POLICY_LIMIT {
            return Err(RecordError::TooFar);
        }
        self.seal_rekey(stream, rekey_nonce)
    }

    /// Перезапускает цепочку `K_record` от пост-ротационного `K_session'` (`02 §3.3`).
    ///
    /// `seq` при этом **не** сбрасывается: сессия не соединение (`§1`), новый узел получает
    /// продолжение нумерации через `continuity_point`. С F-02 «перезапуск» — просто смена
    /// базы вывода на `K_session'` (без шага-ноль HKDF: член с `info ‖ be64(seq)` уникален
    /// для каждой базы).
    ///
    /// Q25: ротация пере-keyивает ОБА направления (отправителя — сменой `chain_base`,
    /// приёмника — чисткой `gen_bases`): история порогов старого поколения после
    /// переключения базы вывода не имеет смысла, обе стороны симметрично начинают
    /// нумерацию поколений заново.
    pub fn ratchet_from(&mut self, k_session_prime: &[u8; 32]) {
        self.chain_base = *k_session_prime;
        self.gen_bases.clear();
        self.ratchet_restarts = self.ratchet_restarts.saturating_add(1);
    }

    /// Продолжает отправку по живому sid после рестарта владельца сессии (Q26/F-12).
    ///
    /// **Fail-closed на уровне API:** это единственный путь продолжить нумерацию отправителя,
    /// и он принимает счётчик **явно** — `next_seq` (следующий невыданный seq), сохранённый
    /// в session-store рядом с `K_session`. Продолжить живой sid «с нуля» нельзя: нумерация
    /// начнёт выдавать уже выданные seq, и повторный seal под тем же `(sid, seq)` при той же
    /// базе переиспользовал бы и `K_record[seq]`, и nonce `seq ‖ sid` — криптокатастрофу.
    /// Поэтому `next_seq = 0` отвергается assert'ом: сторона, не знающая своего счётчика,
    /// продолжает не сессию, а консервативную переоценку — новую сессию с новым sid
    /// (новые salt и база вывода ⇒ для любого seq и ключ, и nonce попарно различны; старые
    /// записи не попадают в новое окно — дедуп по `(sid, seq)`).
    ///
    /// `dedup_floor`/`resume_from` восстанавливают окно дедупа этой стороны так же, как на
    /// узле: пол из ticket и подписанный «выданный потолок» (см.
    /// `DedupWindow::restore_from_signed_last_seq`). Свежий узел, принявший RESUME из
    /// клиентского claim, остаётся валидным приёмником — консервативное правило касается
    /// только отправителя и его собственного счётчика (ротация и морф не ломаются).
    ///
    /// Поколения rekey при этом НЕ восстанавливаются (`gen_bases` пуст — ограничение
    /// Phase 0, см. `base_for`): in-flight записи старых поколений после рестарта
    /// дропаются; целостность и конфиденциальность не страдают.
    pub fn resume_as_sender(
        session_id: SessionId,
        k_session: [u8; 32],
        next_seq: u64,
        dedup_floor: Seq,
        resume_from: Seq,
        crypto: Box<dyn SessionCrypto>,
    ) -> Self {
        assert!(
            next_seq > 0,
            "продолжение живой сессии требует ненулевого счётчика отправителя: next_seq = 0 — потеря состояния, нужна новая сессия с новым sid (Q26/F-12)",
        );
        Self {
            session_id,
            chain_base: k_session,
            next_seq,
            gen_bases: Vec::new(),
            streams: Vec::new(),
            crypto,
            dedup: DedupWindow::restore_from_signed_last_seq(dedup_floor, resume_from),
            overlap: None,
            ack: None,
            nak: None,
            ratchet_restarts: 0,
        }
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
        /// Детерминированная одношаговая функция члена `seq`: XOR-смешение `seq` в ключ
        /// через повтор (мок проверяет каркас, не крипто — реальный вывод в `crypto-core`).
        fn record_key_at(&self, session_id: &[u8; 16], base: &[u8; 32], seq: u64) -> [u8; 32] {
            let mut out = [0u8; 32];
            let tag = seq.wrapping_mul(0x9E37_79B9_7F4A_7C15).to_be_bytes();
            for (index, byte) in base.iter().enumerate() {
                out[index] =
                    byte ^ session_id[index % session_id.len()] ^ tag[index % tag.len()] ^ 0x5a;
            }
            out
        }

        /// Ключ-чувствительный мок AEAD: 16-байтовый тег — свёртка ключа, nonce и AAD.
        /// Чувствительность к ключу нужна негативным тестам rekey (Q25): wrong-key
        /// открытие обязано отказывать, прежний префиксный мок ключ игнорировал.
        fn seal(&self, k: &[u8; 32], nonce: [u8; 24], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
            let mut out = aad.to_vec();
            out.extend_from_slice(plaintext);
            let tag = Self::mock_tag(k, nonce, aad, plaintext.len());
            out.extend_from_slice(&tag);
            out
        }

        fn open(
            &self,
            k: &[u8; 32],
            nonce: [u8; 24],
            aad: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, RecordError> {
            if ciphertext.len() < aad.len() + MOCK_TAG_LEN {
                return Err(RecordError::OpenFailed);
            }
            let (head, tag) = ciphertext.split_at(ciphertext.len() - MOCK_TAG_LEN);
            if !head.starts_with(aad) {
                return Err(RecordError::OpenFailed);
            }
            let plaintext = &head[aad.len()..];
            let expected = Self::mock_tag(k, nonce, aad, plaintext.len());
            let mut diff = 0u8;
            for (a, b) in tag.iter().zip(expected.iter()) {
                diff |= a ^ b;
            }
            if diff != 0 {
                return Err(RecordError::OpenFailed);
            }
            Ok(plaintext.to_vec())
        }

        /// Мок-вывод поколения rekey (Q25): отличим от `record_key_at` константой и
        /// отсутствием seq-тега — доменное разделение мока важно для негативных тестов.
        fn derive_rekey_generation(
            &self,
            session_id: &[u8; 16],
            base: &[u8; 32],
            rekey_nonce: &[u8; 32],
        ) -> [u8; 32] {
            let mut out = [0u8; 32];
            for (index, byte) in base.iter().enumerate() {
                out[index] = byte
                    ^ session_id[index % session_id.len()]
                    ^ rekey_nonce[index % rekey_nonce.len()]
                    ^ 0xa7;
            }
            out
        }
    }

    /// Длина тега мок-AEAD (16 B — как у Poly1305, чтобы размеры записи были правдоподобны).
    const MOCK_TAG_LEN: usize = 16;

    impl MockCrypto {
        /// Свёртка ключа/nonce/AAD/длины в тег: достаточна для каркасных тестов,
        /// реальная аутентификация — Poly1305 в `crypto-core`.
        fn mock_tag(k: &[u8; 32], nonce: [u8; 24], aad: &[u8], pt_len: usize) -> [u8; 16] {
            let mut tag = [0u8; 16];
            for (index, cell) in tag.iter_mut().enumerate() {
                let mut acc = k[index % k.len()]
                    ^ nonce[index % nonce.len()]
                    ^ pt_len.to_le_bytes()[index % 8]
                    ^ (index as u8);
                if let Some(a) = aad.get(index) {
                    acc ^= a;
                }
                *cell = acc;
            }
            tag
        }
    }

    /// Контракт record-слоя: запись кодируется в `type | seq | stream_id | flags | len |
    /// ciphertext`, nonce собирается как `seq(8B) || sid(16B)`, `seq` монотонен в пределах сессии.
    #[test]
    fn contract_record_layout_and_nonce() {
        let sid = SessionId([0x33; 16]);
        let mut session = Session::new(sid, [0x44; 32], Box::new(MockCrypto));
        let stream = session.open_stream(FlowId(7));
        assert_eq!(
            session.open_stream(FlowId(7)),
            stream,
            "поток не переоткрывается"
        );

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

        // Каноничность varint (аудит F-12): overlong-кодировка отклоняется. Поле `len`
        // со значением 5, закодированное двумя байтами (0x85, 0x00) вместо одного (0x05),
        // обязано быть BadLayout — иначе у одного значения два проводных вида. Для forging
        // строим кадр вручную: type | seq | stream_id | flags | len(overlong) | ciphertext.
        let mut forged = Vec::with_capacity(bytes.len() + 1);
        forged.extend_from_slice(&bytes[..4]); // type | seq(0) | stream_id | flags
        forged.extend_from_slice(&[0x85, 0x00]); // overlong-форма 5 вместо [0x05]
        forged.extend_from_slice(&record.ciphertext);
        assert_eq!(
            Record::decode(&forged),
            Err(RecordError::BadLayout),
            "overlong varint отвергается"
        );

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
        assert_eq!(
            fresh.continuity_point(),
            Seq(0),
            "повтор не двигает границу"
        );
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
        assert_eq!(
            fresh.window().lo,
            Seq(last.0 + 1 - u64::from(DUPLICATE_WINDOW_RECORDS))
        );
        assert_eq!(fresh.window().hi, last);
        assert_eq!(fresh.accept(Seq(5)), DedupOutcome::BelowWindow);
        assert_eq!(fresh.anomalies(), 1, "seq ниже пола считается аномалией");

        // Восстановление из подписанного last_seq (`§3.5`, строка «Потеря состояния»).
        let mut restored = DedupWindow::restore_from_signed_last_seq(Seq(0), Seq(10_000));
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
        assert_eq!(
            MAX_RESUME_ATTEMPTS, 2,
            "первая попытка + одна повторная (`02 §3.7`, Q18)"
        );
        assert_eq!(T_QUARANTINE_MS, 300_000, "T_quar = 5 мин (`02 §4`)");

        let mut window = OverlapWindow::new(500);
        assert_eq!(window.timeout_ms(), 1_000);
        assert_eq!(window.budget_records(), 4096);
        assert_eq!(window.duplicate(0), DuplicateStep::Duplicated);
        assert!(
            !window.close_on_ack(false),
            "невалидный ACK окно не закрывает"
        );
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

    /// F-02 (аудит 3): член `K_record[seq]` — ОДИН шаг HKDF для произвольного `seq`.
    /// Приём записи с огромным seq (2 млн > старый `CHAIN_ITERATION_LIMIT`) — те же
    /// микросекунды, что и для seq = 0: никакого O(seq)-вывода, никакого само-DoS,
    /// никакого жёсткого `TooFar` на не-политических seq.
    #[test]
    fn contract_record_key_is_constant_time_per_seq() {
        let sid = SessionId([0x71; 16]);
        let mut session = Session::new(sid, [0x72; 32], Box::new(MockCrypto));
        let stream = session.open_stream(FlowId(1));

        // Приёмник с пустым дедуп-окном принимает запись с seq = 2_000_000:
        // ключ выводится на месте одним шагом, AEAD открывается.
        let mut far_receiver = Session::new(sid, [0x72; 32], Box::new(MockCrypto));
        far_receiver.open_stream(FlowId(1));
        let far = far_receiver.seal_record(stream, b"far");
        assert_eq!(far.seq, Seq(0));

        // Отправитель досылает до seq = 2_000_000 за O(1) на запись (без цикла ratchet).
        let mut sender = Session::new(sid, [0x72; 32], Box::new(MockCrypto));
        sender.open_stream(FlowId(1));
        let first = sender.seal_record(stream, b"first");
        assert_eq!(first.seq, Seq(0));
        // Политический потолок REKEY_POLICY_LIMIT остаётся (Q25): seq за ним — TooFar.
        let far_record = Record {
            kind: RecordType::Data,
            stream_id: stream,
            flags: 0,
            seq: Seq(REKEY_POLICY_LIMIT + 1),
            ciphertext: Vec::new(),
        };
        assert_eq!(
            far_receiver.recv_record(&far_record),
            Err(RecordError::TooFar),
            "seq за политическим потолком отклоняется, но как Err, не как обрыв цепочки"
        );
    }

    /// F-02 (аудит 3): отказ вскрытия записи НЕ consume слот дедупа — окно не двигается,
    /// повторная попытка той же записи обрабатывается, поддельный поток кадров не выжигает
    /// дедуп-окно и не сдвигает пол (CPU-усилитель убран вместе с O(seq)-выводом).
    #[test]
    fn contract_open_failure_does_not_consume_dedup_slot() {
        let sid = SessionId([0x81; 16]);
        let mut sender = Session::new(sid, [0x82; 32], Box::new(MockCrypto));
        let stream = sender.open_stream(FlowId(1));
        let record = sender.seal_record(stream, b"payload");

        // Приёмник: та же база, но шифротекст повреждён → AEAD-open отказывает.
        let mut receiver = Session::new(sid, [0x82; 32], Box::new(MockCrypto));
        receiver.open_stream(FlowId(1));
        let mut tampered = record.clone();
        tampered.ciphertext[0] ^= 1;
        assert_eq!(
            receiver.recv_record(&tampered),
            Err(RecordError::OpenFailed),
            "испорченный шифротекст — вскрытие не проходит"
        );
        // Окно НЕ двигалось: запись всё ещё «новая», пол и hi на месте.
        assert_eq!(receiver.dedup().continuity_point(), Seq(0));
        assert_eq!(receiver.dedup().window().hi, Seq(0));

        // Подлинная запись принимается и окно коммитится; повтор — дубль.
        assert_eq!(
            receiver.recv_record(&record).expect("вскрытие"),
            Some(b"payload".to_vec())
        );
        assert_eq!(receiver.dedup().continuity_point(), Seq(0));
        assert_eq!(
            receiver.recv_record(&record),
            Ok(None),
            "повтор той же записи отброшен дедупом после коммита"
        );
    }

    /// Q26/F-12: инвариант восстановленного окна — пол тикета входит в окно,
    /// «выданный потолок» дедупится, продолжение за потолком принимается.
    #[test]
    fn contract_restore_window_floor_and_ceiling() {
        // Пол из ticket 9_500, подписанный клиентом потолок 10_000.
        let mut restored = DedupWindow::restore_from_signed_last_seq(Seq(9_500), Seq(10_000));
        assert_eq!(
            restored.window(),
            DuplicateWindow { lo: Seq(9_500), hi: Seq(10_000) },
            "window_lo = max(пол из ticket, last_seq − 4096): пол выше слайда задаёт нижнюю границу",
        );
        assert_eq!(
            restored.accept(Seq(9_499)),
            DedupOutcome::BelowWindow,
            "seq ниже пола тикета — аномалия (§3.7), а не приём",
        );
        assert_eq!(restored.anomalies(), 1);
        assert_eq!(
            restored.accept(Seq(9_800)),
            DedupOutcome::Duplicate,
            "всё ≤ выданного потолка дедупится: зазор до факта приёма не переоткрывается",
        );
        assert_eq!(
            restored.accept(Seq(10_001)),
            DedupOutcome::Accepted,
            "продолжение нумерации — строго выше выданного потолка",
        );
        assert_eq!(
            restored.continuity_point(),
            Seq(10_001),
            "continuity_point двигает только запись за потолком",
        );

        // Пол 0: окно от слайда last_seq − 4096 (§3.5).
        let far = DedupWindow::restore_from_signed_last_seq(Seq(0), Seq(50_000));
        assert_eq!(
            far.window().lo,
            Seq(50_000 + 1 - u64::from(DUPLICATE_WINDOW_RECORDS)),
            "пол 0 ниже слайда: window_lo = last_seq − 4096",
        );
    }

    /// Q26/F-12: fail-closed отправителя — продолжение живой сессии требует явного
    /// ненулевого счётчика; нулевой (потеря состояния) отвергается на уровне API.
    #[test]
    #[should_panic(expected = "продолжение живой сессии требует ненулевого счётчика")]
    fn contract_resume_sender_rejects_zero_counter() {
        Session::resume_as_sender(
            SessionId([0x77; 16]),
            [0x78; 32],
            0,
            Seq(0),
            Seq(0),
            Box::new(MockCrypto),
        );
    }

    /// Q26/F-12: продолжение с сохранённым счётчиком выдаёт seq строго выше подписанного
    /// потолка; окно дедупа стороны восстановлено с полом тикета и потолком.
    #[test]
    fn contract_resume_sender_continues_numbering_above_ceiling() {
        // Отправитель выдал seq 0..=5000 (потолок 5000), сохранил next_seq = 5001 рядом
        // с K_session, рестарт: продолжение — только с явным счётчиком.
        let mut resumed = Session::resume_as_sender(
            SessionId([0x79; 16]),
            [0x7a; 32],
            5_001,
            Seq(1_000),
            Seq(5_000),
            Box::new(MockCrypto),
        );
        let stream = resumed.open_stream(FlowId(1));
        let record = resumed.seal_record(stream, b"after restart");
        assert_eq!(
            record.seq,
            Seq(5_001),
            "первый seq после рестарта — сохранённый счётчик, не ноль и не потолок",
        );
        assert_eq!(resumed.last_seq(), Seq(5_001));

        // Приёмная сторона с тем же восстановленным окном (пол 1000, потолок 5000):
        // ниже пола — аномалия, внутри окна — дубль, за потолком — новая запись.
        let mut dedup = DedupWindow::restore_from_signed_last_seq(Seq(1_000), Seq(5_000));
        assert_eq!(dedup.accept(Seq(999)), DedupOutcome::BelowWindow);
        assert_eq!(dedup.accept(Seq(2_000)), DedupOutcome::Duplicate);
        assert_eq!(dedup.accept(Seq(5_001)), DedupOutcome::Accepted);
    }

    /// Q25: политика триггера — раз в `REKEY_TRIGGER_BYTES` (¾ потолка) на поколение;
    /// выпуск rekey — явный (`begin_rekey`), авто-магии в data-пути нет; счётчик,
    /// потоки и непрерывность `seq` не сбрасываются; ротация (`ratchet_from`)
    /// пере-keyивает оба направления и чистит историю порогов приёма.
    #[test]
    fn contract_rekey_trigger_policy_and_explicit_begin() {
        assert_eq!(
            REKEY_TRIGGER_BYTES,
            REKEY_POLICY_LIMIT / 4 * 3,
            "порог = ¾ потолка: смена поколения происходит до лимита, не на нём",
        );
        // Счётчик восстановлен (Q26) на значение порога: до порога смена не назрела.
        let mut sender = Session::resume_as_sender(
            SessionId([0x5b; 16]),
            [0x5c; 32],
            REKEY_TRIGGER_BYTES,
            Seq(0),
            Seq(REKEY_TRIGGER_BYTES - 1),
            Box::new(MockCrypto),
        );
        assert!(
            !sender.needs_rekey(),
            "ровно на пороге смена ещё не назрела"
        );
        let stream = sender.open_stream(FlowId(1));
        let data = sender.seal_record(stream, b"at the threshold");
        assert_eq!(data.seq, Seq(REKEY_TRIGGER_BYTES), "seq не сбрасывается");
        assert!(
            sender.needs_rekey(),
            "первая запись за порогом назревает rekey",
        );

        // Явный выпуск: rekey-запись занимает очередной seq (тот же счётчик, что данные).
        let rekey = sender
            .begin_rekey(stream, &[0x9e; 32])
            .expect("rekey внутри потолка разрешён");
        assert_eq!(rekey.kind, RecordType::Rekey);
        assert_eq!(rekey.seq, Seq(REKEY_TRIGGER_BYTES + 1));
        assert_eq!(sender.rekey_generations(), 1);

        // После rekey окно политики начинается заново; цепочка rekey разрешена:
        // вторая rekey-запись шифруется уже базой первого поколения.
        assert!(
            !sender.needs_rekey(),
            "после rekey окно политики начинается заново",
        );
        let rekey2 = sender
            .begin_rekey(stream, &[0x11; 32])
            .expect("цепочка rekey разрешена");
        assert_eq!(rekey2.seq, Seq(REKEY_TRIGGER_BYTES + 2));
        assert_eq!(sender.rekey_generations(), 2);

        // Потоки и непрерывность нумерации переживают смену поколения.
        let after = sender.seal_record(stream, b"generation two");
        assert_eq!(after.seq, Seq(REKEY_TRIGGER_BYTES + 3));
        assert_eq!(sender.stream_table(), &[(FlowId(1), stream)]);

        // Ротация: база меняется на K_session', история порогов приёма чистится —
        // пост-ротационная сторона получает непрерывный seq на новой базе.
        sender.ratchet_from(&[0xdd; 32]);
        assert_eq!(sender.rekey_generations(), 0);
        let post_rotation = sender.seal_record(stream, b"post rotation");
        assert_eq!(post_rotation.seq, Seq(REKEY_TRIGGER_BYTES + 4));
    }

    /// Q25: живой roundtrip смены поколения — in-flight записи старого поколения
    /// вскрываются и после rekey (окно по seq-сплиту), новые — новым ключом;
    /// приёмник БЕЗ обработки rekey вскрывать новое поколение не может (старый
    /// `K_record` не переиспользуется); подделанный REKEY не переключает базу и
    /// не consume слот дедупа.
    #[test]
    fn contract_rekey_roundtrip_in_flight_and_old_key_rejected() {
        let sid = SessionId([0x6b; 16]);
        let k = [0x6c; 32];
        let mut sender = Session::new(sid, k, Box::new(MockCrypto));
        let stream = sender.open_stream(FlowId(1));

        let mut pre = Vec::new();
        for i in 0..3 {
            pre.push(sender.seal_record(stream, format!("pre-{i}").as_bytes()));
        }
        let rekey = sender
            .begin_rekey(stream, &[0x9e; 32])
            .expect("rekey внутри потолка");
        let mut post = Vec::new();
        for i in 0..3 {
            post.push(sender.seal_record(stream, format!("post-{i}").as_bytes()));
        }
        assert_eq!(rekey.seq, Seq(3));
        assert_eq!(post[0].seq, Seq(4));

        // Приёмник: rekey приходит ПЕРВЫМ, потом — in-flight старого поколения,
        // вперемешку с новым; всё вскрывается (интерливинг — реальный порядок сети).
        let mut receiver = Session::new(sid, k, Box::new(MockCrypto));
        receiver.open_stream(FlowId(1));
        assert_eq!(
            receiver.recv_record(&rekey).expect("rekey вскрывается"),
            None,
            "rekey — управление ключами, приложению не доставляется",
        );
        assert_eq!(receiver.rekey_generations(), 1);
        for (index, record) in pre.iter().enumerate() {
            assert_eq!(
                receiver
                    .recv_record(record)
                    .expect("in-flight старое поколение"),
                Some(format!("pre-{index}").into_bytes()),
                "запись за rekey-порогом вскрывается СТАРОЙ базой (seq-сплит)",
            );
        }
        for (index, record) in post.iter().enumerate() {
            assert_eq!(
                receiver.recv_record(record).expect("новое поколение"),
                Some(format!("post-{index}").into_bytes()),
                "запись за rekey-порогом вскрывается НОВОЙ базой",
            );
        }

        // Повтор rekey-записи — дедуп: второе переключение поколения не происходит.
        assert_eq!(receiver.recv_record(&rekey), Ok(None), "повтор — дубль");
        assert_eq!(receiver.rekey_generations(), 1);

        // Негатив: приёмник без rekey не вскрывает новое поколение — старый
        // K_record для тех же (sid, seq) не подходит.
        let mut stale = Session::new(sid, k, Box::new(MockCrypto));
        stale.open_stream(FlowId(1));
        assert_eq!(
            stale.recv_record(&post[0]),
            Err(RecordError::OpenFailed),
            "старый K_record не переиспользуется: пост-rekey запись не вскрывается",
        );

        // Подделанный REKEY: вскрытие отказывает, база не переключается, слот дедупа
        // не consumed (настоящая запись того же seq принимается заново — F-02).
        let mut forged = rekey.clone();
        forged.ciphertext[0] ^= 1;
        let mut target = Session::new(sid, k, Box::new(MockCrypto));
        target.open_stream(FlowId(1));
        assert_eq!(
            target.recv_record(&forged),
            Err(RecordError::OpenFailed),
            "подделанный REKEY отброшен AEAD",
        );
        assert_eq!(
            target.rekey_generations(),
            0,
            "неаутентифицированный rekey не переключает базу",
        );
        assert_eq!(
            target.dedup().continuity_point(),
            Seq(0),
            "слот не consumed"
        );
        assert_eq!(
            target.recv_record(&rekey).expect("настоящий rekey"),
            None,
            "после отказа тот же seq принимается заново (F-02)",
        );
        assert_eq!(target.rekey_generations(), 1);
    }
}
