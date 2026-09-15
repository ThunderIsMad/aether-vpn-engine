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
//! Record = type(1B) | stream_id(varint) | flags(1B) | len(varint) | ciphertext
//! ciphertext = XChaCha20-Poly1305(K_record, nonce = seq(8B) || sid(16B), plaintext)
//! ```
//!
//! Сессия — это НЕ транспортное соединение: таблица потоков + ключи + счётчики, живущие
//! на клиенте и восстановимые на узле из ticket. Реализация — Phase 0; до неё здесь
//! объявлен только контракт, под который пишутся юнит- и интеграционные тесты.

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

/// Зашифрованная запись: `type | stream_id | flags | len | ciphertext`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Тип записи.
    pub kind: RecordType,
    /// Поток, которому принадлежит запись.
    pub stream_id: StreamId,
    /// Флаги (FIN-семантика прикладного потока — `02 §1`).
    pub flags: u8,
    /// XChaCha20-Poly1305 шифротекст; nonce = `seq || sid` (24 B, см. `crypto-core`).
    pub ciphertext: Vec<u8>,
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

/// Ветки `RESUME_NAK` (`02 §3.7`) — ровно четыре, без расширения.
///
/// `02 §3.7` называет их `bad_pop` / `replay` / `epoch` / `expired`; форма Rust-типа —
/// решение Phase 0 по объёму ACK/NAK (`QUESTIONS.md` Q3), состав веток — из спеки.
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
    ///
    /// `sig_node` в подписи не «на всякий случай»: проверка подписи узла — часть контракта,
    /// без неё фикс свежего DH не работает (скомпрометированный N1 подсунул бы свой `eph_node`).
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

#[cfg(test)]
mod tests {
    /// Контракт record-слоя: запись кодируется в `type | stream_id | flags | len | ciphertext`,
    /// nonce собирается как `seq(8B) || sid(16B)`, `seq` монотонен в пределах сессии.
    #[test]
    #[ignore = "контракт Phase 0: тело намеренно todo!() — тест начнёт проходить вместе с реализацией"]
    fn contract_record_layout_and_nonce() {
        todo!("Phase 0: Record layout + nonce seq||sid (02 §1)")
    }

    /// Контракт дедупа: окно 4096 записей, `seq < window_lo` → drop,
    /// повтор внутри окна → drop без сдвига `continuity_point`; восстановление окна
    /// из подписанного клиентом `last_seq` после рестарта узла.
    #[test]
    #[ignore = "контракт Phase 0: тело намеренно todo!() — тест начнёт проходить вместе с реализацией"]
    fn contract_dedup_window_boundaries() {
        todo!("Phase 0: dedup по (sid, seq) — окно 4096, границы и восстановление (02 §3.5)")
    }
}
