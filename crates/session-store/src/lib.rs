//! `session-store` — клиентское хранилище состояния сессии (`03-components.md` §7)
//! и **владелец клиентских ключей личности**.
//!
//! **In/State:** `(subscription_id, uuid, session_id)`, `K_session`, tickets, chain descriptor,
//! `client_identity` (Ed25519 priv — подпись `RESUME`), `client_static` (X25519 priv —
//! статик инициатора в Noise_IK).
//! **Out:** сессия, готовая к резюму; ticket для `key-coordinator`.
//! **Deps:** нет (OS secure store подключается на платформенном уровне).
//!
//! **At-rest:** `client_identity`, `client_static` и `K_session` — в OS secure store
//! (keyring / DPAPI / Keychain / libsecret); tickets — только in-memory. У сервера
//! состояния, переживающего ротацию, нет (на время сессии узел держит in-memory окно
//! дедупликации).
//!
//! ## Что реализовано в Phase 0 и какие решения тут приняты
//!
//! 1. **Форма приватных ключей зафиксирована** (в скаффолде они были намеренно не объявлены):
//!    `client_identity` — seed Ed25519 (32 B), `client_static` — приватный скаляр X25519 (32 B).
//!    Оба живут в `ClientSecrets`, поля приватные, `Debug` напечатан как `<redacted>`:
//!    ключ, который можно случайно вывести в лог, — это ключ, который утечёт.
//! 2. **Backend абстрагирован трейтом `SecureStore`.** В Phase 0 реализован только
//!    in-memory backend: OS-хранилища (keyring/DPAPI/Keychain/libsecret) — это отдельная
//!    платформенная работа Phase 1, и выдавать её за сделанную нельзя. Тесты проверяют
//!    **политику** (что именно уходит в backend, что остаётся в памяти, что стирает `wipe`),
//!    а не конкретное OS-хранилище.
//! 3. **Дескриптор сессии персистится рядом с секретами** (`KEY_DESCRIPTOR`): без него
//!    `load` после рестарта процесса нечего было бы вернуть, кроме секретов. Дескриптор
//!    не секрет, но лежит в том же хранилище — это осознанный выбор в пользу того, чтобы
//!    сессия восстанавливалась целиком, а не наполовину.
//! 4. **Tickets не касаются backend'а вообще.** Политика `03 §7` («tickets — только
//!    in-memory») проверяется тестом: ни одного вхождения байтов ticket в значениях backend.
//! 5. **`zeroize` не подключён.** Честно: вычищать скаляры из памяти на drop — hardening,
//!    который требует крейта; в скаффолде он был назван условием реализации, и здесь
//!    отложен вместе с платформенным backend'ом (`QUESTIONS.md`, Phase 1 hardening).
//! 6. **Debug секретов — ручной redacted, сырые значения — только в тестах.** `SessionState`
//!    и `InMemorySecureStore` печатают `<redacted>` вместо `k_session`/ключей; выгрузка всех
//!    значений backend'а (`values`) и доступ к самому backend'у (`ClientSessionStore::backend`)
//!    гейтятся `#[cfg(test)]` — прод-код не умеет одной строкой скопировать весь набор секретов
//!    (закрытие аудита F-SEC).
//! 7. **Счётчик отправителя персистится в дескрипторе** (Q26/F-12): `SessionState.next_seq`
//!    (следующий невыданный seq) лежит рядом с `K_session`; продолжение живого sid после
//!    рестарта возможно только с явным счётчиком (`frame_session::Session::resume_as_sender`),
//!    продолжить «с нуля» нельзя — инвариант против отката нумерации и переиспользования
//!    `K_record[seq]`/nonce. Каденция записи фиксируется уже сейчас: Phase 0 (in-memory
//!    backend) — sync-запись на каждый `seal_record` бесплатна; правило Phase 1 (OS store) —
//!    sync-запись на каждый seal, краш между seal и записью = счётчик мог откатиться =
//!    новая сессия, не resume.

#![deny(unsafe_code)]

use std::collections::HashMap;
use std::fmt;

/// Идентификатор подписки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionId(pub String);

/// Клиентские ключи личности — единственная копия в системе (`03` §7).
///
/// Поля приватные, конструктор один: собрать `ClientSecrets` мимо `session-store` нельзя,
/// а значит нельзя и завести вторую копию `client_identity`, которой подписывается `RESUME`.
/// Без `PartialEq` (аудит F-12): `==` на секретах — branch-on-secret; без `Copy` —
/// неявное размножение секретных копий (клонирование — осознанный вызов).
#[derive(Clone)]
pub struct ClientSecrets {
    client_identity: [u8; 32],
    client_static: [u8; 32],
}

impl ClientSecrets {
    /// Собирает пару: seed Ed25519 (подпись `RESUME`) и приватный скаляр X25519 (Noise_IK).
    pub fn new(client_identity: [u8; 32], client_static: [u8; 32]) -> Self {
        Self {
            client_identity,
            client_static,
        }
    }

    /// Seed Ed25519 для `sig_client` (`02 §3.3`).
    pub fn identity(&self) -> &[u8; 32] {
        &self.client_identity
    }

    /// Приватный `client_static` для Noise_IK (`02 §5`).
    pub fn statics(&self) -> &[u8; 32] {
        &self.client_static
    }
}

impl fmt::Debug for ClientSecrets {
    /// Ровно то, что можно печатать: длина, не байты.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientSecrets")
            .field("client_identity", &"<redacted>")
            .field("client_static", &"<redacted>")
            .finish()
    }
}

/// Состояние сессии на клиенте (`03-components.md` §7).
///
/// Debug — ручной redacted, не derive: `k_session` и `secrets` печатаются как `<redacted>`,
/// не байтами. Дамп `SessionState` целиком (панель отладчика, лог упавшего теста,
/// `debug!`) обязан быть безопасным (аудит F-SEC). Без `PartialEq` — содержит секреты
/// (аудит F-12).
#[derive(Clone)]
pub struct SessionState {
    /// Подписка, в рамках которой живёт сессия.
    pub subscription_id: SubscriptionId,
    /// UUID устройства/клиента в подписке.
    pub uuid: [u8; 16],
    /// Идентификатор сессии (`sid`).
    pub session_id: [u8; 16],
    /// Мастер-ключ сессии (в at-rest — только через OS secure store).
    pub k_session: [u8; 32],
    /// Счётчик отправителя сессии (Q26/F-12): следующий невыданный `seq`. Персистится в
    /// дескрипторе рядом с `K_session`; sync-запись на каждый `seal_record` (Phase 0 —
    /// in-memory backend; правило Phase 1 — sync, краш между seal и записью = новая
    /// сессия, не resume). Откат запрещён: продолжение живого sid — только через
    /// `frame_session::Session::resume_as_sender` с этим явным счётчиком.
    pub next_seq: u64,
    /// Tickets, выданные узлами (только in-memory).
    pub tickets: Vec<Vec<u8>>,
    /// Chain descriptor для Federated Egress Mesh (Phase 3, `02 §3.4`).
    pub chain: Vec<[u8; 16]>,
    /// Ключи личности — принадлежат этому модулю.
    pub secrets: ClientSecrets,
}

impl fmt::Debug for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionState")
            .field("subscription_id", &self.subscription_id)
            .field("uuid", &"<redacted>")
            .field("session_id", &"<redacted>")
            .field("k_session", &"<redacted>")
            .field("next_seq", &self.next_seq)
            .field("tickets", &self.tickets.len())
            .field("chain", &self.chain.len())
            .field("secrets", &"<redacted>")
            .finish()
    }
}

/// Ошибка хранилища.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// OS secure store недоступен (нет keyring/DPAPI и т. п.).
    Unavailable,
    /// Запись повреждена или расшифровка не прошла.
    Corrupt,
    /// Доступ запрещён пользователем/политикой ОС.
    Denied,
}

/// Ключ OS secure store: seed Ed25519 (`client_identity`).
pub const KEY_CLIENT_IDENTITY: &str = "aether/client_identity";
/// Ключ OS secure store: приватный скаляр X25519 (`client_static`).
pub const KEY_CLIENT_STATIC: &str = "aether/client_static";
/// Ключ OS secure store: `K_session`.
pub const KEY_K_SESSION: &str = "aether/k_session";
/// Ключ OS secure store: дескриптор сессии (не секрет, но нужен, чтобы `load` был полным).
pub const KEY_DESCRIPTOR: &str = "aether/session_descriptor";

/// Секреты, которые обязаны лежать в OS secure store (`03` §7).
pub const SECRET_KEYS: [&str; 3] = [KEY_CLIENT_IDENTITY, KEY_CLIENT_STATIC, KEY_K_SESSION];

/// Backend защищённого хранилища. Платформенные реализации — Phase 1
/// (keyring / DPAPI / Keychain / libsecret); в Phase 0 есть эталонная in-memory.
pub trait SecureStore {
    /// Кладёт запись.
    fn put(&mut self, key: &str, value: &[u8]) -> Result<(), StoreError>;
    /// Читает запись.
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError>;
    /// Удаляет запись (отсутствие — не ошибка).
    fn delete(&mut self, key: &str) -> Result<(), StoreError>;
}

/// Эталонный in-memory backend: он не защищён и не персистентен — тесты проверяют
/// **политику** хранения, а не свойства OS-хранилища.
///
/// Debug — ручной redacted, не derive: значения backend'а — это сами секреты
/// (`client_identity`, `client_static`, `K_session`), и `{:?}` над хранилищем не имеет
/// права их печатать (аудит F-SEC). Без `PartialEq` — содержит секреты (аудит F-12);
/// `Default` остаётся: пустое хранилище — валидное начальное состояние.
#[derive(Clone, Default)]
pub struct InMemorySecureStore {
    map: HashMap<String, Vec<u8>>,
}

impl fmt::Debug for InMemorySecureStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InMemorySecureStore")
            .field("keys", &self.map.keys().collect::<Vec<_>>())
            .field("values", &"<redacted>")
            .finish()
    }
}

impl InMemorySecureStore {
    /// Пустое хранилище.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ключи, которые сейчас лежат в backend'е.
    pub fn keys(&self) -> Vec<&str> {
        let mut keys: Vec<&str> = self.map.keys().map(String::as_str).collect();
        keys.sort_unstable();
        keys
    }

    /// Все значения, лежащие в backend'е: это **секреты в открытом виде**. Метод
    /// существует только для тестов политики хранения — прод-код не должен уметь
    /// скопировать весь набор ключей одной строкой (аудит F-SEC).
    #[cfg(test)]
    pub fn values(&self) -> Vec<&[u8]> {
        self.map.values().map(Vec::as_slice).collect()
    }

    /// Ключ существует.
    pub fn has(&self, key: &str) -> bool {
        self.map.contains_key(key)
    }
}

impl SecureStore for InMemorySecureStore {
    fn put(&mut self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        self.map.insert(key.to_string(), value.to_vec());
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.map.get(key).cloned())
    }

    fn delete(&mut self, key: &str) -> Result<(), StoreError> {
        self.map.remove(key);
        Ok(())
    }
}

/// ЧЕРНОВОЙ контракт: в `03-components.md` трейта нет — форма зафиксирована здесь.
/// Хранилище одно на клиента, сессия — одна активная.
pub trait SessionStore {
    /// Загружает сохранённую сессию, если она есть.
    fn load(&self) -> Result<Option<SessionState>, StoreError>;
    /// Сохраняет состояние сессии.
    fn save(&mut self, state: &SessionState) -> Result<(), StoreError>;
    /// Стирает состояние (logout / отзыв клиента через манифест).
    fn wipe(&mut self) -> Result<(), StoreError>;
}

/// Клиентское хранилище: секреты — в backend, tickets — только в памяти.
pub struct ClientSessionStore<S: SecureStore> {
    backend: S,
    state: Option<SessionState>,
    tickets: Vec<Vec<u8>>,
}

impl<S: SecureStore> ClientSessionStore<S> {
    /// Хранилище поверх backend'а (в Phase 0 — `InMemorySecureStore`).
    pub fn new(backend: S) -> Self {
        Self {
            backend,
            state: None,
            tickets: Vec::new(),
        }
    }

    /// Backend на чтение — **только тесты**: отдаёт необработанный backend, чей `get`
    /// вынимает секреты в открытом виде (аудит F-SEC). Прод-диагностике достаточно
    /// `keys()`/`state()`/`tickets()`/`secrets()`.
    #[cfg(test)]
    pub fn backend(&self) -> &S {
        &self.backend
    }

    /// Активная сессия, если она есть.
    pub fn state(&self) -> Option<&SessionState> {
        self.state.as_ref()
    }

    /// Tickets текущей сессии — только in-memory (`03` §7).
    pub fn tickets(&self) -> &[Vec<u8>] {
        &self.tickets
    }

    /// Кладёт ticket, выданный узлом: он живёт в памяти и в backend не уходит.
    pub fn store_ticket(&mut self, ticket: Vec<u8>) {
        self.tickets.push(ticket);
    }

    /// Единственный доступ к ключам личности: их владелец — этот модуль (`03` §7).
    pub fn secrets(&self) -> Option<&ClientSecrets> {
        self.state.as_ref().map(|state| &state.secrets)
    }
}

/// Дескриптор сессии: `subscription_len(2) ‖ subscription ‖ uuid(16) ‖ sid(16) ‖ chain_n(2) ‖ chain`.
fn encode_descriptor(state: &SessionState) -> Result<Vec<u8>, StoreError> {
    if state.subscription_id.0.len() > u16::MAX as usize || state.chain.len() > u16::MAX as usize {
        return Err(StoreError::Corrupt);
    }
    let mut out =
        Vec::with_capacity(2 + state.subscription_id.0.len() + 34 + state.chain.len() * 16);
    out.extend_from_slice(&(state.subscription_id.0.len() as u16).to_be_bytes());
    out.extend_from_slice(state.subscription_id.0.as_bytes());
    out.extend_from_slice(&state.uuid);
    out.extend_from_slice(&state.session_id);
    out.extend_from_slice(&(state.chain.len() as u16).to_be_bytes());
    for hop in &state.chain {
        out.extend_from_slice(hop);
    }
    out.extend_from_slice(&state.next_seq.to_be_bytes());
    Ok(out)
}

/// Читает кусок байт и сдвигает курсор; нехватка байт — `Corrupt`.
fn take_slice<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8], StoreError> {
    let end = cursor.checked_add(len).ok_or(StoreError::Corrupt)?;
    let slice = bytes.get(*cursor..end).ok_or(StoreError::Corrupt)?;
    *cursor = end;
    Ok(slice)
}

/// Читает массив фиксированной длины — ноль магии: длина входа проверяется `try_into`.
fn take_arr<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], StoreError> {
    take_slice(bytes, cursor, N)?
        .try_into()
        .map_err(|_| StoreError::Corrupt)
}

/// Секрет из хранилища: отсутствие — `Corrupt` (это не «сессия без ключа»), неверная длина — тоже.
fn secret32(value: Option<Vec<u8>>) -> Result<[u8; 32], StoreError> {
    let bytes = value.ok_or(StoreError::Corrupt)?;
    bytes.try_into().map_err(|_| StoreError::Corrupt)
}

/// Несекретная часть сессии — то, что лежит в хранилище рядом с секретами, чтобы `load`
/// поднимал сессию целиком, а не наполовину.
struct SessionDescriptor {
    subscription_id: SubscriptionId,
    uuid: [u8; 16],
    session_id: [u8; 16],
    chain: Vec<[u8; 16]>,
    /// Счётчик отправителя (Q26/F-12) — следующий невыданный `seq`.
    next_seq: u64,
}

/// Обратный разбор дескриптора. Обрезанный или неверный вход — `Corrupt`.
fn decode_descriptor(bytes: &[u8]) -> Result<SessionDescriptor, StoreError> {
    let mut cursor = 0usize;
    let name_len = u16::from_be_bytes(take_arr::<2>(bytes, &mut cursor)?) as usize;
    let name = String::from_utf8(take_slice(bytes, &mut cursor, name_len)?.to_vec())
        .map_err(|_| StoreError::Corrupt)?;
    let uuid = take_arr::<16>(bytes, &mut cursor)?;
    let session_id = take_arr::<16>(bytes, &mut cursor)?;
    let chain_len = u16::from_be_bytes(take_arr::<2>(bytes, &mut cursor)?) as usize;
    let mut chain = Vec::with_capacity(chain_len);
    for _ in 0..chain_len {
        chain.push(take_arr::<16>(bytes, &mut cursor)?);
    }
    let next_seq = u64::from_be_bytes(take_arr::<8>(bytes, &mut cursor)?);
    if cursor != bytes.len() {
        return Err(StoreError::Corrupt);
    }
    Ok(SessionDescriptor {
        subscription_id: SubscriptionId(name),
        uuid,
        session_id,
        chain,
        next_seq,
    })
}

impl<S: SecureStore> SessionStore for ClientSessionStore<S> {
    fn load(&self) -> Result<Option<SessionState>, StoreError> {
        let descriptor = self.backend.get(KEY_DESCRIPTOR)?;
        let identity = self.backend.get(KEY_CLIENT_IDENTITY)?;
        let statics = self.backend.get(KEY_CLIENT_STATIC)?;
        let k_session = self.backend.get(KEY_K_SESSION)?;
        if descriptor.is_none() && identity.is_none() && statics.is_none() && k_session.is_none() {
            return Ok(None);
        }
        // Часть секретов без остальных — не «сессия без ключа», а повреждённое хранилище:
        // молча продолжить здесь значит работать без `client_identity` (то есть без PoP).
        let descriptor = decode_descriptor(&descriptor.ok_or(StoreError::Corrupt)?)?;
        Ok(Some(SessionState {
            subscription_id: descriptor.subscription_id,
            uuid: descriptor.uuid,
            session_id: descriptor.session_id,
            k_session: secret32(k_session)?,
            next_seq: descriptor.next_seq,
            tickets: Vec::new(),
            chain: descriptor.chain,
            secrets: ClientSecrets::new(secret32(identity)?, secret32(statics)?),
        }))
    }

    fn save(&mut self, state: &SessionState) -> Result<(), StoreError> {
        let descriptor = encode_descriptor(state)?;
        self.backend
            .put(KEY_CLIENT_IDENTITY, state.secrets.identity())?;
        self.backend
            .put(KEY_CLIENT_STATIC, state.secrets.statics())?;
        self.backend.put(KEY_K_SESSION, &state.k_session)?;
        self.backend.put(KEY_DESCRIPTOR, &descriptor)?;
        // Tickets остаются в памяти: `03` §7 прямо запрещает им переживать процесс.
        self.tickets = state.tickets.clone();
        self.state = Some(SessionState {
            tickets: self.tickets.clone(),
            ..state.clone()
        });
        Ok(())
    }

    fn wipe(&mut self) -> Result<(), StoreError> {
        for key in SECRET_KEYS {
            self.backend.delete(key)?;
        }
        self.backend.delete(KEY_DESCRIPTOR)?;
        self.tickets.clear();
        self.state = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDENTITY: [u8; 32] = [0xa1; 32];
    const STATIC: [u8; 32] = [0xb2; 32];
    const K_SESSION: [u8; 32] = [0xc3; 32];

    fn state() -> SessionState {
        SessionState {
            subscription_id: SubscriptionId("sub-42".to_string()),
            uuid: [0x11; 16],
            session_id: [0x22; 16],
            k_session: K_SESSION,
            next_seq: 7,
            tickets: vec![vec![0xd4; 161]],
            chain: vec![[0x33; 16], [0x44; 16]],
            secrets: ClientSecrets::new(IDENTITY, STATIC),
        }
    }

    /// Контракт хранилища: `K_session` и обе приватные пары личности лежат в OS secure
    /// store, tickets — только в памяти; после `wipe` не остаётся ни одного секрета.
    #[test]
    fn contract_secrets_at_rest_and_wipe() {
        let mut store = ClientSessionStore::new(InMemorySecureStore::new());
        assert!(
            matches!(store.load(), Ok(None)),
            "пустое хранилище — сессии нет"
        );

        store.store_ticket(vec![0xd4; 161]);
        store.save(&state()).expect("сохранение");

        // Что уходит в backend: ровно три секрета + дескриптор.
        assert_eq!(
            store.backend().keys(),
            vec![
                KEY_CLIENT_IDENTITY,
                KEY_CLIENT_STATIC,
                KEY_K_SESSION,
                KEY_DESCRIPTOR
            ]
        );
        assert_eq!(
            store.backend().get(KEY_CLIENT_IDENTITY),
            Ok(Some(IDENTITY.to_vec()))
        );
        assert_eq!(
            store.backend().get(KEY_CLIENT_STATIC),
            Ok(Some(STATIC.to_vec()))
        );
        assert_eq!(
            store.backend().get(KEY_K_SESSION),
            Ok(Some(K_SESSION.to_vec()))
        );

        // Tickets в secure store не попадают вообще (`03` §7).
        let ticket_bytes = vec![0xd4u8; 161];
        assert!(
            !store.backend().values().contains(&ticket_bytes.as_slice()),
            "ticket не лежит в at-rest хранилище"
        );
        assert_eq!(store.tickets(), &[vec![0xd4u8; 161]]);

        // Загрузка возвращает и дескриптор, и секреты, но не tickets.
        let loaded = store
            .load()
            .expect("хранилище читается")
            .expect("сессия есть");
        assert_eq!(loaded.subscription_id, SubscriptionId("sub-42".to_string()));
        assert_eq!(loaded.uuid, [0x11; 16]);
        assert_eq!(loaded.session_id, [0x22; 16]);
        assert_eq!(loaded.k_session, K_SESSION);
        assert_eq!(
            loaded.next_seq, 7,
            "счётчик отправителя переживает хранилище рядом с K_session (Q26/F-12)"
        );
        assert_eq!(loaded.chain, vec![[0x33; 16], [0x44; 16]]);
        assert_eq!(loaded.secrets.identity(), &IDENTITY);
        assert_eq!(loaded.secrets.statics(), &STATIC);
        assert!(
            loaded.tickets.is_empty(),
            "tickets resumption-процесса — не из диска"
        );

        // Секреты, вынутые из backend'а по одному, — `Corrupt`, а не сессия без PoP.
        let mut broken = ClientSessionStore::new(store.backend().clone());
        broken.backend.delete(KEY_CLIENT_IDENTITY).expect("delete");
        assert!(matches!(broken.load(), Err(StoreError::Corrupt)));
        let mut half = ClientSessionStore::new(store.backend().clone());
        half.backend.delete(KEY_DESCRIPTOR).expect("delete");
        assert!(matches!(half.load(), Err(StoreError::Corrupt)));

        // `wipe` не оставляет ни секретов, ни дескриптора, ни tickets.
        store.wipe().expect("wipe");
        assert!(store.backend().keys().is_empty());
        assert!(store.tickets().is_empty());
        assert!(store.state().is_none());
        assert!(matches!(store.load(), Ok(None)), "после wipe сессии нет");
        assert!(store.secrets().is_none(), "и ключей личности тоже");
    }

    /// Контракт владельца: `client_identity` priv доступен только этому модулю —
    /// им подписывается `RESUME`, а не хранится где-либо ещё (`03` §7).
    #[test]
    fn contract_client_identity_is_owned_here() {
        let mut store = ClientSessionStore::new(InMemorySecureStore::new());
        assert!(store.secrets().is_none(), "до сохранения ключей нет");
        store.save(&state()).expect("сохранение");

        // Доступ к ключам — только через владельца; поля `ClientSecrets` приватны,
        // собрать их мимо этого крейта нельзя (проверяется компилятором).
        let secrets = store.secrets().expect("ключи появились");
        assert_eq!(secrets.identity(), &IDENTITY);
        assert_eq!(secrets.statics(), &STATIC);

        // Ключ, который можно напечатать, — утёкший ключ. Проверяем Debug **в любом
        // формате**: hex-пары (`a1, a1` — обычная derive-форма массивов), hex-константы
        // (`0xa1`), десятичные последовательности (`161, 161` — derive(Debug) массива
        // десятичными числами). Прежняя проверка видела только hex-пару и пропускала
        // десятичный дамп — false confidence (аудит F-SEC).
        let secrets_debug = format!("{:?}", store.state().expect("сессия").secrets);
        let state_debug = format!("{:?}", store.state().expect("сессия"));
        // Хранилище целиком: значения backend'а — сами секреты, {:?} не печатает их.
        let store_debug = format!("{:?}", store.backend());

        fn assert_no_secret_bytes(printed: &str, secret: &[u8], what: &str) {
            assert!(
                printed.contains("<redacted>"),
                "{what}: секретные поля redacted: {printed}"
            );
            for byte in secret.iter().take(4) {
                assert!(
                    !printed.contains(&format!("{byte}, {byte}")),
                    "{what}: нет десятичного дампа ({byte}, {byte}): {printed}"
                );
                assert!(
                    !printed.contains(&format!("0x{byte:02x}")),
                    "{what}: нет hex-дампа (0x{byte:02x}): {printed}"
                );
                assert!(
                    !printed.contains(&format!("{byte:02x}, {byte:02x}")),
                    "{what}: нет hex-пар ({byte:02x}, {byte:02x}): {printed}"
                );
            }
        }
        assert_no_secret_bytes(&secrets_debug, &IDENTITY, "ClientSecrets.identity");
        assert_no_secret_bytes(&secrets_debug, &STATIC, "ClientSecrets.statics");
        assert_no_secret_bytes(&state_debug, &IDENTITY, "SessionState");
        assert_no_secret_bytes(&state_debug, &STATIC, "SessionState");
        assert_no_secret_bytes(&state_debug, &K_SESSION, "SessionState");
        assert_no_secret_bytes(&store_debug, &K_SESSION, "InMemorySecureStore");

        // Стирание забирает и ключи: после `wipe` владельца ключей просто нет.
        store.wipe().expect("wipe");
        assert!(store.secrets().is_none());
    }

    /// Контракт восстановления: новая сессия процесса над тем же backend'ом поднимает
    /// состояние целиком (дескриптор + секреты), а не половину.
    #[test]
    fn contract_restart_restores_full_state() {
        let mut first = ClientSessionStore::new(InMemorySecureStore::new());
        first.save(&state()).expect("сохранение");
        let backend = first.backend().clone();

        let second = ClientSessionStore::new(backend);
        let restored = second.load().expect("чтение").expect("сессия есть");
        assert_eq!(
            restored.subscription_id,
            SubscriptionId("sub-42".to_string())
        );
        assert_eq!(restored.session_id, [0x22; 16]);
        assert_eq!(restored.next_seq, 7, "счётчик отправителя в дескрипторе");
        assert_eq!(restored.chain.len(), 2);
        assert_eq!(restored.secrets.statics(), &STATIC);
        assert!(
            restored.tickets.is_empty(),
            "tickets переживали бы только память"
        );

        // Испорченный дескриптор — `Corrupt`, не «сессия с чужим sid».
        let mut corrupt = ClientSessionStore::new(store_with_bad_descriptor());
        assert!(matches!(corrupt.load(), Err(StoreError::Corrupt)));
        corrupt.save(&state()).expect("перезапись чинит хранилище");
        assert!(corrupt.load().is_ok());
    }

    fn store_with_bad_descriptor() -> InMemorySecureStore {
        let mut backend = InMemorySecureStore::new();
        backend
            .put(KEY_DESCRIPTOR, &[0x00, 0x08, 0x41])
            .expect("put");
        backend.put(KEY_CLIENT_IDENTITY, &IDENTITY).expect("put");
        backend.put(KEY_CLIENT_STATIC, &STATIC).expect("put");
        backend.put(KEY_K_SESSION, &K_SESSION).expect("put");
        backend
    }
}
