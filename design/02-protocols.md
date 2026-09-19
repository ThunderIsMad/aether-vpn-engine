# Aether — протоколы и механизмы (v3, drilldown ротации и handshake)

Главные изменения v2: (1) добавлен frame-слой как носитель сессии; (2) ротация описана
до уровня сообщений (ticket-based, make-before-break); (3) 0-RTT переосмыслен; (4) убраны
некорректные утверждения про «inner QUIC переживает всё» и «KEM едет в QUIC Initial».

**Изменения v3 (по результатам anti-air-audit и drilldown §3/§5):**
(1) handshake переименован: `Noise_IK`, а не XX — статический ключ узла предраспределён
в манифесте подписки (§5); (2) резюм требует proof-of-possession клиента: украденный ticket
больше не даёт сессии (§3.3); (3) post-rotation re-key переведён на свежий DH — прежняя формула
`HKDF(K_session, "rotate", eph)` forward secrecy против N1 не давала (§3.3); (4) RESUME получил
явную защиту `K_resume`, снято противоречие per-node/fleet wrap: wrap объявлен флотским (§3.2);
(5) дедуп на узле специфицирован окном 4096 и клейм заменён на at-most-once (§3.5);
(6) крана объявлен как разрешаемая клиентом + consumed-set на узле (§3.6); (7) multi-hop
объявлен RESEARCH-GRADE без ложного «спроектирован» (§3.4).

## 1. FrameSession — cover-agnostic record-протокол (носитель сессии)

Сессия Aether — это НЕ транспортное соединение. Это таблица потоков + ключи + счётчики,
живущие на клиенте (SessionStore) и восстановимые на узле из ticket. Все данные ходят records:

```
Record = type(1B) | stream_id(varint) | flags(1B) | len(varint) | ciphertext
ciphertext = XChaCha20-Poly1305(K_record, nonce = seq(8B) || sid(16B), plaintext)
```

- `K_record` — константный вывод из `K_session` (F-02, аудит 3):
  `K_record[n] = HKDF-SHA256(salt = sid, ikm = K_session, info = "aether v3 record" ‖ be64(n))` —
  один шаг HKDF для произвольного `n` (приём O(1), без цепочки-курсора; утечка члена не даёт
  ни прошлых, ни будущих; компрометация `K_session` раскрывает всё поколение — окно сужается
  периодическим re-key (политика `REKEY_POLICY_LIMIT` записей, Q25) и ротацией узла).
- `seq` — монотонный счётчик записей сессии (не потока); узел подтверждает continuity point
  по `seq` и дедуплицирует по `(sid, seq)` — идемпотентный дедуп, **at-most-once на выходе**
  (exactly-once не заявляется; окно и его границы — `§3.5`).
- Типы: DATA, ACK, RESUME, RESUME_ACK, REKEY, KEEPALIVE, COVER_HINT, CLOSE.
- `stream_id` ↔ один прикладной поток (route rule / app flow). FIN-семантика через flags.

**Инвариант:** сессия живёт, пока жив `(K_session, stream_table, seq)`. Транспортные
соединения (outer) приходят и уходят — обложки, узлы, even протоколы (UDP/TCP).

## 2. Байндинги frame-слоя к транспортам

### 2.1 QUIC-нативный байндинг (дефолт)
- Один outer QUIC connection; `stream_id` ↔ QUIC stream → no-HOL, CID rotation. Migration:
  серверная сторона в quinn есть и включена по умолчанию (`ServerConfig::migration`, NAT-rebinding
  и смена адреса клиента), активная миграция со стороны клиента публичным API quinn 0.11.12
  не предоставляется (только endpoint-широкий `Endpoint::rebind`) — клейм сужен (Phase 0.5,
  `docs/phase-reports/phase-0.5.md`).
- Control-записи (RESUME/REKEY) — отдельный QUIC stream.
- 0-RTT early data outer QUIC — только для control-записей без побочных эффектов (KEEPALIVE),
  — подтверждено спайком: `Connecting::into_0rtt()` в quinn 0.11.12 есть, replay-оговорка самой
  библиотеки («never invoke non-idempotent operations») совпадает с этим правилом (`phase-0.5.md`),
  и только если стек поддерживает; иначе 1-RTT resumption через TLS tickets.
- **Следствие v3:** `RESUME` идемпотентным больше не является — повтор того же ticket даёт
  `RESUME_NAK replay` (`§3.6`). Поэтому по умолчанию RESUME идёт после подтверждённого outer–хендшейка,
  а его отправка в 0-RTT допустима только вместе с обработкой NAK/ретрая.

### 2.2 Reality/TCP-байндинг (tradeoff — задокументирован)
- Records идут как length-prefixed frames поверх сплайснутого TLS-потока Reality.
- **HOL-блокировка на TCP существует для этого байндинга** — это цена самой сильной статики
  против DPI. Митигация: MorphController использует Reality только при явной блокировке
  QUIC-путей, и переключается на QUIC-байндинг при первой возможности (FSM `§4`).
- QUIC-over-TCP не используется (противоестественно: datagram-протокол в stream).

### 2.3 MASQUE-байндинг (RFC 9298 CONNECT-UDP)
- Records — полезная нагрузка UDP-капсул в CONNECT-UDP сессии поверх HTTP/3.
- Выглядит как легитимный HTTP/3 прокси-трафик; проходит QUIC-вайтлистящие цензоры.

## 3. Ротация egress-узла (Stateless Egress Core)

Паттерн: **TLS session tickets (RFC 8446 §2.2), адаптированный под флот узлов**, плюс
proof-of-possession клиента и свежий DH на ротации.

### 3.1 Ключи и единый канал раздачи

| Ключ | Размер | У кого priv | Назначение |
|---|---|---|---|
| `authority_sign` Ed25519 | 32 B | authority | подпись манифеста подписки |
| `TFK_epoch` (AEAD) | 32 B | **только узлы флота** | wrap/unwrap ticket |
| `node_static` X25519 | 32 B | узел | DH-половина Noise_IK |
| `node_identity` Ed25519 | 32 B | узел | подпись `RESUME_ACK` |
| `client_static` X25519 | 32 B | клиент | DH-половина Noise_IK |
| `client_identity` Ed25519 | 32 B | клиент | PoP-подпись `RESUME` |
| `K_session` | 32 B | клиент + текущий узел | мастер сессии |
| `K_resume` | 32 B | любой узел флота (из ticket) | защита RESUME/RESUME_ACK |
| `K_record` | 32 B | клиент + узел | записи (ratchet) |

Канал раздачи — **манифест подписки**, подписанный `authority_sign`, доставляется по тому же
subscription-update каналу, но payload **ролевой**:

| Получатель | Что получает |
|---|---|
| Узел флота | `TFK_epoch`, `epoch_id`, `node_set_id`, авторизованный набор `client_static`/`client_identity` pub |
| Клиент | `node_static`/`node_identity` pub узлов флота, свои ключи, `node_set_id` |

**`TFK_epoch` клиенту не выдаётся никогда** — иначе клиент минтит tickets сам, и PoP с containment
обходятся. Аутентификация канала: подпись authority, монотонная версия манифеста, `manifest_exp`;
доставка по mTLS. Отзыв узла или клиента = исключение из списка. При недоступности authority
работа продолжается на текущем манифесте до `manifest_exp`, новые ключи не принимаются.

### 3.2 Ticket

`ticket_blob = nonce(12 B) ‖ AEAD_XChaCha20Poly1305(TFK_epoch, nonce, plaintext)`

| Поле plaintext | Размер | Кто выставляет |
|---|---|---|
| `version` | 1 B | узел-минтер |
| `session_id` | 16 B | узел-минтер |
| `node_set_id` | 4 B | authority (из манифеста) |
| `epoch_id` | 4 B | узел-минтер |
| `minted_at` | 8 B | узел-минтер |
| `exp` | 8 B | узел-минтер |
| `K_session_wrapped` | 32 B | узел-минтер |
| `client_auth_pub` (Ed25519) | 32 B | узел-минтер (из авторизованного набора) |
| `window_lo`, `window_hi` | 8 B + 8 B | узел-минтер (пол дедупа на момент минта) |

Итого blob ≈ 165 B. **Wrap — флотский** (`TFK_epoch` у всех узлов флота): компрометация одного
узла вскрывает tickets эпохи. Это задокументированный tradeoff; per-node wrap — hardening вне MVP.

Mint делает **только узел**, по запросу клиента (MINT_REQ внутрь `K_session`) или сразу после
handshake. Клиентский `KeyCoordinator` не минтит и `TFK_epoch` не имеет: он хранит ticket,
запрашивает mint, делает PoP-подпись и проводит re-key (см. `03-components`, `01-architecture`).

### 3.3 Ротация: PoP + свежий DH (1 RTT)

`K_resume = HKDF-Expand(HKDF-Extract(salt = session_id, ikm = K_session), "aether v3 resume", 32)`

**RESUME** (клиент → N2, в control-стриме поверх шифрованного outer):

**Обрамление сообщения (Q19, зафиксировано по проводу — CI, `a1bd09f`):** за заголовком
`kind ‖ len` следует **nonce 24 B в открытом виде, до AEAD-payload** — для `RESUME` это
`client_nonce(16 B) ‖ метка направления(8 B)`, для `RESUME_ACK` — тот же `client_nonce` с меткой
`"resumeak"`; разные метки исключают повтор nonce при одном `K_resume` на два сообщения.
Дублирование `client_nonce` внутри sealed-части оставлено: оно под `sig_client`, то есть
аутентифицировано; голый префикс подписи не несёт. Nonce не может жить внутри payload,
который им же вскрывается; AAD ответа — сам запрос `RESUME` (привязка к нему).

| Поле | Размер | Кто выставляет |
|---|---|---|
| `ticket_blob` | ~165 B | узел-минтер (непрозрачен, вне `K_resume`) |
| `sealed{K_resume}` → `last_seq` | 8 B | клиент |
| `sealed{K_resume}` → `window_lo`, `window_hi` | 8 B + 8 B | клиент |
| `sealed{K_resume}` → `eph_client` X25519 pub | 32 B | клиент |
| `sealed{K_resume}` → `client_nonce` | 16 B | клиент |
| `sealed{K_resume}` → `sig_client` Ed25519 | 64 B | клиент |

`sig_client` покрывает `"aether-resume-v3" ‖ sha256(ticket_blob) ‖ last_seq ‖ window_lo ‖ window_hi
‖ eph_client ‖ client_nonce`. N2 разворачивает `ticket_blob` флотским `TFK_epoch` → получает
`K_session` → вычисляет `K_resume` → рассекречивает остаток. **Узел проверяет `sig_client` по
`client_auth_pub` из ticket: украденный `ticket_blob` резюм не даёт.** Тикет летит вне `K_resume`,
но внутри шифрованного outer, то есть защищён от сети и открыт для флота — как и требуется.
Проводной формат RESUME: `kind(1B) ‖ len(2B) ‖ nonce(24B) ‖ sealed` (Q19, выше); **RESUME_ACK —
len-less**: `kind(1B) ‖ nonce(24B) ‖ sealed` (длина не нужна — payload фиксирован:
120 B; так он на проводе с Phase 0, признано по BLOCKER-2, `QUESTIONS.md`).

**RESUME_ACK** (N2 → клиент, sealed под `K_resume`):

| Поле | Размер | Кто выставляет |
|---|---|---|
| `continuity_point` | 8 B | N2 |
| `window_lo`, `window_hi` | 8 B + 8 B | N2 |
| `eph_node` X25519 pub | 32 B | N2 |
| `sig_node` Ed25519 | 64 B | N2 |

`sig_node` покрывает `"aether-resume-ack-v3" ‖ sha256(transcript_client) ‖ continuity_point ‖
window_lo ‖ window_hi ‖ eph_node`. **Подпись узла обязательна:** без неё скомпрометированный N1,
знающий `K_session`, подсунул бы свой `eph_node` и сохранил чтение — фикс свежего DH без неё не работает.

**Семантика `last_seq`/`continuity_point` ACK (Q26/F-12, 2026-09-19).** `last_seq` в `RESUME` —
последний **выданный** seq отправителя в рамках sid: монотонный, откат запрещён. Узел после
рестарта строит окно из этого claim и в `RESUME_ACK` подтверждает **выданный потолок**, а не
«последний принятый»: факт приёма у рестартовавшего узла не восстановим, и он его не заявляет.
Следствие для клиента: продолжение отправки — со `seq > ACK.continuity_point`; счётчик
отправителя персистится клиентом рядом с `K_session` (sync-запись на каждый seal),
продолжение живого sid с откатным/нулевым счётчиком запрещено — без счётчика только новая
сессия с новым sid (иначе повтор `seal` под тем же `(sid, seq)` переиспользовал бы
`K_record[seq]` и nonce `seq ‖ sid`). Правило не касается приёмной стороны ротации: свежий
узел обязан принимать RESUME из клиентского claim (`§3.5`).

**Post-rotation re-key:**

`ss_rotate = DH(eph_client_priv, eph_node_pub)` — 32 B
`K_session' = HKDF-Expand(HKDF-Extract(salt = session_id, ikm = ss_rotate ‖ K_session), "aether v3 rotate", 32)`

ratchet `K_record` перезапускается от `K_session'`. N1, знающий только `K_session`, `ss_rotate`
не вычислит, а подделать `RESUME_ACK` без `node_identity` не может → пост-ротационный трафик
ему недоступен.

Шаг 5 прежней редакции (дублирование `seq >= continuity_point` на оба канала до подтверждения,
затем teardown старого) сохраняется; таймаут и бюджет дублирования — `§4`.

**Состояния по сторонам** (клиент / N1 старый / N2 новый):

| Сторона | До ротации | Во время (make-before-break) | После |
|---|---|---|---|
| Клиент | `K_session`, `K_record`, seq, ticket | + `eph_client`, `client_nonce`, дубли на оба канала | `K_session'`, ratchet от нуля, `window_lo/hi` |
| N1 (старый узел) | `K_session`, окно 4096, consumed-set эпохи | принимает дубли, гасится по сигналу клиента | состояния сессии нет; `K_session` пост-ротационный трафик не читает |
| N2 (новый узел) | только `TFK_epoch` + манифест | unwrap ticket, проверка PoP, отправка ACK | `K_session'`, своё окно 4096, consumed-set пополнен |

### 3.4 Multi-hop (Federated Egress Mesh) — RESEARCH-GRADE

RESEARCH-GRADE (Phase 3): per-hop фрейминг и ключи хопов не специфицированы; см. `05-roadmap`.

Цепочка 1–3 узлов, per-hop гибрид, `K_session` end-to-end между клиентом и последним хопом.
**Механизм прохождения кадра через хопы (вложенная ре-инкапсуляция? ключи хопов? onion-слои?)
не специфицирован.** Каркас: SessionStore держит chain descriptor, адресация следующего хопа
в control-записи. Валидация метрики — Phase 3.

### 3.5 Дедуп на узле

Клейм: **идемпотентный дедуп по `(sid, seq)`, at-most-once на выходе**. Exactly-once не заявляется.

| Параметр | Значение | Владелец |
|---|---|---|
| Окно | 4096 записей (bitmap 512 B per session) | узел, in-memory |
| `window_lo` при resume | max(пол из ticket, `last_seq` − 4096) | узел |
| `seq < window_lo` | drop + счётчик аномалии | узел |
| `seq` в окне повторно | drop, `continuity_point` не двигается | узел |
| Потеря состояния (рестарт) | окно восстанавливается из подписанного клиентом `last_seq` (= выданный потолок отправителя); `window_lo` = max(пол из ticket, `last_seq` − 4096) | узел |

Узел держит окно только на время сессии; состояния, переживающего ротацию, у него нет.
`last_seq`/`window_lo/hi` приходят от клиента и покрыты его подписью (`§3.3`) — иначе клиент мог бы
произвольно двигать пол. Клиент-обманщик вредит только собственной целостности, что допустимо.

**Семантика `last_seq` (Q26/F-12, 2026-09-19).** `last_seq` — «последний **выданный** seq
отправителя в рамках sid», монотонный, откат запрещён. После рестарта узел строит окно
`(max(пол из ticket, last_seq − 4096), last_seq)`: всё `seq ≤ hi` никогда не принимается как
новое (повтор — `Duplicate`), продолжение нумерации — `> hi`. Зазор между реально принятым
узлом и выданным потолком теряется из доставки — осознанная потеря availability при рестарте;
целостность и at-most-once не страдают. Отправитель продолжает с сохранённого счётчика
(session-store, sync-запись на каждый seal); продолжение живого sid с откатным/нулевым
счётчиком запрещено — только новая сессия с новым sid (повтор `seal` под тем же `(sid, seq)`
при той же базе переиспользовал бы `K_record[seq]` и nonce `seq ‖ sid`).

### 3.6 Крана и повтор RESUME

- Узел держит **in-memory consumed-ticket set** на эпоху (ключ `epoch_id ‖ sha256(ticket_blob)`).
  Первый RESUME → `RESUME_ACK`; повтор того же ticket **на том же узле** → `RESUME_NAK replay`.
- **Набор теряется при рестарте узла** — принимаем и документируем: в окне до перезапуска повтор
  того же ticket даёт вторую живую сессию поверх PoP. Смягчение: короткие эпохи + `exp`.
- **Кране двух разных узлов** (N2 и N3) набором не решается — наборы не разделяются. Практически
  она достижима только для самого клиента (повтор при ретрае) или для узла флота, у которого
  уже есть `TFK_epoch` (вне модели угроз), потому что PoP-подпись третьей стороне недоступна.
  Разрешается на клиенте: побеждает первый валидный `RESUME_ACK`, второй канал уходит в quarantine
  (`§4`); при двух ACK одновременно — тот, чья `sig_node` проверена раньше.
- Ретрай после потери ACK: новый `client_nonce` и новый `eph_client`, тот же ticket (узел примет
  его один раз).

### 3.7 Ветки отказов

**Кадр `RESUME_NAK`** (F-06, аудит 3): `kind(1B) = 0x02 ‖ код причины(1B)`. Коды —
единый источник правды `key_coordinator::NAK_*`: `bad_pop = 0x01`, `replay = 0x02`,
`epoch = 0x03`, `expired = 0x04`. Шифрования нет — NAK не несёт секрета, только причину.
Детекция — по фрейму целиком (`len == 2` **и** `kind == 0x02`), не по первому байту
сырого ответа (аудит F-CORR: первый байт легитимного ticket — данные). Неизвестный код
причины — «ответ не разбирается» на клиенте. Эмиттер один для всех узлов —
`key_coordinator::build_resume_nak`; парсер один — `accept_response` →
`ResumeError::Nacked(ResumeNak)` с причиной (клиент различает ветки, см. таблицу).

| Ветка | Детект | Действие |
|---|---|---|
| `RESUME_ACK` не пришёл | таймаут `T_ack` = 2 × SRTT, клип [200 ms, 2 s]; владелец FrameSession | ретрай с новым nonce: первая попытка плюс **не более одной повторной** (всего ≤ 2 попыток RESUME на ticket — Q18), затем откат на старый канал |
| `sig_client` неверна | узел | `RESUME_NAK bad_pop`, ticket не консумируется, инцидент в телеметрию узла |
| `sig_node` неверна | клиент | канал не подтверждён, узел в quarantine, откат на старый канал |
| Крана RESUME | узел и клиент | `§3.6` |
| Узел упал между RESUME и RESUME_ACK | клиент по `T_ack` | новый узел из `node_set_id`; старый канал живёт до валидного ACK |
| `epoch_id` не совпал | узел | `RESUME_NAK epoch`, фолбэк: полный IK-handshake `§5` |
| `exp` истёк | узел | `RESUME_NAK expired`, фолбэк: полный handshake |
| `last_seq` ниже пола из ticket | узел | принять окно от клиента (`window_lo` = пол из ticket), залогировать аномалию |

### 3.8 Инварианты

| Инвариант | Enforcement |
|---|---|
| Пост-ротационный трафик читает только новый узел | `K_session'` требует `ss_rotate`; `sig_node` не даёт подменить `eph_node` |
| Украденный ticket не даёт сессии | `sig_client` проверяется по `client_auth_pub` из ticket |
| Клиент не минтит tickets | `TFK_epoch` клиенту не выдаётся, mint только на узле |
| **Aether**-сессия не рвётся на ротации (payload-соединения — `05-roadmap` риск) | make-before-break: старый канал гасится только после валидного ACK |
| **At-most-once на узел; at-least-once при ротации** | окно 4096 у каждого узла, `window_lo` из ticket, при потере состояния — подписанный пол от клиента; дубли между узлами покрыты duplicate-окном (`§3.9`), глобального exactly-once нет и не заявляется |

### 3.9 Компромисс-анализ

| Скомпрометировано | Последствие | Митигация |
|---|---|---|
| `authority_sign` (корень доверия) | обнуляет отзыв `node_identity` / `client_identity` / `node_static` / `TFK_epoch`: подделанный манифест возвращает отозванные ключи в строй | короткий `manifest_exp` + ротация authority (вне MVP) |
| `TFK_epoch` | все tickets эпохи → `K_session` → чтение и resume | короткие эпохи, ротация TFK, per-node wrap вне MVP |
| `K_session` у N1 | трафик до ротации (по построению — узел и есть точка выхода) | post-rotation re-key |
| `client_identity` (Ed25519) | резюм с украденным ticket возможен | нужен ещё и ticket (SessionStore); отзыв клиента через манифест |
| `client_static` (X25519) | выдача себя за клиента в IK | отзыв через манифест; для резюма всё равно нужен `client_identity` |
| `node_identity` (Ed25519) | подмена `RESUME_ACK` → N1 сохраняет чтение | ротация ключа узла через манифест |
| `node_static` (X25519) | MITM на новом handshake ещё до IK-аутентификации | отзыв узла; на существующие сессии не влияет (FS через эфемерные ключи) |
| `K_record` в момент n | записи `> n` (ratchet однонаправленный) | периодический re-key + ротация узла |

Duplicate-окно при ротации ≈ 1 RTT дублированного трафика — bounded, задокументирован (`§4`).

## 4. Liquid Tunnel (морфинг FSM) — research-grade, но механизм описан

```mermaid
stateDiagram-v2
  state "rollback → предыдущий байндинг" as Rollback
  [*] --> Probe
  Probe --> QuicNative: HTTP/3 норма
  Probe --> Masque: QUIC-вайтлист прокси
  Probe --> Reality: чистый uplink, но QUIC блокируется
  Probe --> SsPadded: низкая безопасность сети
  QuicNative --> Masque: классификатор: non-browser QUIC
  QuicNative --> Reality: ECH/SNI-проблемы
  Masque --> Reality: классификатор: прокси-паттерн
  Masque --> QuicNative: QUIC доступен
  Reality --> QuicNative: QUIC доступен
  Reality --> Masque: probe-rate/RST spike
  Reality --> SsPadded: target-site дрейф
  SsPadded --> QuicNative: сеть чистая
  QuicNative --> Rollback: morph failed / BindingError
  Masque --> Rollback: morph failed / BindingError
  Reality --> Rollback: morph failed / BindingError
  SsPadded --> Rollback: morph failed / BindingError
```

- Классификатор на устройстве (tiny ONNX/TFLite, класс 2506.11319): probe/block rate,
  RST/FIN паттерны, latency cliffs, распределение длин пакетов vs baseline (2509.23522).
- Метрика приёмки: false-negative < X% и false-positive < Y% на тестбеде Phase 2; пороги — Phase 2.
  Значения не выдумываются здесь: они зависят от распределения и стоимости ложных срабатываний на тестбеде.
- Морф = смена активного байндинга в TransportMux + (опц.) смена target-site/fingerprint.
- **Overlap-window при морфе (специфицировано v3):** дублирование records на старый+новый
  байндинги до ACK по новому; старый teardown. Параметры — в таблице ниже; бюджет именно
  двойной (`N` ИЛИ `T`), потому что одного счётчика записей мало (при низком трафике окно висит
  бесконечно), а одного таймера тоже (при высоком дубли раздуваются до его истечения).

| Параметр окна морфа | Значение | Владелец |
|---|---|---|
| Условие закрытия | валидный ACK по новому байндингу | FrameSession |
| Таймаут `T_morph` | 2 × SRTT, клип [200 ms, 2 s] | FrameSession (владелец таймера) |
| Бюджет дублирования | `N ≤ 4096` записей **или** `T_morph` — что раньше | FrameSession |
| Исчерпание бюджета | `MorphFailed` → ребро отката на предыдущий байндинг, обложка в quarantine | MorphController |
| Quarantine | обложка не выбирается `T_quar = 5 мин` (иначе FSM ретраит сломанную обложку) | MorphController |
| Синхронный отказ `send()` | `BindingError` → FSM, обложка в quarantine | TransportMux |
| Асинхронный отказ байндинга | событие `on_failure()` → тот же путь rollback/quarantine | TransportMux → FSM |
- Self-test: локальный прогон публичной DPI-модели (eval-only) для оценки обложек офлайн.

## 5. Гибридный PQ handshake (Noise_IK, стиль PQNoise)

**Исправление v3.** Прежняя формулировка «Noise-XX из двух сообщений» неверна дважды.
XX — это три сообщения, и он передаёт статический ключ **респондера**. У нас статический ключ
узла **предраспределён в манифесте подписки**, а по классификации Noise (`I` — статик инициатора
передаётся сразу; `K` — статик респондера известен заранее) это **IK**: два сообщения, один RTT.
Это же модель WireGuard. Если бы статик инициатора тоже был известен заранее, это был бы KK;
IK сохранён сознательно — узел узнаёт, кто звонит, только расшифровав msg1 своим статиком.

Свойства: клиент аутентифицирует узел по `node_static` из манифеста; узел аутентифицирует
клиента по своему авторизованному набору (`client_static`) — cryptokey routing.

Хендшейк едет **на control-стриме поверх уже установленного outer QUIC**, не в Initial
(датаграмма Initial ограничена ~1200 B).

**msg1** (клиент → узел):

| Поле | Размер | Кто выставляет |
|---|---|---|
| `e` X25519 eph pub | 32 B | клиент |
| `e_kem` ML-KEM-768 эфемерный encapsulation key | 1184 B | клиент |
| `sealed_s` статический X25519 клиента (encrypted) | 32 B + 16 B tag | клиент |

**msg2** (узел → клиент):

| Поле | Размер | Кто выставляет |
|---|---|---|
| `e` X25519 eph pub | 32 B | узел |
| `kem_ct` ML-KEM-768 ciphertext к `e_kem` | 1088 B | узел |
| `tag` пустая нагрузка | 16 B | узел |

**Замер раскладки (ИЗМЕРЕНО; Clatter 2.3.0, CI 2026-09-16): msg1 = 3568 B, msg2 = 3424 B** —
итого ≈ 7.0 KB за 1 RTT против прежних бюджетов 1264/1136 (≈ 2.4 KB), разница **2.9×**. Размеры
пиннятся равенством в `crypto-core::contract_noise_ik_two_messages_one_rtt`; **обёртка байтов не
добавляет** (`write_message` → `truncate(n)`, лишних полей нет) — это не баг обёртки, а раскладка
гибридного IK в формулировке Clatter (`hybridIK: -> Skem, E, ES, S, SS / <- Ekem, Skem, E, EE, SE`),
которая несёт то, чего бюджеты не считали:

- `Skem` — **статический** KEM-ключ инициатора в msg1 (1184 B) и статический KEM-ключ узла в msg2
  (1184 B); бюджеты предполагали только эфемерные KEM-половины;
- гибридный `E` несёт **обе** половины — DH (32 B) и KEM-ek (1184 B), т.е. 1216 B на сообщение;
- AEAD-теги зашифрованных статиков (`S`: 32 + 16 B) и внутреннее обрамление/length-префиксы
  сериализации Clatter.

Точная декомпозиция по токенам — Phase 0.5 (Q12). Следствие, пока семантика токенов не зафиксирована:
какая из KEM-половин клиента получает инкапсуляцию в msg2 (эфемерная или статическая) — замером не
установлено, поэтому HNDL-абзац ниже держится на DH-половинах; подтверждение — Phase 0.5.

**KEM остаётся эфемерным.** Если бы клиент инкапсулировал только к статическому PQ-ключу узла,
компрометация этой статики вскрыла бы записанные сессии и HNDL-клейм — центральный для проекта —
перестал бы держаться. Предраспределённые статики дают аутентификацию, эфемерный KEM даёт
post-quantum forward secrecy; это разные задачи.

**Вывод `K_session` (Q10, зафиксировано по факту реализации — вариант «спека под Clatter»):**
формула `HKDF(ss_ee ‖ ss_es ‖ ss_se ‖ ss_ss ‖ ss_mlkem)` ниже — внутренность Clatter: библиотека
смешивает DH- и KEM-секреты в симметричном состоянии и наружу отдельные `ss_*` не отдаёт (экспорт
— `get_hash()`/`get_chaining_key()`/`split()`; по исходнику `handshakestate/hybrid.rs` в hash через
`mix_key_and_hash` идёт только `ss_skem`, все секреты сходятся в chaining key). Наш слой выводит:

`K_session = HKDF-Expand(HKDF-Extract(salt = session_id, ikm = chaining_key), "aether v3 session", 32)`

где `chaining_key` — `SymmetricState::get_chaining_key()` после msg2 (32 B, SHA-256). Гибридность
комбината («держится, пока держит либо X25519, либо ML-KEM») — свойство раскладки токенов Clatter,
на нашем слое не наблюдаемо и не сверяемо; сверка раскладки — Phase 0.5 (Q12). Все нижележащие
выводы наследуют эту точку: `K_resume` (`§3.3`), `K_record`/ratchet (`§1`), `K_session'` при
ротации (`§3.3`) — строятся от `K_session` и не меняются.

Безопасно, пока держит **либо** X25519, **либо** ML-KEM-768 → HNDL-safe для записей сессии.
Outer QUIC/TLS 1.3 — классический, его роль транспортная; PQ-защита относится к записям frame-слоя.

Крипто-агильность: KEM — именованный swappable параметр (2609.07849).

Реализация: **Clatter 2.3.0** — паттерн `noise_hybrid_ik()` (`hybridIK`); гибридный IK в библиотеке
есть (проверено реализацией Phase 0, Q4/Q12). Крейт без формального аудита, своё именование
PQ-примитивов → interop-тесты обязательны (написаны: KAT + двунаправленный PQClean ↔ RustCrypto).
`noise-protocol` + RustCrypto `ml-kem` — только через форк (KEM-токенов нет); `snow` НЕ годится
(только Kyber1024 r3).

**Плата за IK:** нет фолбэка на неизвестный статический ключ узла — ротация `node_static`
требует обновления манифеста до начала сессий. Это осознанный обмен на 1 RTT.

Подтвердить в Phase 0.5 (иначе паттерн пересматривается на KK): семантику токенов и цель
KEM-инкапсуляции, транскрипт хендшейка, поведение при рассинхронизации манифеста.

## 6. App Mirage (research-grade)

CoverEngine синтезирует декой-потоки с byte-length/timing распределением популярного
приложения (FlowPaint-класс, 2606.22717), rate-limited, только по требованию классификатора.
Decoy — реальные зашифрованные байты к benign-назначению. Двухфазная валидация: офлайн
датасеты → живой DPI-тестбед (Phase 3).

## 7. Честная семантика 0-RTT

- Noise_IK не имеет 0-RTT resumption. Заявлять «0-RTT» для сессии — некорректно.
- Реальная семантика: **reconnect ≈ 1 RTT** = outer QUIC TLS resumption (где поддерживается
  стеком) + `RESUME` frame по ticket. 0-RTT early data outer QUIC — только идемпотентный
  контроль. Спайк Phase 0.5: механизм есть (`Connecting::into_0rtt()`), библиотека сама
  предупреждает про replay; RESUME с ticket в 0-RTT не кладётся (replay семантики ticket,
  `§3.6`).

## 8. Сводка крипто

| Плоскость | Примитив | Статус |
|-----------|----------|--------|
| Handshake сессии | Noise_IK + `X25519MLKEM768` | реализовано: `noise_hybrid_ik()` Clatter 2.3.0, токены `-> Skem, E, ES, S, SS / <- Ekem, Skem, E, EE, SE` (Phase 0 + спайк `phase-0.5.md`) |
| Записи сессии | `XChaCha20-Poly1305` + ratchet | реализуемо |
| Ротация | TLS-ticket + PoP + свежий DH re-key | спроектировано до полей (`§3`), тест в Phase 0 |
| Outer транспорт | стандартный QUIC/TLS 1.3 | классический (не PQ) — транспортная роль |
| Cover-синтез | FlowPaint-класс генератор | research-grade |
| Метаданные | CID rotation; ECH/OHTTP | ECH отложен (Phase 4) — сквозь quinn недоступен, серверная половина открыта |
