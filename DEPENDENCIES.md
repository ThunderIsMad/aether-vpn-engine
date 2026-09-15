# DEPENDENCIES — feasibility прогон (первый, реальный)

**Дата прогона:** 2026-09-16 · **Скилл:** `crate-feasibility` · **Источник:** `design/03-components.md` (v2)
**Леджер:** `.agents/skills/crate-feasibility/SKILL.md`, факты F1–F13 (сегодня подтверждены, F5 опровергнут)

Проверка шла против crates.io / docs.rs / GitHub issues, а не «по названиям». Ниже —
что подтвердилось, что опровергнуто и где заявленная альтернатива не является drop-in.

## Что меняет дизайн

1. **F5 опровергнут: rustls умеет клиентский ECH.** `rustls::client::EchConfig` существует,
   есть пример `ech-client.rs`; объявлено experimental с 06.2024, серверный ECH — открытый
   issue #1980. Верна только половина про quinn: quinn ECH-путь не выставляет.
   **Вывод дизайна сохраняется** (ECH остаётся в Phase 4), но обоснование другое: не «rustls
   не поддерживает», а «сквозной ECH через quinn недоступен, серверная половина не готова».
   Формулировку в `03-components.md` и CHANGES-audit п. 8 стоит обновить — иначе она читается
   как устаревший факт.
2. **«noise-protocol + ml-kem» — не композиция, а форк.** В `noise-protocol` трейты только
   `DH`, `Cipher`, `Hash`; токенов `ekem`/`skem` нет вообще. Запасной путь из дизайна
   требует расширения паттерн-языка, а не соединения двух крейтов. Оценку «либо clatter,
   либо noise-protocol+ml-kem» надо переписать как «clatter, либо форк noise-protocol».
3. **BBR в quinn хуже, чем заявлено.** Не просто experimental, а «highly experimental and
   not currently maintained… substantially behind the upstream BBR» (issue #2156). Perf-фичу
   нельзя держать даже в отложенных клеймах.
4. **Клейм «uTLS-эквивалента в Rust нет» частично опровергнут.** Есть `impersonate-rs`
   (01.2026, HTTP-уровень) и профили JA3/JA4. Но TLS-слойного uTLS-эквивалента
   (программируемый ClientHello) действительно нет — `boring` даёт контроль, но это
   BoringSSL-биндинги, а не uTLS. Вывод «Reality — самый дорогой cover» держится; причина
   уточняется.
5. **Решение «свой MASQUE-клиент ~1–2k LOC» подтверждено фактом:** готового quinn-based
   клиента RFC 9298 нет — единственный готовый (`h3-masque`) построен на MsQuic.

## Таблица

| dependency | claimed feature | actual status | drop-in alternative | effort if none | проверен | TTL |
|---|---|---|---|---|---|---|
| `quinn` | QUIC-транспорт, ядро | **EXISTS**, дефолт CC — cubic | — | — | 2026-09-16 | 90 дней |
| `quinn` BBR | perf-фича «BBRv3» → «BBR» | **EXPERIMENTAL + не сопровождается**, отстаёт от upstream BBR (issue #2156) | нет; снять из клеймов, cubic + замер в Phase 0.5 | 0 (фича не нужна MVP) | 2026-09-16 | 90 дней |
| `quinn` resumption / 0-RTT / migration | восстановление сессии, миграция | **не проверено** — отложено в Phase 0.5 самим дизайном | — | спайк 1–2 дня (уже в roadmap) | 2026-09-16 | 90 дней |
| `h3` | HTTP/3 для MASQUE CONNECT-UDP | **EXISTS** | — | — | 2026-09-16 | 180 дней |
| CONNECT-UDP клиент | «свой на quinn+h3, ~1–2k LOC» | готового quinn-based нет; `h3-masque` — на MsQuic | свой клиент (как и планировалось) | ~1–2k LOC (оценка вперёд не проверяема) | 2026-09-16 | 180 дней |
| `clatter` | PQNoise с ML-KEM-768 | **EXISTS**, поддерживает MLKEM512/768/1024 + HQC. Оговорки: без формального аудита; собственное именование PQ-примитивов → interop не гарантирован; нет SEEC; опущены pattern parsing, Curve448, deferred/fallback patterns, PSK validity rule | — | принять + свои interop-тесты против эталона | 2026-09-16 | 180 дней |
| `noise-protocol` | база для NoisePQC++ | **EXISTS, но DH-only** — трейты DH/Cipher/Hash, KEM-токенов нет | — | форк: расширение паттерн-языка и KEM-трейт | 2026-09-16 | 180 дней |
| `ml-kem` (RustCrypto) | ML-KEM-768 | **EXISTS**, FIPS 203 | `kyberlib` (аудит против KyberSlash) | — | 2026-09-16 | 180 дней |
| `snow` | отвергнут дизайном | **CONFIRMED отвергнут**: только Kyber1024 round-3, закрытый `KemChoice` enum | `clatter` | — | 2026-09-16 | 180 дней |
| `chacha20poly1305`, `x25519-dalek` | AEAD + DH | EXISTS (стандарт RustCrypto); **в этом прогоне детально не перепроверялись** | — | пиннинг версий в Phase 0 | не проверялось | задать в Phase 0 |
| `boring` | Reality-обложка, контроль ClientHello | **EXISTS** (cloudflare/boring: 4.x stable, 5.0.0-alpha.1). Риск: два libcrypto в одном дереве (конфликт символов с rustls/ring) | xray-core как Go-sidecar | — | 2026-09-16 | 180 дней |
| `xray-core` | reference для Reality | EXISTS, **не зависимость** | — | — | 2026-09-16 | ∞ |
| `masque-go`, `quic-go` | reference-only | **CONFIRMED**: Go; `masque-go` реализует RFC 9298 | — | — | 2026-09-16 | ∞ |
| `ort` | ONNX Runtime для классификатора | **EXISTS**, но 2.0 — release candidate (2.0.0-rc.13); multiversioning ONNX Runtime 1.17–1.24 | TFLite | — | 2026-09-16 | 90 дней |
| TFLite | альтернатива для on-device ML | **не проверялось** в этом прогоне | `ort` | — | — | задать в Phase 2 |
| keyring / DPAPI / Keychain / libsecret | секьюрное хранилище | **не проверялось** в этом прогоне | — | — | — | задать в Phase 0 |
| «uTLS-эквивалента в Rust нет» | обоснование цены Reality | **ЧАСТИЧНО ОПРОВЕРГНУТО**: `impersonate-rs` (01.2026, HTTP-уровень), профили JA3/JA4; TLS-слойного эквивалента нет | — | уточнить формулировку в `03-components.md` | 2026-09-16 | 90 дней |

## RESEARCH-GRADE

Ни одна строка не получила статус RESEARCH-GRADE в этом прогоне: у всех либо EXISTS, либо
есть drop-in, либо дизайн уже сам вынес вопрос в спайк. Ближе всего к этому порогу
`noise-protocol` как замена clatter — там нет готового пути, только форк.

## До Phase 0

1. `MorphController`/`Classifier` на `ort` держать на 2.0-rc с планом отката на 1.x —
   rc-версия в крипто-ядре недопустима, но классификатор к ядру не относится.
2. Перед добавлением `boring` проверить сборку рядом с rustls: конфликт символов libcrypto
   проявится только на линковке, и лучше узнать это в Phase 1, а не в Phase 4.
3. Пункты 1–3 из «Что меняет дизайн» — это правки текста `03-components.md`, а не кода.

## Что не проверялось

`chacha20poly1305`, `x25519-dalek`, `keyring`/DPAPI/Keychain/libsecret, TFLite. Они не несут
специфичных для дизайна клеймов (кроме выбора хранилища), поэтому версии фиксируются на
скаффолде, а не здесь. В леджере их нет — фактов о них я не заводил.
