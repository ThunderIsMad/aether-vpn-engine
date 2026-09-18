# E2E-прогон вручную (Phase 1) — живой QUIC, живая ротация N1→N2

**Дата:** 2026-09-16 · **Крейт:** `crates/e2e-harness` (бины `aether-node`, `aether-client`,
фича `e2e`) · **Скрипт:** `scripts/e2e-manual.sh` · **CI-статус:** это **не** CI job.

## Что это и зачем

Phase 0 проверяла протоколы `02-protocols.md` моками (`rotation-tests`: MockChannel,
`phase0-path`: MemBinding). Единственный пробел такого подхода — **настоящий транспорт**:
реальный `quinn::Endpoint` (UDP-сокеты, QUIC-handshake, QUIC-датаграммы) вместо
имитации канала. Этот прогон закрывает пробел на localhost.

## Точная команда

```bash
./scripts/e2e-manual.sh
# переопределение: PORT1=45100 PORT2=45101 ./scripts/e2e-manual.sh
```

Скрипт сам: собирает бины, поднимает N1 и N2 (каждый пишет манифест в `mktemp -d`),
ждёт манифесты, запускает клиента, печатает логи узлов, гасит процессы.

## Что происходит в прогоне

1. **N1, N2**: QUIC-серверы quinn на `127.0.0.1` (датаграммы включены), ключи из seed'ов,
   самоподписанный сертификат + манифест на диск.
2. **Клиент**: `policy-engine` (правило → `Route`) → QUIC-соединение с N1 (пин сертификата
   из манифеста) → Noise_IK (прод-`IkInitiator`/`IkResponder` на clatter) →
   `frame_session::Session` → прод-`QuicBinding` (`send` → `take_pending` →
   `send_datagram`) — 5 записей на N1, N1 вскрывает их зеркалом сессии.
3. **Mint**: клиент запрашивает ticket у N1 (`TicketFactory::mint_at`).
4. **Ротация N1→N2**: прод-`ClientRotation` — mint-запрос, `RESUME` (`build_resume`,
   PoP `sig_client`), проверка `sig_node` ACK на клиенте (`accept_response`),
   консумация ticket на N2 (`handle_resume`), re-key `K_session'` по DH(eph_client, eph_node)
   с обеих сторон.
5. **После re-key**: 5 записей seq=5..9 на N2 под `K_session'`; N2 вскрывает их,
   окно дедупа восстановлено из подписанного `last_seq` (`02 §3.5`).

## Что видно в логах (критерии успеха)

```
[client] policy: 203.0.113.x:443 (Some("lab.aether.test")) → Route (tunnel-lab)
[client] QUIC connected to N1 (...)
[client] Noise_IK complete: K_session#=ab12cd34ef56...
[node1]  Noise_IK handshake complete: K_session#=ab12cd34ef56...   ← тот же хеш
[node1]  record seq=0..4 accepted
[client] ticket minted at N1 (161 B)
[client] RESUME accepted by N2: continuity_point=4, window=(0,4)
[node2]  RESUME accepted: last_seq=4, window=(0,4), ticket consumed
[node2]  re-key: K_session'#=9876fedcba54...
[client] re-key: K_session'#=9876fedcba54...                        ← тот же хеш
[client] record seq=5..9 sent to N2 under K_session'
[node2]  record seq=5..9 accepted                                   ← продолжение нумерации
[client] E2E DONE
```

Прогон успешен, если: хеши `K_session` у клиента и N1 совпали; хеши `K_session'` у
клиента и N2 совпали; N2 принял seq=5..9 без rejected/DUPLICATE; ticket консумирован
(`consumed`), дедуп-счётчики N1/N2 чистые.

## Что это доказывает

* **Реальный quinn 0.11.12**: UDP endpoint'ы, QUIC-handshake с TLS, QUIC-датаграммы
  (`send_datagram`/`read_datagram`), а не имитация канала.
* **Реальный Clatter handshake**: полный гибридный Noise_IK `X25519MLKEM768` в двух
  сообщениях поверх живого стрима — тот же код, что в `crypto-core` KAT/interop-тестах.
* **Реальная ротация**: прод-`ClientRotation` + прод-`TicketFactory` против друг друга
  по сети — mint, RESUME с PoP, проверка `sig_node`, консумация, re-key `K_session'`,
  продолжение `seq` без сброса, восстановление окна дедупа у нового узла.
* **Прод-путь кадра**: `policy-engine → Session → QuicBinding → encode_frame → datagram`
  и обратное вскрытие на зеркале — те же функции, что в `phase0-path`, но через UDP.

## Что это НЕ доказывает

* **Нагрузку**: 10 записей и localhost — ни перегрузки, ни потерь, ни reordering.
* **Множественных пиров**: один клиент, один поток, одна сессия.
* **Потери пакетов и RTT**: QUIC-ретрансмиссии в прогоне не срабатывают (localhost не
  теряет датаграммы); поведение при потерях — за пределами прогона.
* **Outer-обложку против DPI**: сертификат самоподписанный, TOFU-пин из манифеста;
  трафик не проверялся классификатором.
* **Production-конфигурацию**: ключи из фиксированных seed'ов CLI, порты фиксированные,
  consumed-set тикетов in-memory (`§3.6`), в нескольких процессах N2 эпоха-ключ одинаковый
  потому что задан вручную.

## Отхождения от спеки в лаборатории (не правки спеки)

1. **Mint-запрос расширен лабораторными полями** (`sid ‖ client_auth ‖ last_seq`):
   `Rotation::request_ticket` в проде несёт только `kind ‖ node_id` — узел берёт sid/клиента
   из авторизованного набора и своего handshake-состояния. Здесь у узла нет session-store,
   поэтому клиент передаёт их явно. Формат `kind(0x01) ‖ node_id` сохранён, расширение
   снаружи (`ext_len`).
2. ~~RESUME_ACK собирается в `e2e-harness`, а не в прод-крейте~~ **закрыто (BLOCKER-2,
   `QUESTIONS.md`)**: узловая сборка ACK поднята в `key-coordinator::build_resume_ack`
   — единственный прод-эмиттер; и `e2e-harness`, и мок `rotation-tests` теперь вызывают
   его, кадр в лаборатории не кодируется вручную. Провод не изменился: `kind(0x01) ‖
   nonce(24B) ‖ AEAD{K_resume}(...)` без `len` — спека приведена к проводу (см. ниже).
3. **`K_session` в mint-запросе не ходит**: узел, который провёл Noise_IK с клиентом,
   вывел ключ сам (`IkResponder::respond`). Ничего секретного по проводу не пересылается.

Protocol invariants `02-protocols.md` не правились (кроме признания len-less ACK в §3.3 —
закрытие BLOCKER-2 по прецеденту Q19, см. `QUESTIONS.md`). Расхождение, найденное при живом
прогоне, идёт в `QUESTIONS.md` как BLOCKER, а не в правку спеки.

**Повторный живой прогон после закрытия BLOCKER-2:** не выполнялся — локального тулчейна
на машине нет (`DEPENDENCIES.md`), провод байт-в-байт не изменился, эквивалентность
закреплена юнит-тестами: roundtrip эмиттер↔парсер в `key-coordinator` и все 7 сценариев
`rotation-tests` на прод-эмиттере.

## Зависимости лаборатории (не прод-пины)

`tokio` (рантайм бинов), `rustls 0.23` (TLS QUIC-лаборатории, фича `ring`), `rcgen 0.13`
(самоподписанный сертификат) — тянутся только `crates/e2e-harness` за фичей `e2e`;
прод-крейты их не видят, дуга Phase 0 не расширяется. `quinn` — тот же workspace-пин
0.11.12, что у `transport-mux`. В `DEPENDENCIES.md` добавлен раздел «E2E-лаборатория».

## CI

`cargo test --workspace --all-targets` гоняет юнит-тесты крейта (wire-framing, манифест,
lab-config, `quic_lab::endpoints_bind` — bind на `127.0.0.1:0`); `cargo clippy
-p e2e-harness --all-targets --all-features -- -D warnings` проверяет бины. Живой прогон
в CI не запускается: это ручной шаг (см. выше), но код бинов проверяется компиляцией
и lint'ом на каждый push.

## Статус CI

Основной rust-job зелёный на коммите `8ba9927` (run 35124640948): **91 passed / 0 failed /
0 ignored** по всему воркспейсу, включая 13 юнит-тестов `e2e-harness` без фичи, 15 с фичей
`e2e` (шаг best-effort, на раннере прошёл — bind на `127.0.0.1:0` разрешён) и 1 тест бина
узла; `cargo clippy --workspace --all-targets -- -D warnings` и `cargo clippy -p e2e-harness
--all-targets --all-features -- -D warnings` чисты. Сам живой прогон в CI не запускается —
это ручной шаг.
