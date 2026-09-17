# Reality-обложка: проба линковки boring (шаги 1–3 из 5)

**Дата прогона:** 2026-09-17 · **Крейт:** `boring 4.22.0` (cloudflare/boring) · **Тулчейн:** `stable-x86_64-pc-windows-gnu` (rustc 1.98.1)
**Статус:** РАЗВЕДКА — вопрос F11 «два libcrypto в одном дереве (конфликт символов с rustls/ring)» из `DEPENDENCIES.md`.

Это разведка, не прод-зависимость: `boring` **не** добавлен в workspace `Cargo.toml`,
в `crates/` нет никаких изменений. Всё хозяйство пробы — вне репо, в
`~/Desktop/boring-probe/` (два независимых крейта со своими `Cargo.lock`; workspace
репозитория не тронут — проба собиралась из своего каталога, lock-файлы у неё свои).

## Вопрос пробы

F11 зафиксирован буквально: «**EXISTS** (cloudflare/boring: 4.x stable…) Риск: два
libcrypto в одном дереве (конфликт символов с rustls/ring)». Это открытый риск
линковки, а не «отклонено» — ниже он **снят** для локального тулчейна windows-gnu:
boring линкуется чисто рядом с rustls/ring в одном бинаре (debug и release).

## Шаг 1 — план пробы

Две независимые сборки вне workspace, обе — **реальные вызовы** boring (не «импорт
для линковки», чтобы объектники гарантированно втянулись):

| Проба | Зависимости | Что делает |
|---|---|---|
| `probe-boring-only` | `boring = "4"` | `boring::sha::sha256` (libcrypto) + `SslConnector::builder(SslMethod::tls())` с ALPN (libssl) |
| `probe-boring-rustls` | `boring = "4"` + `rustls 0.23` (default-features = false, features = `[ring, std, tls12]`) + `ring 0.17` | всё то же + сверка SHA-256 boring vs ring, ECDSA-подпись ring, `rustls::crypto::ring::default_provider().install_default()`, сборка `ClientConfig` |

Набор rustls-фич в пробе повторяет прод-стек лаборатории (`crates/e2e-harness`):
тот же провайдер (`ring`), который реально едет в прод-пинах quinn/rustls.

## Шаг 2 — тулчейн: чего не хватало сверх `scripts/local-env.sh`

`local-env.sh` даёт базу (w64devkit-gcc в PATH, self-contained линкер rustup,
RUSTFLAGS/CFLAGS для PQ-shim) — её хватает workspace-пинам. Для boring-sys её
недостаточно; каждое из трёх звеньев ниже — реальный фейл холодной сборки:

1. **`CMAKE_GENERATOR=Ninja`.** boring-sys собирает BoringSSL через cmake-crate.
   Генератор по умолчанию на MSYS/Git Bash — Makefiles-вариант, зовущий `sh`;
   с busybox-sh из w64devkit сгенерированные CMake make-скрипты ломаются.
   Ninja шелл не использует — с ним собирается. `ninja.exe` и `cmake.exe` уже
   лежат в `w64devkit/bin` (добавляются local-env.sh), ставить ничего не нужно.
   Подтверждение по артефактам: `CMakeCache.txt` пробы —
   `CMAKE_GENERATOR:INTERNAL=Ninja`.
2. **NASM 2.16.03 (портативный).** CMakeLists BoringSSL на x86_64 Windows требует
   NASM для perlasm-ассемблера; без него конфигурация падает (`ASM_NASM not found`).
   В w64devkit nasm не входит. Достаточно zip `nasm-2.16.03-win64.zip` с nasm.org,
   распакованного в `Desktop/boring-probe/tools/nasm-2.16.03/` (nasm.exe + ndisasm.exe).
3. **`LIBCLANG_PATH` + `BINDGEN_EXTRA_CLANG_ARGS`.** boring-sys генерирует FFI
   bindgen'ом, которому нужен `libclang.dll`. Системного LLVM на машине нет —
   использована готовая библиотека из PyPI-колеса `libclang`
   (`pip download libclang`, wheel — это zip; распакован в
   `Desktop/boring-probe/tools/libclang/clang/native/libclang.dll`, версия 18.1.1).
   Без `-target x86_64-pc-windows-gnu` libclang парсит mingw-заголовки в режиме MSVC
   и падает на mingw-специфичных атрибутах (`__MINGW_NOTHROW` и др.). Отдельные `-I`
   нужны, потому что у libclang из колеса нет встроенных путей к заголовкам:
   `-I<w64devkit>/include` + `-I<w64devkit>/lib/gcc/x86_64-w64-mingw32/<ver>/include`
   (внутренний include gcc).

### Воспроизведение

Вспомогательный скрипт **`scripts/boring-probe-env.sh`** (в репо, вне crates/)
дополняет local-env.sh — он `source`-ит его и добавляет только недостающее,
ничего не дублируя. Explicit-fail по образцу local-env.sh: любой отсутствующий
компонент — понятная ошибка с подсказкой. Он не пишет ничего в каталог пробы —
только экспортирует переменные текущего шелла.

```bash
cd /путь/к/репо
source scripts/boring-probe-env.sh          # тянет local-env.sh, затем добавляет своё
# дальше — сборка пробы из её собственного каталога (вне workspace):
cd ~/Desktop/boring-probe/probe-boring-rustls
cargo build                                  # debug
cargo build --release                        # release
./target/debug/probe-boring-rustls.exe       # и то же для probe-boring-only
```

Полный набор переменных, который в итоге должен стоять в окружении
(если делать руками без скрипта):

```bash
source scripts/local-env.sh                  # база: PATH+w64devkit, LINKER, RUSTFLAGS, CFLAGS
export CMAKE_GENERATOR=Ninja
export PATH="$HOME/Desktop/boring-probe/tools/nasm-2.16.03:$PATH"
export LIBCLANG_PATH="$HOME/Desktop/boring-probe/tools/libclang/clang/native"   # C:/... форма
export BINDGEN_EXTRA_CLANG_ARGS="-target x86_64-pc-windows-gnu \
 -I$(cygpath -m "$HOME/w64devkit/include") \
 -I$(cygpath -m "$HOME/w64devkit/lib/gcc/x86_64-w64-mingw32/16.2.0/include)"
```

Переопределения скрипта (до source): `BORING_PROBE_DIR` (дефолт
`~/Desktop/boring-probe`), `BORING_PROBE_NASM_DIR`, `BORING_PROBE_LIBCLANG_DIR`.

## Шаг 3 — результат

| Проверка | Результат |
|---|---|
| `probe-boring-only`, cargo build (debug) | ✅ собралось чисто, 0 предупреждений линковщика |
| `probe-boring-rustls`, cargo build (debug) | ✅ оба TLS-стека в одном бинаре, конфликтов символов нет |
| `probe-boring-rustls`, cargo build --release | ✅ release-профиль линкуется чисто |
| Прогон `probe-boring-rustls` (реальные вызовы обоих стеков) | ✅ boring `sha256[:8]`, коннектор с ALPN, сверка `СОВПАДАЮТ` с ring, ring ECDSA-подпись, `ClientConfig` на ring-провайдере |
| Символьный аудит exe | ✅ в бинаре присутствуют символы **обоих** стеков (`BoringSSL`* / boring-sys объектники и `ring`/rustls) — обе статические библиотеки реально втянуты, дубликатов не подхватилось |
| SHA-256 boring vs ring | ✅ совпадают байт в байт на общем входе (проверяется в рантайме `assert_eq!`) |

Вывод шагов 1–3: **линкуется чисто**, символьный конфликт boring/ring/rustls
не материализовался на x86_64-pc-windows-gnu (rustc 1.98.1, w64devkit GCC 16.2.0).

## Что дальше (шаги 4–5)

Живой TLS-handshake в одном процессе с активным ring/rustls и архитектурная
карточка «boring embedded vs Go-sidecar» — следующие шаги той же разведки;
обновления пишутся в этот файл.
