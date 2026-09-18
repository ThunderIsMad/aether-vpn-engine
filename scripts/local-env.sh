#!/usr/bin/env bash
# local-env.sh — воспроизводимое локальное окружение сборки/тестов (Windows, toolchain windows-gnu).
#
# Зачем: прод-пины clatter (PQClean), quinn (rustls, фича ring) и boring (BoringSSL, cover-reality)
# содержат C/C++ код. Для него cc-rs ищет gcc.exe в PATH. На машине прогона компилятор —
# портативный w64devkit, он НЕ в системном PATH, поэтому «сырой» прогон падает на build-script'ах
# ring/pqcrypto-internals/boring-sys ("failed to find tool \"gcc.exe\""), а частично собранный
# воркспейс тихо проходит только крейты без crypto-транзитива. Линкер — self-contained gcc из
# rustup-тулчейна: gcc.exe из w64devkit для линковки rustc-бинарей не годится
# (не находит -lgcc_eh; у rustup лежит в lib/self-contained).
#
# С b132 (cover-reality) boring — прод-зависимость workspace, поэтому здесь же настраивается
# всё, что нужно boring-sys на Windows/GNU (раньше это был отдельный boring-probe-env.sh для
# пробы вне репо; рецепт — docs/phase-reports/reality-boring-probe.md):
#   CMAKE_GENERATOR=Ninja      — MSYS Makefiles ломается о busybox-sh из w64devkit;
#   NASM 2.16.03 в PATH        — CMakeLists BoringSSL требует ASM_NASM на Windows x86_64;
#   LIBCLANG_PATH + BINDGEN_EXTRA_CLANG_ARGS — bindgen без -target парсит mingw-заголовки
#     в режиме MSVC и падает на __MINGW_NOTHROW; libclang — PyPI-колесо (см. BORING_TOOLS_DIR).
#
# Философия: explicit-fail. Любой отсутствующий компонент — понятная ошибка и подсказка,
# не тихая деградация до «23 теста прошли, остальные не собрались».
#
# F-11 (перевыпуск): rust-toolchain.toml пинит только ВЕРСИЮ компилятора. Host-триплет в
# том файле rustup на Linux читает как non-host toolchain («requires an emulator») и в
# пути авто-установки из override'а качает компилятор ЧУЖОЙ платформы (Windows) — см.
# rust-toolchain.toml и ci.yml → «Verify toolchain pin (linux)». Здесь host известен:
# из версии в файле собирается RUSTUP_TOOLCHAIN=<версия>-x86_64-pc-windows-gnu, а
# проверка хоста ниже из «предусловия» стала пост-условием пина.
#
# Использование:
#   source scripts/local-env.sh
#   cargo test --workspace --all-targets        # как CI
#   cargo test -p e2e-harness --all-features    # шаг best-effort из ci.yml (фича e2e)
#
# Переопределения (до source):
#   W64DEVKIT_HOME=/путь/к/w64devkit source scripts/local-env.sh
#   PQ_SHIM_DIR=/путь/к/шиму        source scripts/local-env.sh  # дефолт: tools/pq-shim в репо
#   BORING_TOOLS_DIR=/путь/к/tools  source scripts/local-env.sh  # дефолт: ~/Desktop/boring-probe/tools
#     (там лежат портативные nasm-2.16.03/ и libclang/clang/native/libclang.dll из пробы)

# Скрипт предназначен ТОЛЬКО для source: он экспортирует переменные в текущий шелл.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "local-env: ОШИБКА: скрипт нужно source-ить, а не запускать:" >&2
  echo "  source scripts/local-env.sh && cargo test --workspace --all-targets" >&2
  exit 1
fi

# Печатает понятную ошибку. Вызывающий код обязан сделать `return 1` (abort source) сам.
_local_env_fail() {
  echo "local-env: ОШИБКА: $1" >&2
  if [[ $# -gt 1 ]]; then shift; printf '  %s\n' "$@" >&2; fi
}

_local_env_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# --- настраиваемые пути (дефолты разумные, ничего не хардкодится) ---
W64DEVKIT_HOME="${W64DEVKIT_HOME:-$HOME/w64devkit}"
PQ_SHIM_DIR="${PQ_SHIM_DIR:-$_local_env_root/tools/pq-shim}"

# --- тулчейн: версия — из rust-toolchain.toml, host — ответственность этого скрипта ----
# Единый источник версии: читаем channel из того же файла, что видит rustup. Триплет здесь
# запрещён явно — если он вернётся в файл, ломать будет CI, а не эту машину.
# awk, а не `sed | head`: одиночный процесс, первая же строка channel, никакой гонки SIGPIPE
# (у вызывающего шелла может быть включён pipefail, и пустая подстановка выглядела бы как
# «не прочитал channel» — диагноз не по адресу).
_local_env_channel="$(awk -F'"' '/^[[:space:]]*channel[[:space:]]*=/{print $2; exit}' \
  "$_local_env_root/rust-toolchain.toml")"
if [[ -z "$_local_env_channel" ]]; then
  _local_env_fail "не прочитал channel из $_local_env_root/rust-toolchain.toml" \
    "Ожидается строка вида: channel = \"1.98.1\""
  return 1
fi
if [[ "$_local_env_channel" =~ -(x86_64|i686|aarch64|armv7|arm|s390x|powerpc64|riscv64)- ]]; then
  _local_env_fail "channel в rust-toolchain.toml несёт host-триплет: '$_local_env_channel'" \
    "Файл должен нести только версию: на Linux rustup читает такой канал как non-host" \
    "toolchain и качает компилятор чужой платформы. Host задаёт этот скрипт."
  return 1
fi

_local_env_toolchain="${_local_env_channel}-x86_64-pc-windows-gnu"

# Уже выставленный RUSTUP_TOOLCHAIN молча не перетираем: либо он совпадает с пином (no-op),
# либо это осознанное отклонение от воспроизводимости — пусть будет названо вслух.
if [[ -n "${RUSTUP_TOOLCHAIN:-}" && "$RUSTUP_TOOLCHAIN" != "$_local_env_toolchain" ]]; then
  _local_env_fail "RUSTUP_TOOLCHAIN='$RUSTUP_TOOLCHAIN' конфликтует с пином '$_local_env_toolchain'." \
    "Сними переменную и запусти source заново: unset RUSTUP_TOOLCHAIN"
  return 1
fi
export RUSTUP_TOOLCHAIN="$_local_env_toolchain"

# --- проверки (explicit-fail; каждый фейл = return 1 из source) ---
command -v rustc >/dev/null 2>&1 || {
  _local_env_fail "rustc не найден в PATH." "Установи rustup: https://rustup.rs"
  return 1
}

# Пост-условие пина: активный host — windows-gnu. На этом держится вся обвязка ниже
# (sysroot, self-contained линкер), поэтому проверяем не «что-нибудь стоит», а именно пин.
_local_env_host="$(rustc -vV 2>/dev/null | sed -n 's/^host: //p')"
if [[ "$_local_env_host" != "x86_64-pc-windows-gnu" ]]; then
  _local_env_fail "активный тулчейн '$_local_env_host', ожидался x86_64-pc-windows-gnu ($_local_env_toolchain)." \
    "Установи пин: rustup toolchain install $_local_env_toolchain"
  return 1
fi

# b132: sysroot в bash-подстановке, не через внешний `tr`: в PATH тестируемой машины
# w64devkit стоит первым, а его busybox-tr НЕ транслирует `\`→`/` (молча оставляет как
# есть) — путь self-contained линкера ломался в `C:CUsers...` и source падал. Bash-
# расширение `${var//\\//}` от PATH не зависит.
_local_env_sysroot="$(rustc --print sysroot)"
_local_env_selfcont="${_local_env_sysroot//\\//}/lib/rustlib/x86_64-pc-windows-gnu"
_local_env_linker="$_local_env_selfcont/bin/self-contained/x86_64-w64-mingw32-gcc.exe"
_local_env_libdir="$_local_env_selfcont/lib/self-contained"

if [[ ! -x "$W64DEVKIT_HOME/bin/gcc.exe" ]]; then
  _local_env_fail "w64devkit не найден: $W64DEVKIT_HOME/bin/gcc.exe" \
    "Установи https://github.com/skeeto/w64devkit/releases (распаковать в ~/w64devkit)" \
    "или укажи путь: W64DEVKIT_HOME=/путь/к/w64devkit source scripts/local-env.sh"
  return 1
fi

if [[ ! -x "$_local_env_linker" ]]; then
  _local_env_fail "self-contained gcc не найден: $_local_env_linker" \
    "Переустанови тулчейн: rustup toolchain install stable-x86_64-pc-windows-gnu"
  return 1
fi

if [[ ! -f "$PQ_SHIM_DIR/features.h" ]]; then
  _local_env_fail "заглушка features.h не найдена: $PQ_SHIM_DIR/features.h" \
    "Она версионируется в репо (tools/pq-shim/); если репо урезан — задай PQ_SHIM_DIR"
  return 1
fi

# Пути с пробелами молча ломают -C linker / -L: fail-fast.
if [[ "$W64DEVKIT_HOME$PQ_SHIM_DIR$_local_env_linker" == *" "* ]]; then
  _local_env_fail "путь содержит пробел, rustc -C linker так не принимает." \
    "Поставь w64devkit/репо в путь без пробелов"
  return 1
fi

command -v cygpath >/dev/null 2>&1 || {
  _local_env_fail "cygpath не найден (нужен Git Bash/MSYS2 для конверсии путей в Windows-форму)."
  return 1
}

# --- экспорт ---
_local_env_shim_win="$(cygpath -m "$PQ_SHIM_DIR")"   # C:/... — форма, которую ест gcc.exe

export PATH="$W64DEVKIT_HOME/bin:$PATH"
export CFLAGS="-I $_local_env_shim_win"
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="$_local_env_linker"
export RUSTFLAGS="-L $_local_env_libdir"

# --- boring-sys (прод-зависимость с b132): Ninja + NASM + libclang/bindgen ---
BORING_TOOLS_DIR="${BORING_TOOLS_DIR:-$HOME/Desktop/boring-probe/tools}"

# 1) Ninja: MSYS Makefiles ломается о busybox-sh из w64devkit (cmake -E env не находит
#    cmake.exe: путь в POSIX-форме, sh из busybox не понимает). Ninja уже в w64devkit.
if [[ -z "${CMAKE_GENERATOR:-}" ]]; then
  export CMAKE_GENERATOR=Ninja
fi

# 2) NASM 2.16.03 (портативный): enable_language(ASM_NASM) в CMakeLists BoringSSL.
if [[ -x "$BORING_TOOLS_DIR/nasm-2.16.03/nasm.exe" ]]; then
  case ":$PATH:" in
    *":$BORING_TOOLS_DIR/nasm-2.16.03:"*) ;;
    *) export PATH="$BORING_TOOLS_DIR/nasm-2.16.03:$PATH" ;;
  esac
else
  _local_env_fail "nasm.exe не найден: $BORING_TOOLS_DIR/nasm-2.16.03/nasm.exe" \
    "Скачай https://www.nasm.us/pub/nasm/releasebuilds/2.16.03/win64/nasm-2.16.03-win64.zip" \
    "и распакуй в $BORING_TOOLS_DIR/ или укажи BORING_TOOLS_DIR"
  return 1
fi

# 3) libclang (PyPI-колесо) + аргументы bindgen: без -target x86_64-pc-windows-gnu clang
#    парсит mingw-заголовки в режиме MSVC и падает на __MINGW_NOTHROW.
_local_env_libclang_native="$BORING_TOOLS_DIR/libclang/clang/native"
if [[ -f "$_local_env_libclang_native/libclang.dll" ]]; then
  export LIBCLANG_PATH="$(cygpath -m "$_local_env_libclang_native")"
  _local_env_bindgen_args="-target x86_64-pc-windows-gnu"
  _local_env_gcc_inc="$(ls -d "$W64DEVKIT_HOME"/lib/gcc/x86_64-w64-mingw32/*/include 2>/dev/null | head -1)"
  _local_env_mingw_inc="$W64DEVKIT_HOME/x86_64-w64-mingw32/include"
  [[ -d "$_local_env_gcc_inc" ]] && _local_env_bindgen_args="$_local_env_bindgen_args -I$_local_env_gcc_inc"
  [[ -d "$_local_env_mingw_inc" ]] && _local_env_bindgen_args="$_local_env_bindgen_args -I$_local_env_mingw_inc"
  export BINDGEN_EXTRA_CLANG_ARGS="${BINDGEN_EXTRA_CLANG_ARGS:+$BINDGEN_EXTRA_CLANG_ARGS }$_local_env_bindgen_args"
else
  _local_env_fail "libclang.dll не найден: $_local_env_libclang_native/libclang.dll" \
    "pip download libclang -d /tmp/libclang-wheel, распаковать wheel (это zip) в" \
    "$BORING_TOOLS_DIR/libclang или укажи BORING_TOOLS_DIR"
  return 1
fi

echo "local-env: экспортировано:"
echo "  TOOLCHAIN $RUSTUP_TOOLCHAIN  (версия из rust-toolchain.toml + host этой платформы; rustc $(rustc --version 2>/dev/null | awk '{print $2}'))"
echo "  PATH      + $W64DEVKIT_HOME/bin + nasm-2.16.03  ($(gcc --version 2>/dev/null | head -1))"
echo "  CFLAGS    -I $_local_env_shim_win  (шим __GNUC_PREREQ для PQClean, версионируется в репо)"
echo "  LINKER    $_local_env_linker  (self-contained rustup: w64devkit-gcc линкером не годится, нет -lgcc_eh)"
echo "  RUSTFLAGS -L $_local_env_libdir"
echo "  BORING    CMAKE_GENERATOR=$CMAKE_GENERATOR  LIBCLANG_PATH=$LIBCLANG_PATH  BINDGEN_EXTRA_CLANG_ARGS=$BINDGEN_EXTRA_CLANG_ARGS"
echo "  дальше:   cargo test --workspace --all-targets"

unset _local_env_root _local_env_host _local_env_sysroot _local_env_selfcont _local_env_linker \
      _local_env_libdir _local_env_shim_win _local_env_fail \
      _local_env_libclang_native _local_env_bindgen_args _local_env_gcc_inc _local_env_mingw_inc \
      _local_env_channel _local_env_toolchain
