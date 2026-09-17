#!/usr/bin/env bash
# boring-probe-env.sh — дополнение к local-env.sh для разведочной пробы boring
# (Reality-обложка, F11 из DEPENDENCIES.md). Проба живёт ВНЕ workspace:
# ~/Desktop/boring-probe/ (два независимых крейта со своими Cargo.lock). Этот скрипт
# ничего туда не пишет — только готовит окружение текущего шелла.
#
# СТАТУС b132: boring стал прод-зависимостью workspace (crates/cover-reality), и вся
# настройка (CMAKE_GENERATOR=Ninja, NASM, LIBCLANG_PATH + BINDGEN_EXTRA_CLANG_ARGS)
# переехала в scripts/local-env.sh — для работы workspace теперь достаточно одного
# local-env.sh. Этот скрипт остаётся историческим референсом пробы
# (docs/phase-reports/reality-boring-probe.md) и продолжает работать как раньше.
#
# Чего в local-env.sh нет и почему (каждое звено — реальный фейл холодной сборки
# boring-sys 4.22.0 на windows-gnu, проверено 2026-09-17):
#
#   CMAKE_GENERATOR=Ninja
#     boring-sys собирает BoringSSL через cmake-crate. Генератор по умолчанию на
#     MSYS/Git Bash — "MSYS Makefiles"/"Unix Makefiles", которые зовут sh; с busybox-sh
#     из w64devkit сгенерированные CMake make-скрипты ломаются. Ninja не использует
#     шелл — с ним сборка проходит (ninja.exe и cmake.exe лежат в w64devkit/bin,
#     их добавляет local-env.sh).
#
#   NASM 2.16.03 (портативный)
#     CMakeLists BoringSSL на x86_64 Windows требует NASM для perlasm-ассемблера;
#     без него конфигурация падает ("could NOT find NASM" / ASM_NASM not found).
#     В w64devkit nasm не входит. Достаточно zip с nasm.org, распакованного рядом
#     с пробой (см. BORING_PROBE_NASM_DIR).
#
#   LIBCLANG_PATH + BINDGEN_EXTRA_CLANG_ARGS
#     boring-sys генерирует FFI-биндинги bindgen'ом, которому нужен libclang.dll.
#     Системного LLVM на машине нет — берём готовую библиотеку из PyPI-колеса
#     `libclang` (pip download libclang, распаковать wheel): <dir>/clang/native/libclang.dll.
#     Без -target x86_64-pc-windows-gnu libclang парсит mingw-заголовки в режиме MSVC
#     и падает на mingw-специфичных атрибутах (__MINGW_NOTHROW и др.). Отдельные -I
#     нужны, потому что у libclang из колеса нет встроенных путей к заголовкам —
#     даём include w64devkit (+ внутренний include gcc, если есть).
#
# Использование (проба НЕ в workspace — сборить можно из любого её каталога):
#   source scripts/boring-probe-env.sh
#   cd ~/Desktop/boring-probe/probe-boring-rustls && cargo build          # debug
#   cargo build --release                                                 # release
#
# Переопределения (до source):
#   BORING_PROBE_DIR=/путь/к/boring-probe   source scripts/boring-probe-env.sh
#   BORING_PROBE_NASM_DIR=...               # дефолт: $BORING_PROBE_DIR/tools/nasm-2.16.03
#   BORING_PROBE_LIBCLANG_DIR=...           # дефолт: $BORING_PROBE_DIR/tools/libclang

# Скрипт предназначен ТОЛЬКО для source (как local-env.sh).
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "boring-probe-env: ОШИБКА: скрипт нужно source-ить, а не запускать:" >&2
  echo "  source scripts/boring-probe-env.sh && cd ~/Desktop/boring-probe/probe-boring-rustls" >&2
  exit 1
fi

_bpe_fail() {
  echo "boring-probe-env: ОШИБКА: $1" >&2
  if [[ $# -gt 1 ]]; then shift; printf '  %s\n' "$@" >&2; fi
}

_bpe_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# --- 0) база: local-env.sh (w64devkit в PATH => gcc/cmake/ninja, линкер rustup, RUSTFLAGS) ---
if [[ -z "${CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER:-}" ]]; then
  # shellcheck disable=SC1091
  source "$_bpe_root/scripts/local-env.sh" || return 1
fi

# --- 1) корень пробы (вне репо) ---
BORING_PROBE_DIR="${BORING_PROBE_DIR:-$HOME/Desktop/boring-probe}"
if [[ ! -d "$BORING_PROBE_DIR" ]]; then
  _bpe_fail "каталог пробы не найден: $BORING_PROBE_DIR" \
    "Клонируй/распакуй пробу или укажи: BORING_PROBE_DIR=/путь source scripts/boring-probe-env.sh"
  return 1
fi

# --- 2) NASM (портативный, в PATH) ---
BORING_PROBE_NASM_DIR="${BORING_PROBE_NASM_DIR:-$BORING_PROBE_DIR/tools/nasm-2.16.03}"
if [[ ! -x "$BORING_PROBE_NASM_DIR/nasm.exe" ]]; then
  _bpe_fail "nasm.exe не найден: $BORING_PROBE_NASM_DIR/nasm.exe" \
    "Скачай https://www.nasm.us/pub/nasm/releasebuilds/2.16.03/win64/nasm-2.16.03-win64.zip," \
    "распакуй в $BORING_PROBE_DIR/tools/ или укажи BORING_PROBE_NASM_DIR"
  return 1
fi
case ":$PATH:" in
  *":$BORING_PROBE_NASM_DIR:"*) ;;
  *) export PATH="$BORING_PROBE_NASM_DIR:$PATH" ;;
esac

# --- 3) libclang из PyPI-колеса + аргументы bindgen ---
BORING_PROBE_LIBCLANG_DIR="${BORING_PROBE_LIBCLANG_DIR:-$BORING_PROBE_DIR/tools/libclang}"
_bpe_libclang_native="$BORING_PROBE_LIBCLANG_DIR/clang/native"
if [[ ! -f "$_bpe_libclang_native/libclang.dll" ]]; then
  _bpe_fail "libclang.dll не найден: $_bpe_libclang_native/libclang.dll" \
    "pip download libclang -d /tmp/libclang-wheel, распаковать wheel (это zip) в" \
    "$BORING_PROBE_DIR/tools/libclang или укажи BORING_PROBE_LIBCLANG_DIR"
  return 1
fi
export LIBCLANG_PATH="$(cygpath -m "$_bpe_libclang_native")"   # C:/... — форма для clang-sys

if [[ ! -d "$W64DEVKIT_HOME/include" ]]; then
  _bpe_fail "не найдены заголовки w64devkit: $W64DEVKIT_HOME/include (W64DEVKIT_HOME задан local-env.sh)."
  return 1
fi
_bpe_args="-target x86_64-pc-windows-gnu -I$(cygpath -m "$W64DEVKIT_HOME/include")"
_bpe_gcc_inc="$(ls -d "$W64DEVKIT_HOME"/lib/gcc/x86_64-w64-mingw32/*/include 2>/dev/null | head -1)"
if [[ -n "$_bpe_gcc_inc" ]]; then
  _bpe_args="$_bpe_args -I$(cygpath -m "$_bpe_gcc_inc")"
fi
export BINDGEN_EXTRA_CLANG_ARGS="${BINDGEN_EXTRA_CLANG_ARGS:+$BINDGEN_EXTRA_CLANG_ARGS }$_bpe_args"

# --- 4) генератор CMake для BoringSSL (boring-sys) ---
export CMAKE_GENERATOR=Ninja

echo "boring-probe-env: экспортировано (поверх local-env.sh):"
echo "  CMAKE_GENERATOR            Ninja (busybox-sh из w64devkit ломает Makefiles-генераторы)"
echo "  PATH         + $BORING_PROBE_NASM_DIR  ($(nasm -v 2>/dev/null))"
echo "  LIBCLANG_PATH  $LIBCLANG_PATH  (PyPI-колесо libclang)"
echo "  BINDGEN_EXTRA_CLANG_ARGS  $_bpe_args"
echo "  дальше: cd $BORING_PROBE_DIR/probe-boring-rustls && cargo build"

unset _bpe_root _bpe_fail _bpe_libclang_native _bpe_args _bpe_gcc_inc
