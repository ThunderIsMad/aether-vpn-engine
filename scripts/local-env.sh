#!/usr/bin/env bash
# local-env.sh — воспроизводимое локальное окружение сборки/тестов (Windows, toolchain windows-gnu).
#
# Зачем: прод-пины clatter (PQClean) и quinn (rustls, фича ring) содержат C-код. Для него
# cc-rs ищет gcc.exe в PATH. На машине прогона компилятор — портативный w64devkit, он НЕ в
# системном PATH, поэтому «сырой» прогон падает на build-script'ах ring/pqcrypto-internals
# ("failed to find tool \"gcc.exe\""), а частично собранный воркспейс тихо проходит только
# крейты без crypto-транзитива (23 теста вместо 85). Линкер — self-contained gcc из
# rustup-тулчейна: gcc.exe из w64devkit для линковки rustc-бинарей не годится
# (не находит -lgcc_eh; у rustup лежит в lib/self-contained).
#
# Проверено 2026-09-17 на HEAD: cargo test --workspace --all-targets → 85 passed;
# cargo test -p e2e-harness --all-features → 15 lib + 1 bin. Подробности — DEPENDENCIES.md
# → «Local Rust toolchain (Windows/GNU)».
#
# Философия: explicit-fail. Любой отсутствующий компонент — понятная ошибка и подсказка,
# не тихая деградация до «23 теста прошли, остальные не собрались».
#
# Использование:
#   source scripts/local-env.sh
#   cargo test --workspace --all-targets        # как CI
#   cargo test -p e2e-harness --all-features    # шаг best-effort из ci.yml (фича e2e)
#
# Переопределения (до source):
#   W64DEVKIT_HOME=/путь/к/w64devkit source scripts/local-env.sh
#   PQ_SHIM_DIR=/путь/к/шиму        source scripts/local-env.sh  # дефолт: tools/pq-shim в репо

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

# --- проверки (explicit-fail; каждый фейл = return 1 из source) ---
command -v rustc >/dev/null 2>&1 || {
  _local_env_fail "rustc не найден в PATH." "Установи rustup: https://rustup.rs"
  return 1
}

_local_env_host="$(rustc -vV 2>/dev/null | sed -n 's/^host: //p')"
if [[ "$_local_env_host" != "x86_64-pc-windows-gnu" ]]; then
  _local_env_fail "активный тулчейн '$_local_env_host', а скрипт настроен только для x86_64-pc-windows-gnu." \
    "Переключи: rustup default stable-x86_64-pc-windows-gnu"
  return 1
fi

_local_env_selfcont="$(rustc --print sysroot | tr '\\' '/')/lib/rustlib/x86_64-pc-windows-gnu"
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

echo "local-env: экспортировано:"
echo "  PATH      + $W64DEVKIT_HOME/bin  ($(gcc --version 2>/dev/null | head -1))"
echo "  CFLAGS    -I $_local_env_shim_win  (шим __GNUC_PREREQ для PQClean, версионируется в репо)"
echo "  LINKER    $_local_env_linker  (self-contained rustup: w64devkit-gcc линкером не годится, нет -lgcc_eh)"
echo "  RUSTFLAGS -L $_local_env_libdir"
echo "  дальше:   cargo test --workspace --all-targets"

unset _local_env_root _local_env_host _local_env_selfcont _local_env_linker \
      _local_env_libdir _local_env_shim_win _local_env_fail
