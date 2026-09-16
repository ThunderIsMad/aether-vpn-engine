#!/usr/bin/env bash
# Ручной живой E2E-прогон Phase 1: два процесса aether-node (N1, N2) и aether-client
# на localhost через реальный QUIC (quinn). Не CI job: сети/порты раннера не
# гарантированы. CI проверяет этот код иначе: юнит-тесты крейта + clippy --all-features.
#
# Что делает:
#   1. собирает бины (cargo build -p e2e-harness --features e2e);
#   2. поднимает node1 и node2 (каждый пишет манифест: ключи + QUIC-сертификат);
#   3. ждёт оба манифеста, запускает клиента:
#      policy-engine → Noise_IK → 5 записей на N1 → mint ticket у N1 →
#      RESUME на N2 (прод ClientRotation, PoP + проверка sig_node) → re-key →
#      ещё 5 записей на N2 под K_session';
#   4. гасит узлы.
#
# Что смотреть в логах (критерии успеха — подробнее в docs/phase-reports/e2e-manual.md):
#   * [client] Noise_IK complete: K_session#=...  ==  [node1] handshake complete: K_session#=...;
#   * [node1] record seq=0..4 accepted;
#   * [node2] RESUME accepted ... re-key: K_session'#=...  ==  [client] re-key: K_session'#=...;
#   * [node2] record seq=5..9 accepted — нумерация продолжилась, окно дедупа восстановлено;
#   * ни одной строки rejected / malformed / DUPLICATE.
#
# Порт и seed'ы можно переопределить: PORT1=45100 PORT2=45101 ./scripts/e2e-manual.sh
set -euo pipefail

PORT1="${PORT1:-45100}"
PORT2="${PORT2:-45101}"
SEED_N1="${SEED_N1:-11aa22bb33cc44dd55ee66ff77aa88bb99cc00dd11ee22ff33aa44bb55cc66dd}"
SEED_N2="${SEED_N2:-aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899}"
OUT="$(mktemp -d)"
trap 'kill ${N1_PID:-} ${N2_PID:-} 2>/dev/null || true' EXIT

echo "── [1/4] сборка бинов ──────────────────────────────────────────────"
cargo build -p e2e-harness --features e2e

echo "── [2/4] запуск узлов: N1 на :${PORT1}, N2 на :${PORT2} ──────────────"
cargo run -q -p e2e-harness --features e2e --bin aether-node -- \
  "$PORT1" "$SEED_N1" "$OUT/n1.manifest" --node-id 1 >"$OUT/n1.log" 2>&1 &
N1_PID=$!
cargo run -q -p e2e-harness --features e2e --bin aether-node -- \
  "$PORT2" "$SEED_N2" "$OUT/n2.manifest" --node-id 2 >"$OUT/n2.log" 2>&1 &
N2_PID=$!

echo "── [3/4] ожидание манифестов и запуск клиента ──────────────────────"
for i in $(seq 1 50); do
  [ -f "$OUT/n1.manifest" ] && [ -f "$OUT/n2.manifest" ] && break
  sleep 0.2
done
[ -f "$OUT/n1.manifest" ] || { echo "node1 не поднялся:"; cat "$OUT/n1.log"; exit 1; }
[ -f "$OUT/n2.manifest" ] || { echo "node2 не поднялся:"; cat "$OUT/n2.log"; exit 1; }

# Клиент сам останавливается после пост-ротационных записей.
cargo run -q -p e2e-harness --features e2e --bin aether-client -- \
  "$OUT/n1.manifest" "$OUT/n2.manifest" --records 5 --after 5

echo "── [4/4] логи узлов ────────────────────────────────────────────────"
echo "──── node1 ($OUT/n1.log) ────"; cat "$OUT/n1.log"
echo "──── node2 ($OUT/n2.log) ────"; cat "$OUT/n2.log"
echo "артефакты прогона: $OUT (манифесты и логи можно удалить)"
