#!/usr/bin/env bash
set -Eeuo pipefail
REWARD_PATH="${HARBOR_REWARD_PATH:-/logs/verifier/reward.txt}"
write_zero() {
  mkdir -p "$(dirname "$REWARD_PATH")"
  if [[ "$REWARD_PATH" == "/logs/verifier/reward.txt" ]]; then
    printf '0\n' > /logs/verifier/reward.txt
  else
    printf '0\n' > "$REWARD_PATH"
  fi
}
trap 'write_zero; exit 1' ERR INT TERM HUP
write_zero
cd /tests
python3 -m pip install --no-cache-dir -q -r /tests/requirements.txt
python3 -m pytest --collect-only -q test_release.py
python3 run_weighted_tests.py
trap - ERR INT TERM HUP
