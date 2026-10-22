from __future__ import annotations

import os
import traceback

import pytest

from test_release import GROUPS

if abs(sum(weight for _, _, weight in GROUPS) - 1.0) > 1e-9:
    raise RuntimeError("invalid score weights")

passed = []
for test_id, fn, weight in GROUPS:
    try:
        outcome = pytest.main(["-q", f"test_release.py::{fn.__name__}", "--disable-warnings"])
        if outcome != pytest.ExitCode.OK:
            raise AssertionError(f"pytest returned {outcome.name}")
    except Exception:
        traceback.print_exc()
        passed.append((test_id, False, weight))
    else:
        passed.append((test_id, True, weight))

reward = sum(weight for _, ok, weight in passed if ok)
print("groups:", passed)
path = os.environ.get("HARBOR_REWARD_PATH", "/logs/verifier/reward.txt")
with open(path, "w", encoding="utf-8") as handle:
    handle.write(f"{reward:.6f}\n")
