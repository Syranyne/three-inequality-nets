# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""检索命中、语义理解、权威裁决和施工结论要分开核。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from three_inequality_nets.nets.catalog import LINKS
from three_inequality_nets.nets.common import evaluate_net, require_bool, signals_of


def semantic(payload: dict[str, Any], stage: str) -> list[str]:
    signals = signals_of(payload)
    if stage == "L1":
        return []
    key = {
        "L2": "object_aligned",
        "L3": "current_authority",
        "L4": "conditions_met",
    }[stage]
    reasons = require_bool(signals, stage, key)
    if reasons:
        return reasons
    if signals[key] is not True:
        return [f"{stage}:semantic"]
    return []


def evaluate(payload: Any, root: Path) -> dict[str, Any]:
    return evaluate_net(payload, root, "retrieval", LINKS["retrieval"], semantic)
