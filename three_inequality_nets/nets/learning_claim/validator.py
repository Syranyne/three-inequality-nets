# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""窗口、训练集、标注和推理生效要分开核。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from three_inequality_nets.nets.catalog import LINKS
from three_inequality_nets.nets.common import evaluate_net, require_bool, require_text, signals_of


def semantic(payload: dict[str, Any], stage: str) -> list[str]:
    signals = signals_of(payload)
    if stage == "L1":
        return []
    if stage == "L2":
        reasons = require_bool(signals, stage, "in_dataset")
        if reasons:
            return reasons
        if signals["in_dataset"] is not True:
            return [f"{stage}:semantic"]
        return []
    if stage == "L3":
        reasons = require_text(signals, stage, "annotator") + require_text(signals, stage, "proposer")
        reasons += require_bool(signals, stage, "label_matches") + require_bool(signals, stage, "level_matches")
        if reasons:
            return reasons
        if signals["annotator"] == signals["proposer"]:
            return [f"{stage}:semantic"]
        if signals["label_matches"] is not True or signals["level_matches"] is not True:
            return [f"{stage}:semantic"]
        return []
    reasons = require_bool(signals, stage, "prompt_contains_answer") + require_bool(signals, stage, "held_out_improved")
    if reasons:
        return reasons
    if signals["prompt_contains_answer"] is True or signals["held_out_improved"] is not True:
        return [f"{stage}:semantic"]
    return []


def evaluate(payload: Any, root: Path) -> dict[str, Any]:
    return evaluate_net(payload, root, "learning_claim", LINKS["learning_claim"], semantic)
