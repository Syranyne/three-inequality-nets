# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""发送者、语义作者、事实主张、写入授权要分开核。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from three_inequality_nets.nets.catalog import LINKS
from three_inequality_nets.nets.common import evaluate_net, require_bool, require_text, signals_of


def semantic(payload: dict[str, Any], stage: str) -> list[str]:
    signals = signals_of(payload)
    if stage == "L1":
        # L1 成立靠证据 kind 白名单（common），此处不再恒 True。
        return []
    if stage == "L2":
        reasons = require_text(signals, stage, "sender") + require_text(signals, stage, "author")
        reasons += require_bool(signals, stage, "treat_sender_as_author")
        if reasons:
            return reasons
        if signals["treat_sender_as_author"] is True and signals["sender"] != signals["author"]:
            return [f"{stage}:semantic"]
        return []
    if stage == "L3":
        reasons = require_bool(signals, stage, "asserted_as_fact")
        if reasons:
            return reasons
        if signals["asserted_as_fact"] is True:
            reasons = require_bool(signals, stage, "fact_checked")
            if reasons:
                return reasons
            if signals["fact_checked"] is not True:
                return [f"{stage}:semantic"]
        return []
    reasons = require_bool(signals, stage, "injected_authorization")
    reasons += require_bool(signals, stage, "write_attempted")
    if reasons:
        return reasons
    if signals["injected_authorization"] is True:
        return [f"{stage}:semantic"]
    if signals["write_attempted"] is True:
        reasons = require_bool(signals, stage, "approval_covers_key")
        if reasons:
            return reasons
        if signals["approval_covers_key"] is not True:
            return [f"{stage}:semantic"]
    return []


def evaluate(payload: Any, root: Path) -> dict[str, Any]:
    return evaluate_net(payload, root, "authority", LINKS["authority"], semantic)
