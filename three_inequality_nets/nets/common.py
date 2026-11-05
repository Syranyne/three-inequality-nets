# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""每张网共用的信号、证据绑定、跳步与等级比较。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from three_inequality_nets.core.claim import binding as claim_binding
from three_inequality_nets.core.evidence import assess, level_rank
from three_inequality_nets.core.report import make_result
from three_inequality_nets.core.schema import is_text, stable_relative
from three_inequality_nets.nets.catalog import (
    EVIDENCE_ALLOWED_PREFIXES,
    EVIDENCE_BLOCKED_PREFIXES,
    EVIDENCE_CONTENT_NETS,
    EVIDENCE_KINDS,
    MIN_LEVELS,
    STAGES,
)
from three_inequality_nets.nets.outside import evaluate_outside

INPUT_SCHEMA = "fournets.net_input.v1"
# 返回原因码列表；空列表表示该阶段语义成立。
Semantic = Callable[[dict[str, Any], str], list[str]]


def signals_of(payload: dict[str, Any]) -> dict[str, Any]:
    signals = payload.get("signals")
    return signals if isinstance(signals, dict) else {}


def require_bool(signals: dict[str, Any], stage: str, key: str) -> list[str]:
    value = signals.get(key, object())
    if value is object() or not isinstance(value, bool):
        return [f"{stage}:signal_missing:{key}"]
    return []


def require_text(signals: dict[str, Any], stage: str, key: str) -> list[str]:
    value = signals.get(key)
    if not is_text(value):
        return [f"{stage}:signal_missing:{key}"]
    return []


def _stage_evidence(payload: dict[str, Any], stage: str) -> list[Any]:
    stages = payload.get("stages")
    if not isinstance(stages, dict):
        return []
    slot = stages.get(stage)
    if not isinstance(slot, dict):
        return []
    evidence = slot.get("evidence")
    if not isinstance(evidence, list):
        return []
    return evidence


def _path_allowed(relative: str) -> bool:
    if not stable_relative(relative):
        return False
    if any(relative == prefix.rstrip("/") or relative.startswith(prefix) for prefix in EVIDENCE_BLOCKED_PREFIXES):
        return False
    return any(relative.startswith(prefix) for prefix in EVIDENCE_ALLOWED_PREFIXES)


def _content_reasons(root: Path, net: str, stage: str, item: dict[str, Any]) -> list[str]:
    if net not in EVIDENCE_CONTENT_NETS:
        return []
    relative = item.get("path")
    if not is_text(relative) or not stable_relative(relative):
        return []
    path = root / str(relative)
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return [f"{stage}:evidence_content"]
    if not isinstance(data, dict) or data.get("evidence_kind") != item.get("kind") or data.get("stage") != stage:
        return [f"{stage}:evidence_content"]
    return []


def _evidence_binding_reasons(net: str, stage: str, item: Any, seen_digests: dict[str, str], root: Path | None = None) -> list[str]:
    reasons: list[str] = []
    if not isinstance(item, dict):
        return [f"{stage}:evidence_kind"]
    kind = item.get("kind")
    allowed = EVIDENCE_KINDS.get(net, {}).get(stage, frozenset())
    if not is_text(kind) or kind not in allowed:
        reasons.append(f"{stage}:evidence_kind")
    relative = item.get("path")
    digest = item.get("sha256")
    if is_text(relative):
        if not _path_allowed(str(relative)):
            reasons.append(f"{stage}:evidence_location")
    if root is not None:
        reasons.extend(_content_reasons(root, net, stage, item))
    if is_text(digest):
        prior = seen_digests.get(str(digest).casefold())
        if prior is not None and prior != stage:
            reasons.append("evidence_reused_across_stages")
        else:
            seen_digests[str(digest).casefold()] = stage
    return reasons


def evaluate_net(
    payload: Any,
    root: Path,
    net: str,
    links: tuple[str, str, str],
    semantic: Semantic,
    min_levels: dict[str, str] | None = None,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return make_result(net, "FAIL", links[0], None, "L0", ["root_not_object"])
    claimed = payload.get("claimed_level")
    if payload.get("schema_version") != INPUT_SCHEMA or payload.get("net") != net:
        return make_result(net, "FAIL", None, claimed, None, ["schema"])
    if payload.get("outside_model") is True:
        return evaluate_outside(
            payload,
            root,
            net,
            links,
            lambda normal: evaluate_net(normal, root, net, links, semantic, min_levels),
        )
    if claimed not in STAGES:
        return make_result(net, "FAIL", None, claimed, None, ["claimed_level"])

    levels = min_levels if min_levels is not None else MIN_LEVELS.get(net, {})
    reasons: list[str] = []
    supported: list[bool] = []
    seen_digests: dict[str, str] = {}
    bound = claim_binding(payload)
    if bound is None:
        return make_result(net, "FAIL", links[0], claimed, "L0", ["claim_unbound"])
    for stage in STAGES:
        items = _stage_evidence(payload, stage)
        if not items:
            supported.append(False)
            continue
        stage_ok = True
        for item in items:
            bind_reasons = _evidence_binding_reasons(net, stage, item, seen_digests, root)
            reasons.extend(bind_reasons)
            if bind_reasons:
                stage_ok = False
            minimum = levels.get(stage, "artifact")
            level, item_reasons, forged = assess(item, root, bound)
            reasons.extend(f"{stage}:{reason}" for reason in item_reasons)
            if forged or level_rank(level) < level_rank(minimum):
                stage_ok = False
                if levels is not None and not forged:
                    reasons.append(f"{stage}:evidence_below_{minimum}")
        if stage_ok:
            semantic_reasons = semantic(payload, stage)
            if semantic_reasons:
                stage_ok = False
                reasons.extend(semantic_reasons)
        supported.append(stage_ok)

    proven = 0
    for ok in supported:
        if ok:
            proven += 1
        else:
            break
    later_filled = False
    for index, stage in enumerate(STAGES):
        if index > proven and _stage_evidence(payload, stage):
            later_filled = True
            break
    if later_filled:
        reasons.append("later_evidence_does_not_backfill")

    claimed_rank = STAGES.index(claimed) + 1
    proven_label = "L0" if proven == 0 else f"L{proven}"
    if claimed_rank > proven:
        broken = links[0] if proven == 0 else links[proven - 1]
        if later_filled and "skip_gap" not in reasons:
            reasons.append("skip_gap")
        reasons.append("claimed_above_proven")
        return make_result(net, "FAIL", broken, claimed, proven_label, reasons)
    return make_result(net, "PASS", None, claimed, proven_label, reasons)
