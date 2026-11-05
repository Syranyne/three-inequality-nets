# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""样品、可重复交付、用户价值和行业对照要分开核。"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

from three_inequality_nets.core.attest import attest
from three_inequality_nets.core.claim import binding as claim_binding
from three_inequality_nets.core.schema import file_sha256, is_sha256, is_text, stable_relative
from three_inequality_nets.nets.catalog import LINKS, PRODUCTION_THRESHOLDS
from three_inequality_nets.nets.common import evaluate_net, require_bool, signals_of


def _number(value: Any) -> bool:
    return type(value) in (int, float) and not isinstance(value, bool) and math.isfinite(value)


def _thresholds(payload: dict[str, Any]) -> dict[str, Any]:
    overrides = payload.get("thresholds") if isinstance(payload.get("thresholds"), dict) else {}
    used: dict[str, Any] = {}
    for key, meta in PRODUCTION_THRESHOLDS.items():
        default = meta["value"]
        raw = overrides.get(key, default)
        if not _number(raw):
            raw = default
        # 只能收紧：取输入与默认值中更严的一个。
        value = max(float(raw), float(default)) if isinstance(default, float) else max(int(raw), int(default))
        used[key] = value
        used[f"{key}_status"] = "input_override" if key in overrides and value != default else meta["status"]
    return used


def _load_json(root: Path, relative: Any) -> Any | None:
    if not stable_relative(relative):
        return None
    path = root / str(relative)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None


def _verified_value(root: Path, block: Any, field: str = "value") -> tuple[float | None, list[str]]:
    if not isinstance(block, dict):
        return None, ["L4:benchmark_structure"]
    if field == "value" and not is_text(block.get("name")):
        return None, ["L4:benchmark_structure"]
    claimed = block.get("value") if field == "value" else block.get(field)
    if not _number(claimed):
        return None, ["L4:benchmark_structure"]
    if not stable_relative(block.get("source_ref")) or not is_sha256(block.get("source_sha256")):
        return None, ["L4:benchmark_structure"]
    path = root / str(block["source_ref"])
    if not path.is_file() or file_sha256(path).casefold() != str(block["source_sha256"]).casefold():
        return None, ["L4:benchmark_source"]
    data = _load_json(root, block["source_ref"])
    if not isinstance(data, dict) or not _number(data.get(field)):
        return None, ["L4:benchmark_source"]
    if float(data[field]) != float(claimed):
        return None, ["L4:benchmark_source"]
    return float(data[field]), []


def _producers(payload: dict[str, Any]) -> list[str]:
    """声称方的全部身份。证据条目的自报产出者已由 assess 核对与执行回执是同一 principal。"""
    names: list[str] = []
    stages = payload.get("stages") if isinstance(payload.get("stages"), dict) else {}
    for slot in stages.values():
        for item in (slot.get("evidence") if isinstance(slot, dict) and isinstance(slot.get("evidence"), list) else []):
            if isinstance(item, dict) and is_text(item.get("produced_by")):
                names.append(str(item["produced_by"]))
    return names


def benchmark_parts(name: Any, metric: str, value: Any, origin: Any) -> tuple[Any, ...]:
    return ("benchmark", name, metric, float(value), origin)


def _independent(
    root: Path, block: dict[str, Any], metric: str, claimants: list[str], bound: tuple[str, str] | None
) -> list[str]:
    """基线/竞品数值：只认名册 attester 对本次声明的签名，且与声称方不是同一 principal。"""
    data = _load_json(root, block.get("source_ref"))
    if not isinstance(data, dict) or not _number(data.get("value")):
        return ["L4:benchmark_source"]
    if not is_text(data.get("origin")):
        return ["L4:benchmark_not_independent"]
    failure = attest(root, bound, "attester", data.get("attested_by"), data.get("signature"),
                     benchmark_parts(block.get("name"), metric, data.get("value"), data.get("origin")),
                     claimants=claimants)
    if failure == "unbound":
        return ["L4:benchmark_binding"]
    if failure is not None:
        return ["L4:benchmark_not_independent"]
    return []


def _improved(ours: float, other: float, higher: bool, margin: float) -> bool:
    delta = (ours - other) if higher else (other - ours)
    if margin <= 0:
        return delta > 0
    scale = abs(other) if other != 0 else 1.0
    return (delta / scale) >= margin


def check_benchmark(payload: dict[str, Any], root: Path) -> list[str]:
    signals = signals_of(payload)
    block = signals.get("benchmark")
    if not isinstance(block, dict):
        return ["L4:signal_missing:benchmark"]
    for key in ("metric", "higher_is_better", "ours", "baseline", "competitors", "sample_size", "ours_source_ref", "ours_source_sha256"):
        if key not in block:
            return [f"L4:signal_missing:benchmark.{key}"]
    if not is_text(block["metric"]) or not isinstance(block["higher_is_better"], bool):
        return ["L4:benchmark_structure"]
    if not _number(block["ours"]) or type(block["sample_size"]) is not int or isinstance(block["sample_size"], bool):
        return ["L4:benchmark_structure"]
    if not isinstance(block["competitors"], list):
        return ["L4:benchmark_structure"]
    if not block["competitors"]:
        # 没有竞品就谈不上「行业竞争力」。
        return ["L4:benchmark_no_competitor"]
    opts = _thresholds(payload)
    if block["sample_size"] < int(opts["min_samples"]):
        return ["L4:benchmark_samples"]
    ours_block = {
        "name": "ours",
        "value": block["ours"],
        "source_ref": block["ours_source_ref"],
        "source_sha256": block["ours_source_sha256"],
    }
    ours_value, reasons = _verified_value(root, ours_block)
    if reasons:
        return reasons
    baseline_value, reasons = _verified_value(root, block["baseline"])
    if reasons:
        return reasons
    competitor_values: list[float] = []
    for row in block["competitors"]:
        value, reasons = _verified_value(root, row)
        if reasons:
            return reasons
        assert value is not None
        competitor_values.append(value)
    excluded = _producers(payload)
    bound = claim_binding(payload)
    ours_data = _load_json(root, block["ours_source_ref"])
    if isinstance(ours_data, dict) and is_text(ours_data.get("produced_by")):
        excluded.append(str(ours_data["produced_by"]))
    refs = [block["ours_source_ref"]]
    for row in [block["baseline"], *block["competitors"]]:
        if row.get("source_ref") in refs:
            return ["L4:benchmark_not_independent"]
        refs.append(row.get("source_ref"))
        reasons = _independent(root, row, str(block["metric"]), excluded, bound)
        if reasons:
            return reasons
    assert ours_value is not None and baseline_value is not None
    higher = block["higher_is_better"] is True
    margin = float(opts["min_margin"])
    if not _improved(ours_value, baseline_value, higher, margin):
        return ["L4:benchmark_margin"]
    if competitor_values:
        strongest = max(competitor_values) if higher else min(competitor_values)
        if not _improved(ours_value, strongest, higher, margin):
            return ["L4:benchmark_margin"]
    return []


def check_users(payload: dict[str, Any], root: Path) -> list[str]:
    signals = signals_of(payload)
    reasons = require_bool(signals, "L3", "real_user_signal") + require_bool(signals, "L3", "self_scored")
    if reasons:
        return reasons
    if signals["real_user_signal"] is not True or signals["self_scored"] is True:
        return ["L3:semantic"]
    source_ref = signals.get("user_signal_ref")
    source_sha = signals.get("user_signal_sha256")
    sample_size = signals.get("user_sample_size")
    if not stable_relative(source_ref) or not is_sha256(source_sha):
        return ["L3:signal_missing:user_signal_ref"]
    if type(sample_size) is not int or isinstance(sample_size, bool):
        return ["L3:signal_missing:user_sample_size"]
    path = root / str(source_ref)
    if not path.is_file() or file_sha256(path).casefold() != str(source_sha).casefold():
        return ["L3:user_signal_source"]
    data = _load_json(root, source_ref)
    if not isinstance(data, dict) or data.get("sample_size") != sample_size or sample_size < 1:
        return ["L3:user_signal_source"]
    if sample_size < int(_thresholds(payload)["min_user_samples"]):
        return ["L3:user_samples"]
    return []


def evaluate(payload: Any, root: Path) -> dict[str, Any]:
    def semantic(obj: dict[str, Any], stage: str) -> list[str]:
        signals = signals_of(obj)
        if stage == "L1":
            return []
        if stage == "L2":
            reasons = require_bool(signals, stage, "repeat_stable") + require_bool(signals, stage, "release_recorded")
            if reasons:
                return reasons
            if signals["repeat_stable"] is not True or signals["release_recorded"] is not True:
                return [f"{stage}:semantic"]
            return []
        if stage == "L3":
            return check_users(obj, root)
        return check_benchmark(obj, root)

    result = evaluate_net(payload, root, "production", LINKS["production"], semantic)
    if isinstance(payload, dict):
        result["thresholds"] = _thresholds(payload)
    return result
