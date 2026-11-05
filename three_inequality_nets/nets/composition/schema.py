# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""组合观测的字段和时间格式。"""

from __future__ import annotations

from datetime import datetime
import math
import re
from typing import Any
from three_inequality_nets.core.schema import stable_relative
from three_inequality_nets.nets.catalog import LINKS
from three_inequality_nets.nets.outside import record_fields, record_reasons
from three_inequality_nets.nets.composition.identity import identity_key

MIN_RUNS = 5
MIN_PASS_RATE = 0.8
MAX_JOINT_DROP = 0.1
MIN_CONFLICTS = 2
DEFAULT_THRESHOLDS = {
    "min_runs": MIN_RUNS,
    "min_pass_rate": MIN_PASS_RATE,
    "max_joint_drop": MAX_JOINT_DROP,
    "min_conflicts": MIN_CONFLICTS,
}
HANDLINGS = ("deferred", "degraded", "reported")
STAGES = ("L1", "L2", "L3", "L4")


def parse_time(value: str) -> datetime:
    """解析带时区的 ISO 8601。仍接受历史 Z 后缀；也接受 ±HH:MM。"""
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})",
        value,
    ):
        raise ValueError("timezone-aware ISO 8601 timestamp required")
    if value.endswith("Z"):
        return datetime.fromisoformat(value[:-1] + "+00:00")
    return datetime.fromisoformat(value)


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _identity(value: Any) -> bool:
    return _text(value) and bool(identity_key(value))


def _integer(value: Any) -> bool:
    return type(value) is int and value >= 0


def _number(value: Any) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _digest(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value) is not None


def _timestamp(value: Any) -> bool:
    try:
        parse_time(value)
    except (TypeError, ValueError, OverflowError):
        return False
    return True


def _list_of(check):
    return lambda value: isinstance(value, list) and all(check(item) for item in value)


def _object(value, fields, path, issues, optional=()):
    if not isinstance(value, dict):
        issues.append("schema:" + path)
        return False
    for key in sorted(set(value) - set(fields)):
        issues.append("schema:" + path + "." + str(key))
    for key, check in fields.items():
        if key not in value and key in optional:
            continue
        if key not in value or not check(value[key]):
            issues.append("schema:" + path + "." + key)
    return True


def _rows(value, path, issues):
    if not isinstance(value, list):
        issues.append("schema:" + path)
        return []
    return list(enumerate(value))


def _unique(values, path, issues):
    texts = [v for v in values if isinstance(v, str)]
    if len(texts) != len(set(texts)):
        issues.append("schema:" + path)


def _ordered(record, first, second, path, issues):
    if _timestamp(record.get(first)) and _timestamp(record.get(second)):
        if parse_time(record[first]) >= parse_time(record[second]):
            issues.append("schema:" + path + "." + second)


def thresholds(observations: dict) -> dict:
    return {**DEFAULT_THRESHOLDS, **observations.get("thresholds", {})}


def validate_observations(obj: Any) -> list[str]:
    issues: list[str] = []
    if not _object(obj, {
        "subject_id": _identity,
        "capabilities": _list_of(_text), "thresholds": lambda v: isinstance(v, dict),
        "solo": lambda v: isinstance(v, dict), "joint": lambda v: isinstance(v, dict),
        "policy": lambda v: v is None or isinstance(v, dict),
        "conflicts": lambda v: isinstance(v, list), "incidents": lambda v: isinstance(v, list),
    }, "observations", issues, optional=("thresholds",)):
        return issues
    caps = obj.get("capabilities", [])
    if _list_of(_text)(caps):
        if not 2 <= len(caps) <= 8 or len(set(caps)) != len(caps):
            issues.append("schema:observations.capabilities")
    else:
        caps = []
    opts = obj.get("thresholds", {})
    _object(opts, {
        "min_runs": lambda v: _integer(v) and DEFAULT_THRESHOLDS["min_runs"] <= v <= 1000,
        "min_pass_rate": lambda v: _number(v) and DEFAULT_THRESHOLDS["min_pass_rate"] <= v <= 1,
        "max_joint_drop": lambda v: _number(v) and 0 <= v <= DEFAULT_THRESHOLDS["max_joint_drop"],
        "min_conflicts": lambda v: _integer(v) and DEFAULT_THRESHOLDS["min_conflicts"] <= v <= 1000,
    }, "observations.thresholds", issues, optional=tuple(DEFAULT_THRESHOLDS))
    solo = obj.get("solo", {})
    if isinstance(solo, dict):
        for cap, row in solo.items():
            path = "observations.solo." + str(cap)
            if cap not in caps:
                issues.append("schema:" + path)
            if _object(row, {"runs": _integer, "passes": _integer, "run_ids": _list_of(_text)}, path, issues):
                if _integer(row.get("runs")) and _integer(row.get("passes")) and row["passes"] > row["runs"]:
                    issues.append("schema:" + path + ".passes")
    joint = obj.get("joint", {})
    if _object(joint, {"episodes": lambda v: isinstance(v, list)}, "observations.joint", issues):
        episodes = joint.get("episodes", [])
    else:
        episodes = []
    episode_ids, action_ids = [], []
    for index, row in _rows(episodes, "observations.joint.episodes", issues):
        path = f"observations.joint.episodes.{index}"
        if not _object(row, {
            "episode_id": _text, "spans": lambda v: isinstance(v, list),
            "actions": lambda v: isinstance(v, list),
        }, path, issues, optional=("actions",)):
            continue
        episode_ids.append(row.get("episode_id"))
        for offset, span in _rows(row.get("spans"), path + ".spans", issues):
            loc = f"{path}.spans.{offset}"
            if _object(span, {
                "capability": lambda v: _text(v) and v in caps,
                "start": _timestamp, "end": _timestamp, "passed": lambda v: type(v) is bool,
            }, loc, issues):
                _ordered(span, "start", "end", loc, issues)
        for offset, action in _rows(row.get("actions", []), path + ".actions", issues):
            loc = f"{path}.actions.{offset}"
            if _object(action, {
                "action_id": _text, "actor": _identity,
                "at": _timestamp,
            }, loc, issues):
                action_ids.append(action.get("action_id"))
    _unique(episode_ids, "observations.joint.episodes.episode_id", issues)
    _unique(action_ids, "observations.joint.episodes.actions.action_id", issues)
    policy = obj.get("policy")
    if policy is not None and _object(policy, {
        "policy_id": _text, "declared_at": _timestamp, "sha256": _digest,
        "order": _list_of(_text), "rules": lambda v: isinstance(v, list),
    }, "observations.policy", issues):
        pairs = []
        for index, rule in _rows(policy.get("rules"), "observations.policy.rules", issues):
            path = f"observations.policy.rules.{index}"
            if _object(rule, {
                "when": lambda v: _list_of(_text)(v) and len(v) == 2 and len(set(v)) == 2 and all(c in caps for c in v),
                "winner": lambda v: _text(v) and v in caps,
            }, path, issues):
                pair = rule.get("when")
                if _list_of(_text)(pair):
                    pairs.append(tuple(sorted(pair)))
                    if rule.get("winner") not in pair:
                        issues.append("schema:" + path + ".winner")
        if len(pairs) != len(set(pairs)):
            issues.append("schema:observations.policy.rules")
    conflict_ids = []
    for index, row in _rows(obj.get("conflicts"), "observations.conflicts", issues):
        path = f"observations.conflicts.{index}"
        if _object(row, {
            "conflict_id": _text, "episode_id": _text,
            "capabilities": lambda v: _list_of(_text)(v) and len(v) == 2 and len(set(v)) == 2 and all(c in caps for c in v),
            "injected": lambda v: type(v) is bool, "started_at": _timestamp,
            "expected_winner": lambda v: _text(v) and v in caps,
            "chosen": lambda v: _text(v) and v in caps,
            "loser_handling": lambda v: v in HANDLINGS,
        }, path, issues):
            conflict_ids.append(row.get("conflict_id"))
    _unique(conflict_ids, "observations.conflicts.conflict_id", issues)
    incident_ids = []
    for index, row in _rows(obj.get("incidents"), "observations.incidents", issues):
        path = f"observations.incidents.{index}"
        if not _object(row, {
            "incident_id": _text, "action_id": _text, "episode_id": _text,
            "consequence_at": _timestamp, "consequence_metric": _text,
            "baseline": _number, "observed": _number, "detected_at": _timestamp,
            "detected_by": _identity, "hints": lambda v: isinstance(v, list),
            "correction_action_id": _text, "corrected_at": _timestamp,
            "recheck": lambda v: isinstance(v, dict),
            "detection_log_ref": stable_relative, "detection_log_sha256": _digest,
        }, path, issues):
            continue
        incident_ids.append(row.get("incident_id"))
        _ordered(row, "consequence_at", "detected_at", path, issues)
        _ordered(row, "detected_at", "corrected_at", path, issues)
        for offset, hint in _rows(row.get("hints"), path + ".hints", issues):
            _object(
                hint,
                {"at": _timestamp, "source": _text, "from": _text},
                f"{path}.hints.{offset}",
                issues,
                optional=("from",),
            )
        rc = row.get("recheck")
        if _object(rc, {
            "at": _timestamp, "metric_value": _number,
            "tolerance": lambda v: _number(v) and v >= 0,
            "joint_episode_id": _text, "verified_by": _identity,
        }, path + ".recheck", issues):
            if _timestamp(row.get("corrected_at")) and _timestamp(rc.get("at")):
                if parse_time(row["corrected_at"]) >= parse_time(rc["at"]):
                    issues.append("schema:" + path + ".recheck.at")
    _unique(incident_ids, "observations.incidents.incident_id", issues)
    return list(dict.fromkeys(issues))


def validate_payload(obj: Any) -> list[str]:
    issues: list[str] = []
    if not _object(obj, {
        "schema_version": lambda v: v == "fournets.net_input.v1",
        "net": lambda v: v == "composition", "id": _text, "claim": _text,
        "claimed_level": lambda v: v in STAGES,
        "stages": lambda v: isinstance(v, dict),
        "observations": lambda v: isinstance(v, dict),
        "outside_model": lambda v: type(v) is bool,
        "unexplained": lambda v: True,
    }, "input", issues, optional=("id", "claim", "unexplained")):
        return issues
    issues.extend(validate_observations(obj.get("observations")))
    stages = obj.get("stages")
    if isinstance(stages, dict):
        _object(stages, {s: lambda v: isinstance(v, dict) for s in STAGES}, "stages", issues)
        for stage in STAGES:
            slot = stages.get(stage)
            if not _object(slot, {"evidence": lambda v: isinstance(v, list)}, "stages." + stage, issues):
                continue
            for index, evidence in _rows(slot.get("evidence"), "stages." + stage, issues):
                loc = f"stages.{stage}.evidence.{index}"
                if _object(evidence, {
                    "kind": _text, "path": stable_relative, "sha256": _digest, "produced_by": _identity,
                    "command": lambda v: _list_of(_text)(v) and bool(v),
                    "exit_code": lambda v: type(v) is int, "output_summary": _text,
                    "started_at": _timestamp, "finished_at": _timestamp, "timestamp": _timestamp,
                    "reviewed_by": _identity, "forged": lambda v: type(v) is bool,
                    "output_path": stable_relative, "output_sha256": _digest,
                    "review_path": stable_relative, "review_sha256": _digest,
                    "receipt_path": stable_relative, "receipt_sha256": _digest,
                }, loc, issues, optional=(
                    "command", "exit_code", "output_summary", "started_at", "finished_at", "timestamp",
                    "reviewed_by", "forged", "output_path", "output_sha256", "review_path", "review_sha256",
                    "receipt_path", "receipt_sha256",
                )):
                    if _timestamp(evidence.get("started_at")) and _timestamp(evidence.get("finished_at")):
                        if parse_time(evidence["started_at"]) > parse_time(evidence["finished_at"]):
                            issues.append("schema:" + loc + ".finished_at")
    if obj.get("outside_model") is True:
        fields = record_fields(obj, LINKS["composition"])
        issues.extend(record_reasons(fields))
        issues.extend("schema:unexplained" + ("." + field if field != "unexplained" else "") for field in fields)
    return list(dict.fromkeys(issues))
