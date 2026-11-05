# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""联合运行、冲突和纠偏的可复算断言。"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from three_inequality_nets.core.report import make_result
from three_inequality_nets.nets.outside import evaluate_outside
from three_inequality_nets.nets.composition.binding import canonical_bytes, binding_checks
from three_inequality_nets.nets.composition.identity import identity_key
from three_inequality_nets.nets.common import evaluate_net
from three_inequality_nets.nets.catalog import LINKS as NET_LINKS
from three_inequality_nets.nets.composition.schema import DEFAULT_THRESHOLDS, HANDLINGS, parse_time, thresholds, validate_payload

LINKS = NET_LINKS["composition"]
MIN_LEVELS = {"L1": "executed", "L2": "executed", "L3": "executed", "L4": "reviewed"}


def _result(reasons: list[str]) -> tuple[bool, list[str]]:
    return not reasons, list(dict.fromkeys(reasons))


def check_solo(payload: dict) -> tuple[bool, list[str]]:
    obs = payload["observations"]
    opts = thresholds(obs)
    reasons = []
    seen = set()
    for cap in obs["capabilities"]:
        row = obs["solo"].get(cap)
        if row is None:
            reasons.append("L1:solo_missing")
            continue
        runs, passes, ids = row["runs"], row["passes"], row["run_ids"]
        if runs < opts["min_runs"]:
            reasons.append("L1:solo_runs")
        if runs == 0 or passes / runs < opts["min_pass_rate"]:
            reasons.append("L1:solo_pass_rate")
        if len(ids) != runs or len(set(ids)) != len(ids) or seen.intersection(ids):
            reasons.append("L1:solo_run_ids")
        seen.update(ids)
    return _result(reasons)


def _solo_ids(obs: dict) -> set[str]:
    return {rid for row in obs["solo"].values() for rid in row["run_ids"]}


def _episode_reasons(obs: dict, episode: dict) -> list[str]:
    spans = episode["spans"]
    reasons = []
    caps = [span["capability"] for span in spans]
    if len(caps) != len(obs["capabilities"]) or set(caps) != set(obs["capabilities"]):
        reasons.append("L2:joint_coverage")
    if not spans or max(parse_time(s["start"]) for s in spans) >= min(parse_time(s["end"]) for s in spans):
        reasons.extend(["L2:joint_overlap", "L2:stitched_joint"])
    if episode["episode_id"] in _solo_ids(obs):
        reasons.extend(["L2:joint_solo_reuse", "L2:stitched_joint"])
    return reasons


def _contains(episode: dict, time: str) -> bool:
    spans = episode["spans"]
    moment = parse_time(time)
    return bool(spans) and all(parse_time(s["start"]) <= moment < parse_time(s["end"]) for s in spans)


def check_joint(payload: dict) -> tuple[bool, list[str]]:
    obs = payload["observations"]
    episodes = obs["joint"]["episodes"]
    opts = thresholds(obs)
    reasons = []
    if len(episodes) < opts["min_runs"]:
        reasons.append("L2:joint_runs")
    for episode in episodes:
        reasons.extend(_episode_reasons(obs, episode))
    for cap in obs["capabilities"]:
        passed = sum(
            any(span["capability"] == cap and span["passed"] for span in ep["spans"])
            for ep in episodes
        )
        rate = passed / len(episodes) if episodes else 0
        if rate < opts["min_pass_rate"]:
            reasons.append("L2:joint_pass_rate")
        solo = obs["solo"].get(cap)
        if solo is None or solo["runs"] == 0:
            reasons.append("L2:joint_solo_missing")
        elif solo["passes"] / solo["runs"] - rate > opts["max_joint_drop"] + 1e-12:
            reasons.append("L2:joint_drop")
    return _result(reasons)


def check_priority(payload: dict) -> tuple[bool, list[str]]:
    obs = payload["observations"]
    policy = obs["policy"]
    if policy is None:
        return False, ["L3:priority_policy_missing"]
    reasons = []
    caps, order = obs["capabilities"], policy["order"]
    if len(order) != len(caps) or set(order) != set(caps):
        reasons.append("L3:priority_order")
    body = {key: policy[key] for key in ("policy_id", "declared_at", "order", "rules")}
    policy_bytes = canonical_bytes(body)
    actual = hashlib.sha256(policy_bytes).hexdigest()
    evidence = payload["stages"]["L3"]["evidence"]
    bound = any(e.get("kind") == "priority-policy" and e.get("sha256", "").casefold() == actual for e in evidence)
    if actual != policy["sha256"].casefold() or not bound:
        reasons.append("L3:priority_policy_digest")
    conflicts = obs["conflicts"]
    if len(conflicts) < thresholds(obs)["min_conflicts"]:
        reasons.append("L3:priority_trials")
    if not any(row["injected"] for row in conflicts):
        reasons.append("L3:priority_injected")
    episodes = {ep["episode_id"]: ep for ep in obs["joint"]["episodes"]}
    for row in conflicts:
        if parse_time(policy["declared_at"]) >= parse_time(row["started_at"]):
            reasons.append("L3:policy_after_trial")
        pair = row["capabilities"]
        winner = next((rule["winner"] for rule in policy["rules"] if set(rule["when"]) == set(pair)), None)
        if winner is None and all(cap in order for cap in pair):
            winner = min(pair, key=order.index)
        if winner is None or row["expected_winner"] != winner or row["chosen"] != winner:
            reasons.append("L3:priority_winner")
        if row["loser_handling"] not in HANDLINGS:
            reasons.append("L3:priority_loser_handling")
        episode = episodes.get(row["episode_id"])
        if episode is None or _episode_reasons(obs, episode):
            reasons.append("L3:priority_episode")
        elif not _contains(episode, row["started_at"]):
            reasons.append("L3:priority_conflict_time")
    return _result(reasons)


def _subject_key(obs: dict) -> str:
    return identity_key(str(obs.get("subject_id", "")))


def _hint_from(hint: dict) -> str:
    value = hint.get("from", hint.get("source", ""))
    return identity_key(str(value)) if isinstance(value, str) else ""


def _detection_log_ok(row: dict, subject: str, root: Path) -> bool:
    ref = row.get("detection_log_ref")
    digest = row.get("detection_log_sha256")
    if not isinstance(ref, str) or not isinstance(digest, str):
        return False
    try:
        path = (root.resolve() / ref).resolve()
        base = root.resolve()
        if path != base and base not in path.parents:
            return False
        if not path.is_file():
            return False
        from three_inequality_nets.core.schema import file_sha256
        if file_sha256(path).casefold() != digest.casefold():
            return False
        detected_at = parse_time(row["detected_at"])
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            event = json.loads(line)
            if not isinstance(event, dict):
                continue
            if identity_key(str(event.get("actor", ""))) != subject:
                continue
            if event.get("type") != "detection":
                continue
            if parse_time(event["at"]) <= detected_at:
                return True
    except (OSError, UnicodeError, ValueError, OverflowError, json.JSONDecodeError, KeyError, TypeError):
        return False
    return False


def check_correction(payload: dict, root: Path | None = None) -> tuple[bool, list[str]]:
    obs = payload["observations"]
    incidents = obs["incidents"]
    if not incidents:
        return False, ["L4:correction_missing"]
    reasons = []
    subject = _subject_key(obs)
    if not subject:
        return False, ["L4:subject_missing"]
    episodes = {ep["episode_id"]: ep for ep in obs["joint"]["episodes"]}
    actions = {action["action_id"]: (ep, action) for ep in episodes.values() for action in ep.get("actions", [])}
    evidence = payload["stages"]["L4"]["evidence"]
    producers = {identity_key(item["produced_by"]) for item in evidence}
    for item in evidence:
        reviewer = item.get("reviewed_by")
        if isinstance(reviewer, str) and identity_key(reviewer) == identity_key(item["produced_by"]):
            reasons.append("L4:correction_reviewer")
        if isinstance(reviewer, str) and identity_key(reviewer) == subject:
            reasons.append("L4:correction_reviewer")
    reviewers = {item.get("reviewed_by") for item in evidence}
    base = root or Path(".")
    for row in incidents:
        rc = row["recheck"]
        times = [parse_time(row[key]) for key in ("consequence_at", "detected_at", "corrected_at")] + [parse_time(rc["at"])]
        if not all(first < second for first, second in zip(times, times[1:])):
            reasons.append("L4:correction_time_order")
        origin = actions.get(row["action_id"])
        if origin is None:
            reasons.append("L4:correction_action")
        else:
            ep, action = origin
            if identity_key(action["actor"]) != subject or ep["episode_id"] != row["episode_id"] or parse_time(action["at"]) > times[0] or not _contains(ep, action["at"]) or not _contains(ep, row["consequence_at"]):
                reasons.append("L4:correction_action")
        repair = actions.get(row["correction_action_id"])
        if repair is None:
            reasons.append("L4:correction_repair_action")
        else:
            ep, action = repair
            if identity_key(action["actor"]) != subject or row["action_id"] == action["action_id"] or parse_time(action["at"]) != times[2] or not _contains(ep, action["at"]):
                reasons.append("L4:correction_repair_action")
        if identity_key(row["detected_by"]) != subject:
            reasons.append("L4:correction_detection")
        if root is not None and not _detection_log_ok(row, subject, base):
            reasons.append("L4:correction_detection_log")
        if any(times[0] <= parse_time(hint["at"]) <= times[1] for hint in row["hints"]):
            reasons.append("L4:hinted_not_self")
        if any(_hint_from(hint) == subject for hint in row["hints"]):
            reasons.append("L4:hinted_not_self")
        if abs(row["observed"] - row["baseline"]) <= rc["tolerance"]:
            reasons.append("L4:correction_no_consequence")
        if abs(rc["metric_value"] - row["baseline"]) > rc["tolerance"]:
            reasons.append("L4:correction_metric")
        episode = episodes.get(rc["joint_episode_id"])
        if episode is None:
            reasons.append("L4:correction_joint_episode")
        elif (
            episode["episode_id"] == row["episode_id"]
            or _episode_reasons(obs, episode)
            or not all(span["passed"] for span in episode["spans"])
            or not all(parse_time(span["start"]) > times[2] and parse_time(span["end"]) <= times[3] for span in episode["spans"])
            or not check_joint(payload)[0]
        ):
            reasons.append("L4:correction_joint_episode")
        executor_keys = set(producers)
        executor_keys.add(subject)
        if repair is not None:
            executor_keys.add(identity_key(repair[1]["actor"]))
        if identity_key(rc["verified_by"]) in executor_keys or rc["verified_by"] not in reviewers:
            reasons.append("L4:correction_reviewer")
    return _result(reasons)


def _checks(root: Path) -> dict:
    return {
        "L1": check_solo,
        "L2": check_joint,
        "L3": check_priority,
        "L4": lambda payload: check_correction(payload, root),
    }


def semantic(payload: dict, stage: str, root: Path | None = None) -> list[str]:
    items = payload["stages"][stage]["evidence"]
    check = _checks(root or Path("."))[stage]
    ok, reasons = check(payload)
    if not ok:
        return list(reasons)
    if not all(item.get("exit_code") == 0 and not item.get("forged", False) for item in items):
        return [f"{stage}:semantic"]
    return []


def evaluate(payload: Any, root: Path) -> dict[str, Any]:
    issues = validate_payload(payload)
    if issues:
        claimed = payload.get("claimed_level") if isinstance(payload, dict) else None
        return {**make_result("composition", "FAIL", None, claimed, "L0", issues), "thresholds": dict(DEFAULT_THRESHOLDS)}
    if payload["outside_model"]:
        result = evaluate_outside(payload, root, "composition", LINKS,
                                  lambda normal: evaluate(normal, root))
        result["thresholds"] = thresholds(payload["observations"])
        return result
    normalised = copy.deepcopy(payload)
    for slot in normalised["stages"].values():
        for item in slot["evidence"]:
            for key in ("started_at", "finished_at"):
                if key in item:
                    item[key] = parse_time(item[key]).isoformat(timespec="microseconds").replace("+00:00", "Z")
    bound = binding_checks(payload, root)

    def checked_semantic(obj, stage):
        reasons = semantic(obj, stage, root)
        if not bound[stage][0]:
            reasons = list(reasons) + bound[stage][1]
        return reasons

    result = evaluate_net(normalised, root, "composition", LINKS, checked_semantic, min_levels=MIN_LEVELS)
    details = [reason for ok, reasons in bound.values() for reason in reasons]
    for stage, check in _checks(root).items():
        items = payload["stages"][stage]["evidence"]
        if items:
            details.extend(check(payload)[1])
            if any(item.get("forged", False) for item in items):
                details.append(stage + ":evidence_forged")
            if any(item.get("exit_code") != 0 for item in items):
                details.append(stage + ":evidence_failed")
    result["thresholds"] = thresholds(payload["observations"])
    result["reasons"] = list(dict.fromkeys(result["reasons"] + details))
    return result
