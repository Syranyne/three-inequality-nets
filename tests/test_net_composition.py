# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne
import pytest
from three_inequality_nets.nets.composition.validator import check_solo, check_joint, check_priority, check_correction
from tests.composition_data import change, payload

@pytest.mark.parametrize("check", [check_solo, check_joint, check_priority, check_correction])
def test_positive_stages(check):
    assert check(payload()) == (True, [])

@pytest.mark.parametrize("check,path,value,reason", [
    (check_solo, "observations.solo.code.runs", 4, "L1:solo_runs"),
    (check_solo, "observations.solo.docs.passes", 7, "L1:solo_pass_rate"),
    (check_solo, "observations.solo.code.run_ids", ["repeat"]*10, "L1:solo_run_ids"),
    (check_joint, "observations.joint.episodes.0.spans", [], "L2:joint_coverage"),
    (check_joint, "observations.joint.episodes.0.spans.1.start", "2026-01-15T10:50:00Z", "L2:stitched_joint"),
    (check_joint, "observations.joint.episodes.0.episode_id", "solo-code-0", "L2:stitched_joint"),
    (check_priority, "observations.conflicts.0.chosen", "docs", "L3:priority_winner"),
    (check_priority, "observations.conflicts.0.injected", False, "L3:priority_injected"),
    (check_priority, "observations.conflicts", [], "L3:priority_trials"),
    (check_priority, "observations.policy.declared_at", "2026-01-15T12:00:00Z", "L3:policy_after_trial"),
    (check_priority, "observations.conflicts.0.loser_handling", "dropped_silently", "L3:priority_loser_handling"),
    (check_priority, "observations.conflicts.0.episode_id", "absent", "L3:priority_episode"),
    (check_priority, "observations.conflicts.0.expected_winner", "docs", "L3:priority_winner"),
    (check_priority, "observations.policy.order", ["code", "code"], "L3:priority_order"),
    (check_priority, "observations.policy.sha256", "0"*64, "L3:priority_policy_digest"),
    (check_correction, "observations.incidents.0.detected_at", "2026-01-15T10:05:00Z", "L4:correction_time_order"),
    (check_correction, "observations.incidents.0.detected_by", "external", "L4:correction_detection"),
    (check_correction, "observations.incidents.0.hints", [{"at": "2026-01-15T10:07:00Z", "source": "user"}], "L4:hinted_not_self"),
    (check_correction, "observations.incidents.0.recheck.metric_value", 2, "L4:correction_metric"),
    (check_correction, "observations.joint.episodes.9.spans.0.passed", False, "L4:correction_joint_episode"),
    (check_correction, "observations.incidents.0.recheck.verified_by", "runner-a", "L4:correction_reviewer"),
    (check_correction, "observations.joint.episodes.0.actions.0.actor", "external", "L4:correction_action"),
    (check_correction, "observations.incidents.0.action_id", "absent", "L4:correction_action"),
    (check_correction, "observations.incidents.0.correction_action_id", "absent", "L4:correction_repair_action"),
    (check_correction, "observations.incidents.0.recheck.joint_episode_id", "joint-1", "L4:correction_joint_episode"),
    (check_correction, "observations.incidents.0.observed", 0, "L4:correction_no_consequence"),
])
def test_stage_rejects_counterexample(check, path, value, reason):
    obj = payload()
    change(obj, path, value)
    ok, reasons = check(obj)
    assert not ok
    assert reason in reasons

def test_missing_solo_record():
    obj = payload()
    del obj["observations"]["solo"]["code"]
    assert "L1:solo_missing" in check_solo(obj)[1]

def test_joint_rate_drop():
    obj = payload()
    for episode in obj["observations"]["joint"]["episodes"][:2]:
        episode["spans"][1]["passed"] = False
    assert "L2:joint_drop" in check_joint(obj)[1]

@pytest.mark.parametrize("minute", [6, 8])
def test_hint_interval_is_closed(minute):
    obj = payload()
    obj["observations"]["incidents"][0]["hints"] = [{"at": f"2026-01-15T10:{minute:02}:00Z", "source": "user"}]
    assert "L4:hinted_not_self" in check_correction(obj)[1]

def test_time_comparison_uses_parsed_instants():
    obj = payload()
    obj["observations"]["policy"]["declared_at"] = "2026-01-15T10:10:00.1Z"
    assert "L3:policy_after_trial" in check_priority(obj)[1]

def test_joint_overlap_requires_positive_duration():
    obj = payload()
    obj["observations"]["joint"]["episodes"][0]["spans"][1]["start"] = "2026-01-15T10:50:00Z"
    assert "L2:stitched_joint" in check_joint(obj)[1]


import copy
import json
import subprocess
import sys
import pytest
from three_inequality_nets.cli import check_path
from three_inequality_nets.nets.composition.validator import evaluate
from tests.composition_data import ROOT, change, payload
from tests.support import case_paths, matches

@pytest.mark.parametrize("path", case_paths("composition"), ids=lambda p: p.name)
def test_composition_case(path):
    assert matches(path)

@pytest.mark.parametrize("stage", ["L1", "L2", "L3", "L4"])
def test_minimum_evidence_levels(stage):
    obj = payload()
    item = obj["stages"][stage]["evidence"][0]
    for key in ("command", "exit_code", "output_summary", "started_at", "finished_at", "reviewed_by",
                "output_path", "output_sha256", "receipt_path", "receipt_sha256", "review_path", "review_sha256"):
        item.pop(key, None)
    result = evaluate(obj, ROOT)
    assert result["verdict"] == "FAIL"
    minimum = "reviewed" if stage == "L4" else "executed"
    assert stage + ":evidence_below_" + minimum in result["reasons"]

@pytest.mark.parametrize("mode,reason", [
    ("hash", "L1:hash_mismatch"),
    ("output", "L1:exit_without_output"),
    ("reviewer", "L4:reviewer_is_executor"),
    ("marker", "L1:evidence_forged"),
    ("exit", "L1:evidence_failed"),
])
def test_core_and_explicit_forgery_still_fail(mode, reason, tmp_path):
    obj = payload()
    if mode == "hash":
        obj["stages"]["L1"]["evidence"][0]["sha256"] = "0"*64
    elif mode == "output":
        del obj["stages"]["L1"]["evidence"][0]["output_summary"]
        obj["stages"]["L1"]["evidence"][0].pop("output_path", None)
        obj["stages"]["L1"]["evidence"][0].pop("output_sha256", None)
    elif mode == "reviewer":
        obj["stages"]["L4"]["evidence"][0]["reviewed_by"] = "runner-a"
    elif mode == "marker":
        obj["stages"]["L1"]["evidence"][0]["forged"] = True
    else:
        obj["stages"]["L1"]["evidence"][0]["exit_code"] = 1
    from tests.support import resealed
    result = evaluate(*resealed(obj, tmp_path))
    assert result["verdict"] == "FAIL"
    assert reason in result["reasons"]

def test_fractional_evidence_time_and_input_immutability(tmp_path):
    from tests.support import resealed
    obj = payload()
    for slot in obj["stages"].values():
        slot["evidence"][0]["started_at"] = "2026-01-15T00:00:00Z"
        slot["evidence"][0]["finished_at"] = "2026-01-15T00:00:00.1Z"
    obj, root = resealed(obj, tmp_path)
    original = copy.deepcopy(obj)
    assert evaluate(obj, root)["verdict"] == "PASS"
    assert obj == original

@pytest.mark.parametrize("value", [None, [], "text", 5, True])
def test_invalid_top_level_is_schema_failure(value):
    result = evaluate(value, ROOT)
    assert result["verdict"] == "FAIL"
    assert result["reasons"] == ["schema:input"]

def test_cli_schema_exit_code(tmp_path):
    obj = payload()
    del obj["observations"]["joint"]
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2) + chr(10), encoding="utf-8")
    result = subprocess.run([sys.executable, "-m", "three_inequality_nets", "check", "composition", str(path), "--json"], cwd=ROOT, capture_output=True)
    assert result.returncode == 2
    assert "schema:" in result.stdout.decode("utf-8")

def test_correction_does_not_grant_write_authority(tmp_path):
    obj = payload()
    assert evaluate(obj, ROOT)["verdict"] == "PASS"
    # 组合网证据不能直接顶权限网：缺权限信号且 kind 不在权限白名单。
    item = copy.deepcopy(obj["stages"]["L1"]["evidence"][0])
    item["kind"] = "record"
    authority = {
        "schema_version": "fournets.net_input.v1", "net": "authority",
        "claimed_level": "L4", "outside_model": False, "signals": {},
        "stages": {stage: {"evidence": [copy.deepcopy(item)] if stage == "L1" else []} for stage in ("L1", "L2", "L3", "L4")},
    }
    path = tmp_path / "authority_l1.json"
    path.write_text(json.dumps(authority, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    result = check_path("authority", path, ROOT)
    assert result["verdict"] == "FAIL"
    assert result["proven_level"] in ("L0", "L1")
