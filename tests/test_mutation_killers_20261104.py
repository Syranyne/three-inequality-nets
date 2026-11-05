# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""专门杀死 2026-11-04 验收中存活的 7 个变异。"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from three_inequality_nets.core.evidence import assess
from three_inequality_nets.core.schema import file_sha256
from three_inequality_nets.nets.authority.validator import evaluate as _authority_raw
from three_inequality_nets.nets.learning_claim.validator import evaluate as _learning_raw
from three_inequality_nets.nets.production.validator import evaluate as _production_raw
from three_inequality_nets.nets.composition.validator import evaluate as _composition_raw
from three_inequality_nets.core.sealing import seal, write_receipt
from three_inequality_nets.nets.catalog import EVIDENCE_KINDS
from tests.support import ROOT, load_json


def _sealed(raw):
    """补用例 id，并用沙箱里的测试执行方/复核人密钥签字（隔离语义检查）。"""
    def run(payload, root):
        if isinstance(payload, dict):
            payload.setdefault("id", "mutation-killer")
            seal(payload, root)
        return raw(payload, root)
    return run


evaluate_authority = _sealed(_authority_raw)
evaluate_learning = _sealed(_learning_raw)
evaluate_production = _sealed(_production_raw)
evaluate_composition = _sealed(_composition_raw)


def _digest(path: Path) -> str:
    return file_sha256(path)


def _sandbox(tmp_path: Path) -> Path:
    """测试只写 tmp_path，不写仓库；名册随沙盒复制。"""
    roster = tmp_path / "reviewers" / "roster.json"
    roster.parent.mkdir(parents=True, exist_ok=True)
    roster.write_bytes((ROOT / "reviewers" / "roster.json").read_bytes())
    return tmp_path


def _write_json(path: Path, body: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _reviewed_item(root: Path, relative: str, kind: str) -> dict:
    path = root / relative
    digest = _digest(path)
    out_rel = relative.replace(".json", "-out.txt")
    (root / out_rel).write_text("ok\n", encoding="utf-8")
    review_rel = relative.replace(".json", "-review.json")
    review_body = {
        "evidence_sha256": digest,
        "reviewer": "reviewer-b",
        "conclusion": "accept",
    }
    _write_json(root / review_rel, review_body)
    return {
        "kind": kind,
        "path": relative,
        "sha256": digest,
        "produced_by": "worker-a",
        "reviewed_by": "reviewer-b",
        "command": ["py", "-3", "-c", "print(1)"],
        "exit_code": 0,
        "output_summary": "ok",
        "output_path": out_rel,
        "output_sha256": _digest(root / out_rel),
        "started_at": "2026-01-15T00:00:00Z",
        "finished_at": "2026-01-15T00:00:02Z",
        "review_path": review_rel,
        "review_sha256": _digest(root / review_rel),
        "timestamp": "2026-01-15T00:00:00Z",
    }


def _stages_unique(root: Path, prefix: str, net: str) -> dict:
    stages = {}
    for stage in ("L1", "L2", "L3", "L4"):
        kind = sorted(EVIDENCE_KINDS[net][stage])[0]
        rel = f"cases/shared/{prefix}-{stage}.json"
        _write_json(root / rel, {"evidence_kind": kind, "stage": stage, "note": f"{prefix}-{stage}"})
        stages[stage] = {"evidence": [_reviewed_item(root, rel, kind) if stage == "L4" else {
            "kind": kind,
            "path": rel,
            "sha256": _digest(root / rel),
            "produced_by": "worker-a",
            "reviewed_by": "",
            "timestamp": "2026-01-15T00:00:00Z",
        }]}
    return stages


def test_production_missing_benchmark_fails_l4(tmp_path: Path):
    root = _sandbox(tmp_path)
    stages = _stages_unique(root, "kill-benchmark", "production")
    users = root / "cases/production/fixtures/kill-benchmark-users.json"
    _write_json(users, {"sample_size": 30})
    payload = {
        "schema_version": "fournets.net_input.v1",
        "net": "production",
        "claimed_level": "L4",
        "outside_model": False,
        "signals": {
            "repeat_stable": True,
            "release_recorded": True,
            "real_user_signal": True,
            "self_scored": False,
            "user_signal_ref": "cases/production/fixtures/kill-benchmark-users.json",
            "user_signal_sha256": _digest(users),
            "user_sample_size": 30,
            "benchmark_present": True,
        },
        "stages": stages,
    }
    result = evaluate_production(payload, root)
    assert result["verdict"] == "FAIL"
    assert any("benchmark" in r or r.startswith("L4:") for r in result["reasons"])


def test_production_self_scored_fails_l3(tmp_path: Path):
    root = _sandbox(tmp_path)
    stages = _stages_unique(root, "kill-self-scored", "production")
    users = root / "cases/production/fixtures/kill-self-scored-users.json"
    _write_json(users, {"sample_size": 30})
    payload = {
        "schema_version": "fournets.net_input.v1",
        "net": "production",
        "claimed_level": "L3",
        "outside_model": False,
        "signals": {
            "repeat_stable": True,
            "release_recorded": True,
            "real_user_signal": True,
            "self_scored": True,
            "user_signal_ref": "cases/production/fixtures/kill-self-scored-users.json",
            "user_signal_sha256": _digest(users),
            "user_sample_size": 30,
        },
        "stages": {k: stages[k] for k in ("L1", "L2", "L3")},
    }
    for stage in ("L1", "L2", "L3"):
        payload["stages"][stage] = stages[stage]
    result = evaluate_production(payload, root)
    assert result["verdict"] == "FAIL"
    assert any("L3" in r for r in result["reasons"])


def test_production_repeat_unstable_fails_l2(tmp_path: Path):
    root = _sandbox(tmp_path)
    stages = _stages_unique(root, "kill-repeat", "production")
    payload = {
        "schema_version": "fournets.net_input.v1",
        "net": "production",
        "claimed_level": "L2",
        "outside_model": False,
        "signals": {"repeat_stable": False, "release_recorded": True},
        "stages": {k: stages[k] for k in ("L1", "L2")},
    }
    result = evaluate_production(payload, root)
    assert result["verdict"] == "FAIL"
    assert any("L2" in r for r in result["reasons"])


def test_authority_injected_authorization_fails_l4(tmp_path: Path):
    root = _sandbox(tmp_path)
    stages = _stages_unique(root, "kill-inject", "authority")
    payload = {
        "schema_version": "fournets.net_input.v1",
        "net": "authority",
        "claimed_level": "L4",
        "outside_model": False,
        "signals": {
            "sender": "a",
            "author": "a",
            "treat_sender_as_author": True,
            "asserted_as_fact": True,
            "fact_checked": True,
            "injected_authorization": True,
            "write_attempted": True,
            "approval_covers_key": True,
        },
        "stages": stages,
    }
    result = evaluate_authority(payload, root)
    assert result["verdict"] == "FAIL"
    assert any("L4" in r for r in result["reasons"])


def test_learning_self_annotate_fails_l3(tmp_path: Path):
    root = _sandbox(tmp_path)
    stages = _stages_unique(root, "kill-self-label", "learning_claim")
    # learning kinds allow record
    payload = {
        "schema_version": "fournets.net_input.v1",
        "net": "learning_claim",
        "claimed_level": "L3",
        "outside_model": False,
        "signals": {
            "in_dataset": True,
            "annotator": "same-person",
            "proposer": "same-person",
            "label_matches": True,
            "level_matches": True,
        },
        "stages": {k: stages[k] for k in ("L1", "L2", "L3")},
    }
    result = evaluate_learning(payload, root)
    assert result["verdict"] == "FAIL"
    assert any("L3" in r for r in result["reasons"])


def test_evidence_time_order_blocks_executed(tmp_path: Path):
    target = tmp_path / "note.txt"
    target.write_text("hello\n", encoding="utf-8")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    out = tmp_path / "out.txt"
    out.write_text("out\n", encoding="utf-8")
    item = {
        "kind": "note",
        "path": "note.txt",
        "sha256": digest,
        "produced_by": "worker-a",
        "reviewed_by": "",
        "command": ["py", "-3", "x"],
        "exit_code": 0,
        "output_summary": "x",
        "output_path": "out.txt",
        "output_sha256": file_sha256(out),
        "started_at": "2026-01-15T00:00:02Z",
        "finished_at": "2026-01-15T00:00:00Z",
    }
    level, reasons, forged = assess(item, tmp_path)
    assert forged is True
    assert "time_order" in reasons
    assert level != "executed"


def test_evidence_timezone_comparison_not_lexicographic(tmp_path: Path):
    target = tmp_path / "note.txt"
    target.write_text("hello\n", encoding="utf-8")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    out = tmp_path / "out.txt"
    out.write_text("out\n", encoding="utf-8")
    # 字符串比较：09:00+08 > 02:00Z，会误判顺序；真实时间 01:00Z < 02:00Z。
    started = "2026-01-15T09:00:00+08:00"
    finished = "2026-01-15T02:00:00Z"
    assert not (started <= finished)
    item = {
        "kind": "note",
        "path": "note.txt",
        "sha256": digest,
        "produced_by": "worker-a",
        "reviewed_by": "",
        "command": ["py", "-3", "x"],
        "exit_code": 0,
        "output_summary": "x",
        "output_path": "out.txt",
        "output_sha256": file_sha256(out),
        "started_at": started,
        "finished_at": finished,
    }
    _sandbox(tmp_path)
    write_receipt(tmp_path, ("tz", "0" * 64), item)
    level, reasons, forged = assess(item, tmp_path, ("tz", "0" * 64))
    assert "time_order" not in reasons
    assert level == "executed"


def test_composition_joint_recheck_and_self_repair(tmp_path: Path):
    import shutil

    from three_inequality_nets.nets.composition.validator import check_correction

    sandbox = _sandbox(tmp_path)
    for rel in ("cases/composition", "cases/shared"):
        shutil.copytree(ROOT / rel, sandbox / rel)

    path = ROOT / "cases/composition/cp-pass-full.input.json"
    payload = load_json(path)
    # 变异 6：直接打 check_correction——联合整体不达标时，复测不能认可。
    bad = json.loads(json.dumps(payload))
    for ep in bad["observations"]["joint"]["episodes"]:
        for span in ep["spans"]:
            span["passed"] = False
    ok, reasons = check_correction(bad, sandbox)
    assert ok is False
    assert "L4:correction_joint_episode" in reasons

    # 复测 episode 本身仍全通过，但整体 joint 掉点：只能靠 check_joint 复查抓住。
    bad_joint = json.loads(json.dumps(payload))
    recheck_id = bad_joint["observations"]["incidents"][0]["recheck"]["joint_episode_id"]
    for ep in bad_joint["observations"]["joint"]["episodes"]:
        if ep["episode_id"] == recheck_id:
            continue
        for span in ep["spans"]:
            span["passed"] = False
    ok2, reasons2 = check_correction(bad_joint, sandbox)
    assert ok2 is False
    assert "L4:correction_joint_episode" in reasons2

    # 变异 7：修复动作 actor 不是 subject
    bad2 = json.loads(json.dumps(payload))
    for ep in bad2["observations"]["joint"]["episodes"]:
        for action in ep.get("actions") or []:
            if action["action_id"] == bad2["observations"]["incidents"][0]["correction_action_id"]:
                action["actor"] = "external-helper"
    for item in bad2["stages"]["L4"]["evidence"]:
        if item.get("kind") == "incident-observations":
            from three_inequality_nets.nets.composition.binding import canonical_bytes

            blob = canonical_bytes(bad2["observations"]["incidents"])
            (sandbox / item["path"]).write_bytes(blob)
            item["sha256"] = hashlib.sha256(blob).hexdigest()
    result2 = evaluate_composition(bad2, sandbox)
    assert result2["verdict"] == "FAIL"
    assert any("L4:correction_repair_action" in r for r in result2["reasons"])
