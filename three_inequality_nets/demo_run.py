# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""从合成运行日志生成前后对照。"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from three_inequality_nets.core.evidence import assess
from three_inequality_nets.core.reviewers import FIXTURE_ENV
from three_inequality_nets.core.schema import file_sha256
from three_inequality_nets.nets.catalog import EVIDENCE_KINDS
from three_inequality_nets.nets.authority.validator import evaluate as evaluate_authority
from three_inequality_nets.nets.learning_claim.validator import evaluate as evaluate_learning
from three_inequality_nets.nets.production.validator import evaluate as evaluate_production
from three_inequality_nets.nets.retrieval.validator import evaluate as evaluate_retrieval
from three_inequality_nets.nets.composition.validator import evaluate as evaluate_composition

HEADER = "之前（日志自称）\t之后（校验结论）"


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _artifact(root: Path, relative: str, kind: str, *, reviewed: bool = False) -> dict[str, Any]:
    path = root / relative
    digest = file_sha256(path)
    item: dict[str, Any] = {
        "kind": kind,
        "path": relative,
        "produced_by": "worker-a",
        "reviewed_by": "",
        "sha256": digest,
        "timestamp": "2026-01-15T00:00:00Z",
    }
    if reviewed:
        # 执行输出和复核记录都是独立文件，不能拿证据本身充数。
        out_rel = relative[: -len(".json")] + "-out.txt"
        review_rel = relative[: -len(".json")] + "-review.json"
        receipt_rel = relative[: -len(".json")] + "-receipt.json"
        for needed in (out_rel, review_rel, receipt_rel):
            if not (root / needed).is_file():
                raise ValueError(f"demo fixture missing {needed}")
        item.update(
            {
                "command": ["py", "-3", "-c", "print('demo')"],
                "exit_code": 0,
                "output_summary": "demo",
                "output_path": out_rel,
                "output_sha256": file_sha256(root / out_rel),
                "started_at": "2026-01-15T00:00:00Z",
                "finished_at": "2026-01-15T00:00:02Z",
                "reviewed_by": "reviewer-b",
                "review_path": review_rel,
                "review_sha256": file_sha256(root / review_rel),
                "receipt_path": receipt_rel,
                "receipt_sha256": file_sha256(root / receipt_rel),
            }
        )
    return item


def stage_fixture(net: str, stage: str) -> str:
    return f"examples/demo/fixtures/{net}-{stage}.json"


def stage_kind(net: str, stage: str) -> str:
    return sorted(EVIDENCE_KINDS[net][stage])[0]


def _stages(root: Path, net: str, present: set[str]) -> dict[str, Any]:
    # 每网每阶段独立的已提交样例文件；demo 运行时不写仓库。
    out: dict[str, Any] = {}
    for stage in ("L1", "L2", "L3", "L4"):
        if stage not in present:
            out[stage] = {"evidence": []}
            continue
        stage_rel = stage_fixture(net, stage)
        if not (root / stage_rel).is_file():
            raise ValueError(f"demo fixture missing {stage_rel}")
        out[stage] = {
            "evidence": [_artifact(root, stage_rel, stage_kind(net, stage), reviewed=(stage == "L4"))]
        }
    return out


def _net(net: str, claim: str, claimed: str, stages: dict[str, Any], signals: dict[str, Any]) -> dict[str, Any]:
    return {
        "claim": claim,
        "claimed_level": claimed,
        "id": claim,
        "net": net,
        "outside_model": False,
        "schema_version": "fournets.net_input.v1",
        "signals": signals,
        "stages": stages,
    }


def _log_index(path: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            rows[item["id"]] = item
    return rows


def _require(log: dict[str, dict[str, Any]], log_id: str, event_type: str) -> dict[str, Any]:
    item = log.get(log_id)
    if item is None or item.get("type") != event_type:
        raise ValueError(f"demo log missing {log_id}")
    return item


def render(root: Path | None = None) -> tuple[str, int]:
    root = root or project_root()
    demo = root / "examples" / "demo"
    claims = _load_json(demo / "claims.json")
    log = _log_index(demo / "agent_run.log.jsonl")
    lines = [HEADER]
    failures = 0
    items = claims.get("items") if isinstance(claims, dict) else None
    if not isinstance(items, list):
        raise ValueError("demo claims missing items")
    for item in items:
        spoken = item["spoken"]
        rule = item["rule"]
        if rule == "unrun_tests":
            event = _require(log, item["log_id"], "tests_claimed")
            evidence = {
                "exit_code": event.get("exit_code"),
                "kind": "test-report",
                "output_summary": event.get("output"),
                "produced_by": "worker-a",
                "timestamp": "2026-01-15T00:00:00Z",
            }
            level, _reasons, _forged = assess(evidence, root)
            verdict = "FAIL" if level != "executed" else "PASS"
            link = "-"
            proven = level
        elif rule == "injected_write":
            _require(log, item["log_id"], "tool_result")
            payload = _net(
                "authority",
                spoken,
                "L4",
                _stages(root, "authority", {"L1", "L2", "L3", "L4"}),
                {
                    "approval_covers_key": False,
                    "asserted_as_fact": True,
                    "author": "tool-output",
                    "fact_checked": True,
                    "injected_authorization": True,
                    "sender": "tool-output",
                    "treat_sender_as_author": False,
                    "write_attempted": True,
                },
            )
            result = evaluate_authority(payload, root)
            verdict = result["verdict"]
            link = result["broken_link"] or "-"
            proven = result["proven_level"]
        elif rule == "memory_skip":
            _require(log, item["log_id"], "memory_claimed")
            _require(log, "e-correction", "user_correction")
            payload = _net(
                "learning_claim",
                spoken,
                "L4",
                _stages(root, "learning_claim", {"L1"}),
                {
                    "annotator": "reviewer-b",
                    "held_out_improved": False,
                    "in_dataset": False,
                    "label_matches": False,
                    "level_matches": False,
                    "prompt_contains_answer": False,
                    "proposer": "agent-a",
                },
            )
            result = evaluate_learning(payload, root)
            verdict = result["verdict"]
            link = result["broken_link"] or "-"
            proven = result["proven_level"]
        elif rule == "stale_hit":
            _require(log, item["log_id"], "search_hit")
            _require(log, "e-change", "config_change")
            payload = _net(
                "retrieval",
                spoken,
                "L4",
                _stages(root, "retrieval", {"L1", "L2", "L4"}),
                {"conditions_met": False, "current_authority": False, "object_aligned": False},
            )
            result = evaluate_retrieval(payload, root)
            verdict = result["verdict"]
            link = result["broken_link"] or "-"
            proven = result["proven_level"]
        elif rule == "demo_as_ship":
            _require(log, item["log_id"], "ship_claimed")
            _require(log, "e-demo", "demo_ran")
            payload = _net(
                "production",
                spoken,
                "L4",
                _stages(root, "production", {"L1"}),
                {
                    "benchmark_present": False,
                    "real_user_signal": False,
                    "release_recorded": False,
                    "repeat_stable": False,
                    "self_scored": True,
                },
            )
            result = evaluate_production(payload, root)
            verdict = result["verdict"]
            link = result["broken_link"] or "-"
            proven = result["proven_level"]
        elif rule in ("hinted_correction", "unsupported_exception"):
            event_type = "composition_claimed" if rule == "hinted_correction" else "outside_claimed"
            event = _require(log, item["log_id"], event_type)
            result = evaluate_composition(event.get("payload"), root)
            verdict = result["verdict"]
            link = result["broken_link"] or "-"
            proven = result["proven_level"]
        elif rule == "checked_fact":
            _require(log, item["log_id"], "measurement")
            payload = _net(
                "authority",
                spoken,
                "L3",
                _stages(root, "authority", {"L1", "L2", "L3"}),
                {
                    "approval_covers_key": False,
                    "asserted_as_fact": True,
                    "author": "agent-a",
                    "fact_checked": True,
                    "injected_authorization": False,
                    "sender": "agent-a",
                    "treat_sender_as_author": True,
                    "write_attempted": False,
                },
            )
            result = evaluate_authority(payload, root)
            verdict = result["verdict"]
            link = result["broken_link"] or "-"
            proven = result["proven_level"]
        else:
            raise ValueError("unknown demo rule")
        if verdict != "PASS":
            failures += 1
        row = f"{spoken}\t{verdict}\t{link}\t{proven}"
        if rule == "unsupported_exception":
            row += "\t" + " ".join(result["reasons"])
        lines.append(row)
    text = "\n".join(lines) + "\n"
    return text, (1 if failures else 0)


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if not callable(reconfigure):
            continue
        try:
            reconfigure(encoding="utf-8")
        except (OSError, ValueError):
            pass
    # 与 `three_inequality_nets demo` 一致：样例使用名册里的公开测试执行方/复核人。
    os.environ.setdefault(FIXTURE_ENV, "1")
    text, code = render()
    sys.stdout.buffer.write(text.encode("utf-8"))
    return code
