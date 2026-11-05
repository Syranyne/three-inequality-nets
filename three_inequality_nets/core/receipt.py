# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""轻量回执：冻结验收、红绿结果和语义核对。命令数组只作记录，不执行。"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from three_inequality_nets.core.schema import file_sha256, inside_or_equal, is_sha256, is_text, resolve_inside, stable_relative, user_message_ok

SCHEMA = "fournets.receipt.v1"
TOP_KEYS = {
    "schema_version",
    "task_id",
    "routing",
    "authority",
    "baseline",
    "candidate",
    "acceptance",
    "test_strategy",
    "tests",
    "semantic_checks",
    "self_report_not_sufficient",
    "open_items",
    "decision",
}
REQUIRED_FORBIDDEN = {"installation", "running_replacement", "publishing", "restart"}


def _tree_sha256(root: Path) -> str:
    pairs: list[tuple[str, str]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        pairs.append((path.relative_to(root).as_posix(), file_sha256(path)))
    canonical = "".join(f"{name}\0{digest}\n" for name, digest in pairs)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _same_file(left: Path, right: Path) -> bool:
    try:
        return left.samefile(right)
    except OSError:
        return left.resolve() == right.resolve()


def _bind(binding: Any, add, field: str, root: Path) -> tuple[Path | None, str | None]:
    if not isinstance(binding, dict):
        add("ARTIFACT_NOT_OBJECT", field, "产物绑定要是对象")
        return None, None
    unknown = sorted(set(binding) - {"path", "artifact_type", "sha256"})
    for key in unknown:
        add("ARTIFACT_UNKNOWN_FIELDS", f"{field}.{key}", "产物绑定有未声明字段")
    raw_path = binding.get("path")
    kind = binding.get("artifact_type")
    claimed = binding.get("sha256")
    if not stable_relative(raw_path):
        add("ARTIFACT_PATH", f"{field}.path", "产物路径要是稳定相对路径")
        return None, None
    if kind not in {"FILE", "TREE"}:
        add("ARTIFACT_TYPE", f"{field}.artifact_type", "产物类型用 FILE 或 TREE")
    if not isinstance(claimed, str) or not is_sha256(claimed) or claimed != claimed.lower():
        add("ARTIFACT_SHA256", f"{field}.sha256", "摘要要是 64 位小写十六进制")
    try:
        path = resolve_inside(root, raw_path)
    except ValueError:
        add("ARTIFACT_PATH", f"{field}.path", "产物路径越界")
        return None, None
    if kind == "FILE" and not path.is_file():
        add("ARTIFACT_MISSING", f"{field}.path", "绑定的文件不存在")
        return path, None
    if kind == "TREE" and not path.is_dir():
        add("ARTIFACT_MISSING", f"{field}.path", "绑定的目录不存在")
        return path, None
    if kind not in {"FILE", "TREE"} or not path.exists():
        return path, None
    observed = file_sha256(path) if kind == "FILE" else _tree_sha256(path)
    if isinstance(claimed, str) and observed != claimed:
        add("ARTIFACT_HASH_MISMATCH", f"{field}.sha256", "产物字节和声明的摘要不一致")
    return path, observed


def validate(payload: Any, root: Path) -> dict[str, Any]:
    findings: list[dict[str, str]] = []

    def add(code: str, field: str, message: str) -> None:
        findings.append({"code": code, "field": field, "message": message})

    if not isinstance(payload, dict):
        add("ROOT_NOT_OBJECT", "$", "回执根要是对象")
        return _finish(findings, False, None, {})
    for key in sorted(set(payload) - TOP_KEYS):
        add("UNKNOWN_FIELDS", key, "有未声明字段")
    for key in sorted(TOP_KEYS - set(payload)):
        add("MISSING_FIELD", key, "缺少字段")
    if payload.get("schema_version") != SCHEMA:
        add("SCHEMA_VERSION", "schema_version", "模式名不对")
    if not is_text(payload.get("task_id")):
        add("TASK_ID", "task_id", "任务编号不能为空")

    routing = payload.get("routing")
    if not isinstance(routing, dict):
        add("ROUTING_NOT_OBJECT", "routing", "路由要是对象")
        routing = {}
    else:
        extra = sorted(set(routing) - {"track", "writes_files_or_changes_behavior", "bypass_reason", "heavy_triggers"})
        for key in extra:
            add("ROUTING_UNKNOWN_FIELDS", f"routing.{key}", "路由有未声明字段")
    if routing.get("track") != "LIGHT":
        add("TRACK_NOT_LIGHT", "routing.track", "这份校验只接受轻量回执")
    if routing.get("writes_files_or_changes_behavior") is not True:
        add("LIGHT_NOT_REQUIRED", "routing." + "writes_files_or_changes_behavior", "轻量回执要对应一次写文件或行为变化")
    if routing.get("bypass_reason") is not None:
        add("BYPASS_WITH_LIGHT", "routing.bypass_reason", "轻量回执不能同时声明绕过")
    heavy = routing.get("heavy_triggers")
    if not isinstance(heavy, list) or any(not is_text(item) for item in heavy):
        add("HEAVY_TRIGGERS_SHAPE", "routing.heavy_triggers", "重型触发要是文本数组")
    elif heavy:
        add("HEAVY_TRIGGER_REQUIRES_HEAVY", "routing.heavy_triggers", "出现重型触发就不能走轻量回执")

    authority = payload.get("authority")
    write_roots: list[str] = []
    if not isinstance(authority, dict):
        add("AUTHORITY_NOT_OBJECT", "authority", "授权要是对象")
        authority = {}
    else:
        extra = sorted(set(authority) - {"user_evidence", "write_roots", "forbidden_actions"})
        for key in extra:
            add("AUTHORITY_UNKNOWN_FIELDS", f"authority.{key}", "授权有未声明字段")
    if not user_message_ok(authority.get("user_evidence")):
        add("USER_EVIDENCE", "authority.user_evidence", "要有原始请求编号和原句")
    roots = authority.get("write_roots")
    if not isinstance(roots, list) or not roots:
        add("WRITE_ROOTS", "authority.write_roots", "至少要有一个写入根")
    else:
        for index, item in enumerate(roots):
            if not stable_relative(item):
                add("WRITE_ROOT_PATH", f"authority.write_roots[{index}]", "写入根要是稳定相对路径")
            else:
                write_roots.append(item)
    forbidden = authority.get("forbidden_actions")
    if not isinstance(forbidden, list) or any(not is_text(item) for item in forbidden):
        add("FORBIDDEN_ACTIONS", "authority.forbidden_actions", "禁止动作要是文本数组")
    else:
        missing_forbidden = sorted(REQUIRED_FORBIDDEN - set(forbidden))
        if missing_forbidden:
            add("LIGHT_BOUNDARY_MISSING", "authority.forbidden_actions", "轻量回执缺少必须禁止的动作")

    baseline = payload.get("baseline")
    anchors: list[Path] = []
    if not isinstance(baseline, dict) or set(baseline) != {"anchors"}:
        add("BASELINE_SHAPE", "baseline", "基线只能包含锚点")
    anchor_items = baseline.get("anchors") if isinstance(baseline, dict) else None
    if not isinstance(anchor_items, list) or not anchor_items:
        add("BASELINE_ANCHORS", "baseline.anchors", "至少要有一个基线锚点")
    else:
        for index, anchor in enumerate(anchor_items):
            path, _observed = _bind(anchor, add, f"baseline.anchors[{index}]", root)
            if path is not None:
                anchors.append(path)

    candidate_path, candidate_hash = _bind(payload.get("candidate"), add, "candidate", root)
    candidate_relative = payload.get("candidate", {}).get("path") if isinstance(payload.get("candidate"), dict) else None
    if candidate_path is not None and stable_relative(candidate_relative):
        if write_roots and not any(inside_or_equal(candidate_relative, item) for item in write_roots):
            add("CANDIDATE_OUTSIDE_WRITE_SCOPE", "candidate.path", "候选产物不在授权写入根里")
        for index, anchor in enumerate(anchors):
            if anchor.exists() and candidate_path.exists() and _same_file(anchor, candidate_path):
                add("CANDIDATE_EQUALS_BASELINE", "candidate.path", "候选产物和基线锚点是同一个文件")

    acceptance = payload.get("acceptance")
    criteria: dict[str, bool] = {}
    if not isinstance(acceptance, dict):
        add("ACCEPTANCE_NOT_OBJECT", "acceptance", "验收要是对象")
        acceptance = {}
    elif set(acceptance) != {"frozen_before_implementation", "criteria"}:
        add("ACCEPTANCE_SHAPE", "acceptance", "验收字段不齐或有多余字段")
    if acceptance.get("frozen_before_implementation") is not True:
        add("ACCEPTANCE_NOT_FROZEN", "acceptance.frozen_before_implementation", "验收要在施工前冻结")
    criterion_items = acceptance.get("criteria")
    if not isinstance(criterion_items, list) or not criterion_items:
        add("CRITERIA_REQUIRED", "acceptance.criteria", "至少要有一条验收标准")
    else:
        for index, item in enumerate(criterion_items):
            field = f"acceptance.criteria[{index}]"
            if not isinstance(item, dict) or set(item) != {"criterion_id", "statement", "blocking"}:
                add("CRITERION_SHAPE", field, "验收标准只含编号、陈述和是否阻断")
                continue
            cid = item.get("criterion_id")
            if not is_text(cid) or cid in criteria:
                add("CRITERION_ID", f"{field}.criterion_id", "标准编号要唯一且非空")
                continue
            if not is_text(item.get("statement")) or not isinstance(item.get("blocking"), bool):
                add("CRITERION_FIELDS", field, "标准陈述和阻断标记不完整")
                continue
            criteria[str(cid)] = bool(item.get("blocking"))
    if criteria and not any(criteria.values()):
        add("NO_BLOCKING_CRITERION", "acceptance.criteria", "至少要有一条阻断性标准")

    strategy = payload.get("test_strategy")
    if not isinstance(strategy, dict) or set(strategy) != {"mode", "justification"}:
        add("TEST_STRATEGY_SHAPE", "test_strategy", "测试策略只含模式和说明")
        strategy = {}
    mode = strategy.get("mode")
    if mode not in {"RED_GREEN", "JUSTIFIED_NO_RED"}:
        add("TEST_STRATEGY_MODE", "test_strategy.mode", "模式用 RED_GREEN 或 JUSTIFIED_NO_RED")
    if mode == "RED_GREEN" and strategy.get("justification") is not None:
        add("RED_GREEN_JUSTIFICATION", "test_strategy.justification", "红绿模式的说明要留空")
    if mode == "JUSTIFIED_NO_RED" and not is_text(strategy.get("justification")):
        add("NO_RED_JUSTIFICATION", "test_strategy.justification", "不跑红灯时要写下有边界的理由")

    red_seen = False
    green_seen = False
    green_failed = False
    test_ids: set[str] = set()
    tests = payload.get("tests")
    if not isinstance(tests, list) or not tests:
        add("TESTS_REQUIRED", "tests", "至少要有一条绑定了摘要的测试结果")
        tests = []
    expected_keys = {"test_id", "phase", "command_argv", "result_path", "result_sha256", "observed_exit_code", "expected_exit", "status"}
    for index, item in enumerate(tests):
        field = f"tests[{index}]"
        if not isinstance(item, dict) or set(item) != expected_keys:
            add("TEST_SHAPE", field, "测试结果字段不齐或有多余字段")
            continue
        test_id = item.get("test_id")
        if not is_text(test_id) or test_id in test_ids:
            add("TEST_ID", f"{field}.test_id", "测试编号要唯一且非空")
        elif is_text(test_id):
            test_ids.add(test_id)
        argv = item.get("command_argv")
        if not isinstance(argv, list) or not argv or any(not is_text(part) for part in argv):
            add("TEST_ARGV", f"{field}.command_argv", "命令数组要是非空文本数组，校验器不执行它")
        _bind({"path": item.get("result_path"), "artifact_type": "FILE", "sha256": item.get("result_sha256")}, add, field, root)
        phase = item.get("phase")
        exit_code = item.get("observed_exit_code")
        if isinstance(exit_code, bool) or not isinstance(exit_code, int):
            add("TEST_EXIT_CODE", f"{field}.observed_exit_code", "退出码要是整数")
            continue
        if phase == "RED":
            red_seen = True
            if item.get("expected_exit") != "NONZERO" or exit_code == 0 or item.get("status") != "EXPECTED_FAIL":
                add("RED_RESULT", field, "红灯要预期非零、观察到非零，状态为 EXPECTED_FAIL")
        elif phase == "GREEN":
            green_seen = True
            if item.get("expected_exit") != "ZERO" or exit_code != 0 or item.get("status") != "PASS":
                green_failed = True
                add("GREEN_RESULT", field, "绿灯要预期零、观察到零，状态为 PASS")
        else:
            add("TEST_PHASE", f"{field}.phase", "阶段用 RED 或 GREEN")
    if mode == "RED_GREEN" and not red_seen:
        add("RED_EVIDENCE_MISSING", "tests", "红绿策略至少要有一条红灯结果")
    if not green_seen:
        add("GREEN_EVIDENCE_MISSING", "tests", "至少要有一条绿灯结果")

    covered: set[str] = set()
    semantic = payload.get("semantic_checks")
    if not isinstance(semantic, list) or not semantic:
        add("SEMANTIC_CHECKS_REQUIRED", "semantic_checks", "至少要有一条语义核对")
        semantic = []
    check_ids: set[str] = set()
    semantic_keys = {"check_id", "criterion_ids", "result_path", "result_sha256", "observed", "status"}
    for index, item in enumerate(semantic):
        field = f"semantic_checks[{index}]"
        if not isinstance(item, dict) or set(item) != semantic_keys:
            add("SEMANTIC_CHECK_SHAPE", field, "语义核对字段不齐或有多余字段")
            continue
        check_id = item.get("check_id")
        if not is_text(check_id) or check_id in check_ids:
            add("SEMANTIC_CHECK_ID", f"{field}.check_id", "核对编号要唯一且非空")
        elif is_text(check_id):
            check_ids.add(check_id)
        ids = item.get("criterion_ids")
        if not isinstance(ids, list) or not ids or any(cid not in criteria for cid in ids):
            add("SEMANTIC_CRITERIA", f"{field}.criterion_ids", "语义核对要引用已有标准")
        else:
            covered.update(str(cid) for cid in ids)
        _bind({"path": item.get("result_path"), "artifact_type": "FILE", "sha256": item.get("result_sha256")}, add, field, root)
        if item.get("observed") is not True or item.get("status") != "PASS":
            add("SEMANTIC_NOT_PASS", field, "语义核对要标记已观察并且通过")
    uncovered = sorted(cid for cid, blocking in criteria.items() if blocking and cid not in covered)
    if uncovered:
        add("BLOCKING_CRITERIA_UNCOVERED", "semantic_checks", "阻断性标准还没有语义核对")

    if payload.get("self_report_not_sufficient") is not True:
        add("SELF_REPORT_ONLY", "self_report_not_sufficient", "轻量回执不能只靠自述通过")
    open_items = payload.get("open_items")
    if not isinstance(open_items, list) or any(not is_text(item) for item in open_items):
        add("OPEN_ITEMS_SHAPE", "open_items", "未关闭项要是非空文本数组")
        open_items = []
    decision = payload.get("decision")
    if decision not in {"PASS_CANDIDATE", "BLOCKED"}:
        add("DECISION", "decision", "结论用 PASS_CANDIDATE 或 BLOCKED")
    if decision == "PASS_CANDIDATE" and open_items:
        add("PASS_WITH_OPEN_ITEMS", "open_items", "通过候选时不能留未关闭项")
    if decision == "PASS_CANDIDATE" and green_failed:
        add("PASS_WITH_FAILED_TEST", "decision", "通过候选时不能含失败的绿灯")

    passed = not findings
    candidate_passed = passed and decision == "PASS_CANDIDATE" and not open_items and candidate_hash is not None
    return _finish(findings, candidate_passed, candidate_hash, criteria, covered)


def _finish(
    findings: list[dict[str, str]],
    candidate_passed: bool,
    candidate_hash: str | None,
    criteria: dict[str, bool] | None = None,
    covered: set[str] | None = None,
) -> dict[str, Any]:
    findings = sorted(findings, key=lambda item: (item["code"], item["field"], item["message"]))
    criteria = criteria or {}
    covered = covered or set()
    passed = not findings
    if candidate_passed:
        status = "LIGHT_RECEIPT_PASS"
    elif passed:
        status = "LIGHT_RECEIPT_VALID_BLOCKED"
    else:
        status = "LIGHT_RECEIPT_INVALID"
    return {
        "blocking_criteria": sorted(cid for cid, blocking in criteria.items() if blocking),
        "candidate_passed": candidate_passed,
        "candidate_sha256": candidate_hash,
        "command_execution": "none",
        "covered_blocking_criteria": sorted(cid for cid in covered if criteria.get(cid)),
        "finding_count": len(findings),
        "findings": findings,
        "passed": passed,
        "schema_version": "fournets.receipt.validation.v1",
        "status": status,
    }
