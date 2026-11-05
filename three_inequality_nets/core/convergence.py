# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""验收收敛：基线冻结、问题分类，以及结论必须从问题推导出来。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from three_inequality_nets.core.schema import canonical_hash, file_sha256, is_sha256, is_text, resolve_inside, stable_relative, user_message_ok

SCHEMA = "fournets.convergence.v1"
FINDING_CLASSES = {
    "FROZEN_REQUIREMENT_VIOLATION",
    "NEW_REPRODUCIBLE_P0",
    "NEW_NONBLOCKING_REQUIREMENT",
    "EVIDENCE_INVALID",
    "INFORMATIONAL",
}
P0_CATEGORIES = {
    "unauthorized_running_change",
    "privacy_or_security_boundary",
    "data_loss_or_corruption",
    "irreversible_external_effect",
}
DECISIONS = {
    "PASS_CANDIDATE",
    "CONDITIONAL_PASS",
    "RETURN_FOR_REWORK",
    "EVIDENCE_REJECTED_PRODUCT_UNDECIDED",
    "ARCHITECTURE_REVIEW_REQUIRED",
}
ARCHITECTURE_DIMENSIONS = {
    "product_boundary",
    "authority_boundary",
    "state_model",
    "evidence_model",
    "concurrency_or_lifecycle",
    "test_oracle",
}
TOP_KEYS = {
    "schema_version",
    "review_id",
    "candidate",
    "revision",
    "baseline",
    "baseline_change",
    "round_state",
    "findings",
    "closure",
}
BASELINE_ACTION = "AUTHORIZE_ACCEPTANCE_BASELINE_CHANGE"


def _reject_unknown(value: dict[str, Any], allowed: set[str], add, field: str) -> None:
    for key in sorted(set(value) - allowed):
        add("UNKNOWN_FIELD", f"{field}.{key}", "封闭对象不接受未声明字段")


def _file_ok(relative: Any, digest: Any, add, field: str, root: Path) -> Path | None:
    if not stable_relative(relative):
        add("EVIDENCE_PATH", f"{field}.path", "证据路径要是稳定相对路径")
        return None
    if not is_sha256(digest):
        add("EVIDENCE_SHA256", f"{field}.sha256", "证据摘要格式不对")
        return None
    try:
        path = resolve_inside(root, relative)
        actual = file_sha256(path)
    except (OSError, ValueError) as exc:
        add("EVIDENCE_READ_ERROR", f"{field}.path", exc.__class__.__name__)
        return None
    if actual.casefold() != str(digest).casefold():
        add("EVIDENCE_HASH_MISMATCH", f"{field}.sha256", "证据字节和摘要不一致")
        return None
    return path


def _same_path(left: Path | None, right: Path | None) -> bool:
    if left is None or right is None:
        return False
    try:
        return left.samefile(right)
    except OSError:
        return left.resolve() == right.resolve()


def _read_object(path: Path | None, add, field: str) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        add("BOUND_JSON_INVALID", field, exc.__class__.__name__)
        return None
    if not isinstance(value, dict):
        add("BOUND_JSON_NOT_OBJECT", field, "绑定文件的根要是对象")
        return None
    return value


def validate(
    payload: Any,
    root: Path,
    previous: dict[str, Any] | None = None,
    previous_sha256: str | None = None,
) -> dict[str, Any]:
    findings: list[dict[str, str]] = []

    def add(code: str, field: str, message: str) -> None:
        findings.append({"code": code, "field": field, "message": message})

    if not isinstance(payload, dict):
        add("ROOT_NOT_OBJECT", "$", "验收记录根要是对象")
        return _finish(payload, findings, None, None)
    for key in sorted(set(payload) - TOP_KEYS):
        add("UNKNOWN_FIELD", key, "有未声明字段")
    for key in sorted(TOP_KEYS - set(payload)):
        add("MISSING_FIELD", key, "缺少字段")
    if payload.get("schema_version") != SCHEMA:
        add("SCHEMA_VERSION", "schema_version", "模式名不对")
    if not is_text(payload.get("review_id")):
        add("REVIEW_ID", "review_id", "评审编号不能为空")

    candidate = payload.get("candidate")
    if not isinstance(candidate, dict):
        add("CANDIDATE_NOT_OBJECT", "candidate", "候选绑定要是对象")
        candidate = {}
    else:
        _reject_unknown(candidate, {"candidate_id", "artifact_path", "artifact_sha256"}, add, "candidate")
    if not is_text(candidate.get("candidate_id")):
        add("CANDIDATE_ID", "candidate.candidate_id", "候选编号不能为空")
    _file_ok(candidate.get("artifact_path"), candidate.get("artifact_sha256"), add, "candidate", root)

    revision = payload.get("revision")
    if not isinstance(revision, dict):
        add("REVISION_NOT_OBJECT", "revision", "修订要是对象")
        revision = {}
    sequence = revision.get("sequence")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        add("REVISION_SEQUENCE", "revision.sequence", "序号要是正整数")
    if revision.get("change_type") not in {"INITIAL", "CLARIFY", "REPLACE", "AUTHORIZE"}:
        add("REVISION_CHANGE_TYPE", "revision.change_type", "变更类型不在允许集合里")
    if not user_message_ok(revision.get("user_evidence")):
        add("REVISION_USER_EVIDENCE", "revision.user_evidence", "修订要有原始请求")

    baseline = payload.get("baseline")
    criterion_ids: set[str] = set()
    if not isinstance(baseline, dict):
        add("BASELINE_NOT_OBJECT", "baseline", "基线要是对象")
        baseline = {}
    else:
        _reject_unknown(baseline, {"baseline_id", "criteria"}, add, "baseline")
    if not is_text(baseline.get("baseline_id")):
        add("BASELINE_ID", "baseline.baseline_id", "基线编号不能为空")
    criteria = baseline.get("criteria")
    if not isinstance(criteria, list) or not criteria:
        add("BASELINE_CRITERIA", "baseline.criteria", "至少冻结一条验收标准")
        criteria = []
    for index, criterion in enumerate(criteria):
        field = f"baseline.criteria[{index}]"
        if not isinstance(criterion, dict):
            add("CRITERION_NOT_OBJECT", field, "标准要是对象")
            continue
        _reject_unknown(criterion, {"criterion_id", "statement", "source_ref", "verification_method", "blocking"}, add, field)
        criterion_id = criterion.get("criterion_id")
        if not is_text(criterion_id) or criterion_id in criterion_ids:
            add("CRITERION_ID", f"{field}.criterion_id", "标准编号要唯一且非空")
        elif is_text(criterion_id):
            criterion_ids.add(criterion_id)
        for key in ("statement", "source_ref", "verification_method"):
            if not is_text(criterion.get(key)):
                add("CRITERION_TEXT", f"{field}.{key}", "标准文本不能为空")
        if criterion.get("blocking") is not True:
            add("CRITERION_NOT_BLOCKING", f"{field}.blocking", "冻结标准都是阻断项，后来的非阻断想法进积压")

    baseline_change = payload.get("baseline_change")
    if not isinstance(baseline_change, dict):
        add("BASELINE_CHANGE_NOT_OBJECT", "baseline_change", "基线变更记录要是对象")
        baseline_change = {}
    if not isinstance(baseline_change.get("changed"), bool) or not isinstance(baseline_change.get("applies_to_current_candidate"), bool):
        add("BASELINE_CHANGE_FLAGS", "baseline_change", "变更标记要是布尔值")

    round_state = payload.get("round_state")
    if not isinstance(round_state, dict):
        add("ROUND_STATE_NOT_OBJECT", "round_state", "轮次要是对象")
        round_state = {}
    attempt = round_state.get("attempt_number")
    failed_rounds = round_state.get("consecutive_failed_rounds")
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
        add("ATTEMPT_NUMBER", "round_state.attempt_number", "尝试次数要是正整数")
    if isinstance(failed_rounds, bool) or not isinstance(failed_rounds, int) or failed_rounds < 0:
        add("FAILED_ROUNDS", "round_state.consecutive_failed_rounds", "连续失败次数要是非负整数")
        failed_rounds = 0
    architecture = round_state.get("architecture_review")
    if not isinstance(architecture, dict):
        add("ARCHITECTURE_REVIEW_NOT_OBJECT", "round_state.architecture_review", "架构复核要是对象")
        architecture = {}
    architecture_status = architecture.get("status")
    if architecture_status not in {"NOT_REQUIRED", "OPEN", "CLOSED"}:
        add("ARCHITECTURE_STATUS", "round_state.architecture_review.status", "架构复核状态无效")

    rows = payload.get("findings")
    if not isinstance(rows, list):
        add("FINDINGS_NOT_ARRAY", "findings", "问题列表要是数组")
        rows = []
    seen_ids: set[str] = set()
    open_blockers: list[str] = []
    backlog_ids: list[str] = []
    evidence_invalid_open = False
    for index, item in enumerate(rows):
        field = f"findings[{index}]"
        if not isinstance(item, dict):
            add("FINDING_NOT_OBJECT", field, "问题要是对象")
            continue
        finding_id = item.get("finding_id")
        classification = item.get("classification")
        status = item.get("status")
        effect = item.get("current_candidate_effect")
        if not is_text(finding_id) or finding_id in seen_ids:
            add("FINDING_ID", f"{field}.finding_id", "问题编号要唯一且非空")
            finding_id = f"invalid-{index}"
        elif is_text(finding_id):
            seen_ids.add(finding_id)
        if classification not in FINDING_CLASSES:
            add("FINDING_CLASS", f"{field}.classification", "问题分类无效")
            continue
        if status not in {"OPEN", "CLOSED", "BACKLOG"}:
            add("FINDING_STATUS", f"{field}.status", "问题状态无效")

        if classification == "FROZEN_REQUIREMENT_VIOLATION":
            if item.get("criterion_id") not in criterion_ids:
                add("FROZEN_CRITERION_UNKNOWN", f"{field}.criterion_id", "冻结违规要指向已有标准")
            if item.get("severity") not in {"P0", "P1", "P2"}:
                add("FROZEN_SEVERITY", f"{field}.severity", "严重度用 P0、P1 或 P2")
            _evidence_note(item.get("evidence"), add, f"{field}.evidence", root)
            if status == "OPEN":
                if effect != "BLOCK_CURRENT_CANDIDATE":
                    add("FROZEN_EFFECT", f"{field}.current_candidate_effect", "未关闭的冻结违规要阻断当前候选")
                open_blockers.append(str(finding_id))
            elif effect != "NO_EFFECT":
                add("CLOSED_EFFECT", f"{field}.current_candidate_effect", "已关闭问题对当前候选没有效力")
        elif classification == "NEW_REPRODUCIBLE_P0":
            if item.get("severity") != "P0" or item.get("p0_category") not in P0_CATEGORIES or item.get("reproducible") is not True:
                add("NEW_P0_QUALIFICATION", field, "新阻断项要是可复现的严重问题，并落在允许的类别里")
            _p0_evidence(item.get("evidence"), add, f"{field}.evidence", root)
            if status == "OPEN":
                if effect != "BLOCK_CURRENT_CANDIDATE":
                    add("NEW_P0_EFFECT", f"{field}.current_candidate_effect", "未关闭的严重问题要阻断当前候选")
                open_blockers.append(str(finding_id))
            elif effect != "NO_EFFECT":
                add("CLOSED_EFFECT", f"{field}.current_candidate_effect", "已关闭问题对当前候选没有效力")
        elif classification == "NEW_NONBLOCKING_REQUIREMENT":
            if status != "BACKLOG" or effect != "BACKLOG_ONLY" or not is_text(item.get("backlog_requirement_id")):
                add("NONBLOCKING_MUST_BACKLOG", field, "新的非阻断要求只能进积压，不能挡住当前候选")
            if item.get("severity") == "P0":
                add("NONBLOCKING_P0_CONFLICT", f"{field}.severity", "严重问题不能放进非阻断类")
            if is_text(item.get("backlog_requirement_id")):
                backlog_ids.append(item["backlog_requirement_id"])
        elif classification == "EVIDENCE_INVALID":
            _invalid_evidence(item, add, field, root)
            if status == "OPEN":
                evidence_invalid_open = True
                if effect != "PRODUCT_UNDECIDED":
                    add("EVIDENCE_INVALID_EFFECT", f"{field}.current_candidate_effect", "证据无效时产品结论未定，不能直接判产品失败")
            elif effect != "NO_EFFECT":
                add("CLOSED_EFFECT", f"{field}.current_candidate_effect", "已关闭问题对当前候选没有效力")
        elif classification == "INFORMATIONAL":
            if status != "CLOSED" or effect != "NO_EFFECT":
                add("INFORMATIONAL_EFFECT", field, "信息性问题要关闭且不阻断")

    closure = payload.get("closure")
    if not isinstance(closure, dict):
        add("CLOSURE_NOT_OBJECT", "closure", "收口要是对象")
        closure = {}
    evidence_state = closure.get("evidence_state")
    product_state = closure.get("product_state")
    decision = closure.get("decision")
    review_must_stop = closure.get("review_must_stop")
    declared_blockers = closure.get("open_blocking_finding_ids")
    declared_backlog = closure.get("backlog_requirement_ids")
    if evidence_state not in {"VALID", "INVALID", "INCOMPLETE"}:
        add("EVIDENCE_STATE", "closure.evidence_state", "证据状态无效")
    if product_state not in {"PASS", "FAIL", "UNDECIDED"}:
        add("PRODUCT_STATE", "closure.product_state", "产品状态无效")
    if decision not in DECISIONS:
        add("DECISION", "closure.decision", "收口决定无效")
    if not isinstance(review_must_stop, bool):
        add("REVIEW_STOP_FLAG", "closure.review_must_stop", "停止标记要是布尔值")
    if not isinstance(declared_blockers, list) or any(not is_text(item) for item in declared_blockers):
        add("BLOCKER_LEDGER_TYPE", "closure.open_blocking_finding_ids", "阻断编号要是文本数组")
        declared_blockers = []
    if not isinstance(declared_backlog, list) or any(not is_text(item) for item in declared_backlog):
        add("BACKLOG_LEDGER_TYPE", "closure.backlog_requirement_ids", "积压编号要是文本数组")
        declared_backlog = []
    if sorted(declared_blockers) != sorted(open_blockers):
        add("BLOCKER_DERIVATION", "closure.open_blocking_finding_ids", "写下来的阻断项必须等于未关闭的冻结违规和严重问题")
    if sorted(declared_backlog) != sorted(backlog_ids):
        add("BACKLOG_DERIVATION", "closure.backlog_requirement_ids", "写下来的积压必须等于非阻断要求")

    if evidence_invalid_open and open_blockers:
        add("MIXED_UNRESOLVED_EVIDENCE", "findings", "无效证据不能把另一条已证实的阻断项抹掉")
    if evidence_invalid_open:
        if evidence_state != "INVALID" or product_state != "UNDECIDED" or decision != "EVIDENCE_REJECTED_PRODUCT_UNDECIDED" or review_must_stop is not True:
            add("EVIDENCE_INVALID_NOT_SEPARATED", "closure", "证据无效时要停住，产品结论保持未定")
    elif open_blockers:
        if evidence_state != "VALID" or product_state != "FAIL":
            add("OPEN_BLOCKER_STATE", "closure", "还有阻断项时，证据要有效且产品为失败")
        if isinstance(failed_rounds, int) and failed_rounds >= 2:
            if architecture_status == "OPEN":
                if decision != "ARCHITECTURE_REVIEW_REQUIRED" or review_must_stop is not True:
                    add("ARCHITECTURE_STOP_REQUIRED", "closure", "连续两轮失败后要停下来做架构复核")
            elif architecture_status == "CLOSED":
                dimensions = architecture.get("dimensions_reviewed")
                if set(dimensions or []) != ARCHITECTURE_DIMENSIONS or not all(
                    is_text(architecture.get(key)) for key in ("hypothesis", "decision", "targeted_experiment")
                ):
                    add("ARCHITECTURE_REVIEW_INCOMPLETE", "round_state.architecture_review", "架构复核要覆盖六个方面，并写下假设、决定和一次针对性试验")
                if decision != "RETURN_FOR_REWORK" or review_must_stop is not False:
                    add("POST_ARCHITECTURE_DECISION", "closure", "架构复核关闭后只能放行一轮针对性返工")
            else:
                add("ARCHITECTURE_REVIEW_MISSING", "round_state.architecture_review.status", "连续两轮失败必须打开或关闭架构复核")
        elif decision != "RETURN_FOR_REWORK" or review_must_stop is not False:
            add("REWORK_DECISION", "closure", "未到架构复核阈值时，阻断项对应一轮有边界的返工")
    else:
        expected_decision = "CONDITIONAL_PASS" if backlog_ids else "PASS_CANDIDATE"
        if evidence_state != "VALID" or product_state != "PASS" or decision != expected_decision or review_must_stop is not True:
            add("MANDATORY_CLOSURE", "closure", "没有阻断项时必须按证据收口并停止；只有积压时用有条件通过")

    if isinstance(failed_rounds, int) and failed_rounds < 2 and architecture_status != "NOT_REQUIRED":
        add("EARLY_ARCHITECTURE_STATUS", "round_state.architecture_review.status", "未满两轮失败时，架构复核保持不需要")

    current_failure = decision in {"RETURN_FOR_REWORK", "ARCHITECTURE_REVIEW_REQUIRED"}
    expected_failed = 1 if current_failure else 0
    if isinstance(previous, dict):
        previous_report = validate(previous, root)
        if not previous_report["passed"]:
            add("PREVIOUS_RECORD_INVALID", "previous", "前序验收记录自己没有通过")
        if previous.get("schema_version") != SCHEMA:
            add("PREVIOUS_SCHEMA_VERSION", "previous.schema_version", "前序模式不对")
        if not is_sha256(revision.get("previous_record_sha256")) or str(revision.get("previous_record_sha256")).casefold() != str(previous_sha256).casefold():
            add("PREVIOUS_RECORD_HASH", "revision.previous_record_sha256", "修订要绑定前序记录的字节摘要")
        if sequence != previous.get("revision", {}).get("sequence", 0) + 1:
            add("REVISION_SEQUENCE_CHAIN", "revision.sequence", "序号要在前序上加一")
        if attempt != previous.get("round_state", {}).get("attempt_number", 0) + 1:
            add("ATTEMPT_SEQUENCE", "round_state.attempt_number", "尝试次数要在前序上加一")
        previous_baseline = previous.get("baseline")
        changed = canonical_hash(baseline) != canonical_hash(previous_baseline)
        declared_changed = baseline_change.get("changed") is True
        if changed and not _baseline_authorized(payload, baseline, previous_baseline, baseline_change, revision, candidate):
            add("BASELINE_UNBOUND", "baseline", "基线变了，但没有和本次评审、候选以及两份基线摘要绑在一起的授权行")
        elif not changed and declared_changed:
            add("BASELINE_CHANGE_FALSE_CLAIM", "baseline_change.changed", "基线字节没有变，不能宣称改过")
        previous_failure = previous.get("closure", {}).get("decision") in {"RETURN_FOR_REWORK", "ARCHITECTURE_REVIEW_REQUIRED"}
        if current_failure and previous_failure:
            expected_failed = previous.get("round_state", {}).get("consecutive_failed_rounds", 0) + 1
        elif current_failure:
            expected_failed = 1
        else:
            expected_failed = 0
    else:
        if revision.get("previous_record_sha256") is not None:
            add("INITIAL_PREVIOUS_HASH", "revision.previous_record_sha256", "第一份记录不能指向前序")
        if sequence != 1 or attempt != 1:
            add("INITIAL_SEQUENCE", "revision", "第一份记录的序号和尝试次数都是 1")
        if baseline_change.get("changed") is not False or baseline_change.get("applies_to_current_candidate") is not False:
            add("INITIAL_BASELINE_CHANGE", "baseline_change", "第一份冻结基线还不是变更")
    if failed_rounds != expected_failed:
        add("FAILED_ROUND_DERIVATION", "round_state.consecutive_failed_rounds", "连续失败次数要从评审链推出来")

    return _finish(payload, findings, decision, review_must_stop)


def _baseline_authorized(payload: dict[str, Any], baseline: Any, previous_baseline: Any, baseline_change: dict[str, Any], revision: dict[str, Any], candidate: dict[str, Any]) -> bool:
    binding = {
        "action": BASELINE_ACTION,
        "candidate_id": candidate.get("candidate_id"),
        "new_baseline_sha256": canonical_hash(baseline),
        "previous_baseline_sha256": canonical_hash(previous_baseline),
        "review_id": payload.get("review_id"),
    }
    binding_sha = canonical_hash(binding)
    authorization = baseline_change.get("authorization_evidence")
    quote = authorization.get("exact_quote") if isinstance(authorization, dict) else ""
    lines = {line.strip() for line in quote.splitlines()} if isinstance(quote, str) else set()
    return (
        baseline_change.get("changed") is True
        and baseline_change.get("applies_to_current_candidate") is True
        and revision.get("change_type") in {"AUTHORIZE", "REPLACE"}
        and user_message_ok(authorization)
        and authorization == revision.get("user_evidence")
        and isinstance(authorization, dict)
        and authorization.get("binding") == binding
        and authorization.get("binding_sha256") == binding_sha
        and f"{BASELINE_ACTION} {binding_sha}" in lines
        and is_text(baseline_change.get("rationale"))
    )


def _evidence_note(value: Any, add, field: str, root: Path) -> None:
    if not isinstance(value, dict):
        add("EVIDENCE_NOT_OBJECT", field, "证据要是对象")
        return
    _file_ok(value.get("path"), value.get("sha256"), add, field, root)
    if not is_text(value.get("observed_violation")):
        add("EVIDENCE_OBSERVATION", f"{field}.observed_violation", "要写下观察到的具体偏差")


def _p0_evidence(value: Any, add, field: str, root: Path) -> None:
    if not isinstance(value, dict):
        add("EVIDENCE_NOT_OBJECT", field, "证据要是对象")
        return
    _evidence_note(value, add, field, root)
    command = value.get("replay_command")
    if not isinstance(command, list) or not command or any(not is_text(part) for part in command):
        add("P0_REPLAY_COMMAND", f"{field}.replay_command", "要给出可复现的命令数组，校验器不执行它")
    inputs = value.get("input_artifacts")
    if not isinstance(inputs, list) or not inputs:
        add("P0_REPLAY_INPUTS", f"{field}.input_artifacts", "至少绑定一份复现输入")
    else:
        for index, artifact in enumerate(inputs):
            if isinstance(artifact, dict):
                _file_ok(artifact.get("path"), artifact.get("sha256"), add, f"{field}.input_artifacts[{index}]", root)
            else:
                add("P0_REPLAY_INPUTS", f"{field}.input_artifacts[{index}]", "输入绑定要是对象")
    output = value.get("output_artifact") if isinstance(value.get("output_artifact"), dict) else {}
    output_path = _file_ok(output.get("path"), output.get("sha256"), add, f"{field}.output_artifact", root)
    assertion_path = None
    if stable_relative(value.get("path")):
        try:
            assertion_path = resolve_inside(root, value.get("path"))
        except ValueError:
            assertion_path = None
    if _same_path(assertion_path, output_path):
        add("P0_OUTPUT_NOT_SEPARATE", f"{field}.output_artifact.path", "复现输出要和断言文件分开")
    observation = value.get("independent_observation")
    if not isinstance(observation, dict):
        add("P0_INDEPENDENT_OBSERVATION", f"{field}.independent_observation", "要有另一份独立观察")
        return
    if observation.get("source_type") != "INDEPENDENT_QA" or not is_text(observation.get("observer_id")):
        add("P0_INDEPENDENT_OBSERVER", f"{field}.independent_observation", "独立观察要标明观察者和来源")
    observed_path = _file_ok(observation.get("path"), observation.get("sha256"), add, f"{field}.independent_observation", root)
    if _same_path(observed_path, assertion_path) or _same_path(observed_path, output_path):
        add("P0_OBSERVATION_NOT_INDEPENDENT", f"{field}.independent_observation.path", "独立观察不能和复现输出或断言是同一个文件")


def _invalid_evidence(item: dict[str, Any], add, field: str, root: Path) -> None:
    subject = item.get("evidence_subject")
    if not isinstance(subject, dict):
        add("EVIDENCE_INVALID_SUBJECT", f"{field}.evidence_subject", "要写明证据对象和它声明的摘要")
        return
    path_value = subject.get("path")
    claimed = subject.get("claimed_sha256")
    if not stable_relative(path_value) or not is_sha256(claimed):
        add("EVIDENCE_INVALID_SUBJECT_BINDING", f"{field}.evidence_subject", "证据对象要有相对路径和摘要")
        return
    reason = item.get("invalidity_reason")
    if reason not in {"MISSING", "HASH_MISMATCH"}:
        add("EVIDENCE_INVALID_REASON", f"{field}.invalidity_reason", "无效原因用 MISSING 或 HASH_MISMATCH")
    try:
        subject_path = resolve_inside(root, path_value)
        exists = subject_path.exists()
        actual = file_sha256(subject_path) if subject_path.is_file() else None
    except (OSError, ValueError):
        exists = False
        actual = None
    if reason == "MISSING" and exists:
        add("EVIDENCE_SUBJECT_PRESENT", f"{field}.evidence_subject.path", "文件还在，不能记成缺失")
    if reason == "HASH_MISMATCH" and actual is not None and actual.casefold() == claimed.casefold():
        add("EVIDENCE_SUBJECT_HASH_VALID", f"{field}.evidence_subject.claimed_sha256", "摘要是对得上的，不能记成不一致")
    _evidence_note(item.get("evidence"), add, f"{field}.evidence", root)


def _finish(payload: Any, findings: list[dict[str, str]], decision: Any, review_must_stop: Any) -> dict[str, Any]:
    findings = sorted(findings, key=lambda item: (item["code"], item["field"], item["message"]))
    body = payload if isinstance(payload, dict) else {}
    baseline = body.get("baseline")
    return {
        "baseline_sha256": canonical_hash(baseline) if isinstance(baseline, dict) else None,
        "finding_count": len(findings),
        "findings": findings,
        "passed": not findings,
        "schema_version": "fournets.convergence.validation.v1",
        "summary": {
            "decision": decision,
            "review_id": body.get("review_id"),
            "review_must_stop": review_must_stop,
        },
    }
