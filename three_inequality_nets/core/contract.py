# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""任务合同：范围、授权来源、主张状态和委托边界。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from three_inequality_nets.core.schema import (
    canonical_hash,
    file_sha256,
    inside_or_equal,
    is_sha256,
    is_text,
    resolve_inside,
    stable_relative,
    text_list,
    user_message_ok,
)

SCHEMA = "fournets.task_contract.v1"
STATUSES = {"DRAFT", "FROZEN", "EXECUTING", "BLOCKED", "COMPLETED"}
CHANGE_TYPES = {"INITIAL", "ADD", "REPLACE", "CLARIFY", "AUTHORIZE", "REVOKE"}
STATE_KEYS = {
    "installation",
    "running_replacement",
    "deletion",
    "publishing",
    "external_writes",
    "restart",
}
ACTIONS = STATE_KEYS | {"read", "write", "modify", "test", "migrate", "summarize", "invoke"}
READ_ACTIONS = {"read", "summarize"}
WRITE_ACTIONS = {"write", "modify", "migrate", "deletion", "installation", "running_replacement"}
CLAIM_STATES = {
    "OBSERVED",
    "USER_STATED",
    "INFERRED",
    "UNVERIFIED",
    "AUTHORIZED",
    "NOT_AUTHORIZED",
    "RETRIEVAL_HIT_ONLY",
    "SEMANTIC_SCOPE_UNRESOLVED",
    "AUTHORITY_CONFLICT",
}
SOURCE_STATES = {
    "USER_MESSAGE": {"USER_STATED", "AUTHORIZED", "NOT_AUTHORIZED", "UNVERIFIED", "AUTHORITY_CONFLICT"},
    "TOOL_OBSERVATION": {"OBSERVED", "UNVERIFIED", "AUTHORITY_CONFLICT"},
    "RETRIEVED_DOCUMENT": {"RETRIEVAL_HIT_ONLY", "SEMANTIC_SCOPE_UNRESOLVED", "UNVERIFIED", "AUTHORITY_CONFLICT"},
    "FORWARDED_TEXT": {"SEMANTIC_SCOPE_UNRESOLVED", "UNVERIFIED", "AUTHORITY_CONFLICT"},
    "ASSISTANT_INFERENCE": {"INFERRED", "UNVERIFIED", "AUTHORITY_CONFLICT"},
    "ASSISTANT_SUMMARY": {"UNVERIFIED", "AUTHORITY_CONFLICT"},
    "MODEL_CONTEXT": {"UNVERIFIED", "AUTHORITY_CONFLICT"},
    "TEST_RESULT": {"OBSERVED", "UNVERIFIED", "NOT_AUTHORIZED", "AUTHORITY_CONFLICT"},
    "ABSENCE_OF_USER_AUTHORIZATION": {"NOT_AUTHORIZED", "UNVERIFIED"},
}
TRANSITIONS = {
    "RETRIEVAL_HIT_ONLY": {"SEMANTIC_SCOPE_UNRESOLVED", "UNVERIFIED", "AUTHORITY_CONFLICT"},
    "SEMANTIC_SCOPE_UNRESOLVED": {"UNVERIFIED", "USER_STATED", "OBSERVED", "AUTHORITY_CONFLICT"},
    "USER_STATED": {"UNVERIFIED", "AUTHORIZED", "NOT_AUTHORIZED", "OBSERVED", "AUTHORITY_CONFLICT"},
    "INFERRED": {"UNVERIFIED", "OBSERVED", "AUTHORITY_CONFLICT"},
    "UNVERIFIED": {"OBSERVED", "USER_STATED", "AUTHORIZED", "NOT_AUTHORIZED", "AUTHORITY_CONFLICT"},
    "NOT_AUTHORIZED": {"AUTHORIZED", "AUTHORITY_CONFLICT"},
    "AUTHORIZED": {"NOT_AUTHORIZED", "AUTHORITY_CONFLICT"},
    "OBSERVED": {"AUTHORITY_CONFLICT"},
    "AUTHORITY_CONFLICT": {"USER_STATED", "OBSERVED", "AUTHORIZED", "NOT_AUTHORIZED"},
}
TOP_KEYS = {
    "schema_version",
    "task_id",
    "revision",
    "objective",
    "authority_basis",
    "scope",
    "operations",
    "state_changes",
    "source_policy",
    "integrity_gates",
    "claims",
    "delegation",
    "evidence",
    "status",
    "runtime_policy",
    "acceptance_policy",
}
ACCEPTANCE_REQUIRED = {
    "baseline_frozen": True,
    "classify_findings": True,
    "non_p0_backlog_only": True,
    "invalid_evidence_undecided": True,
    "architecture_after_failures": 2,
    "stop_when_closed": True,
    "record_required": True,
}


def boundary_projection(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "acceptance_policy": payload.get("acceptance_policy"),
        "integrity_gates": payload.get("integrity_gates"),
        "runtime_policy": payload.get("runtime_policy"),
        "scope": payload.get("scope"),
        "source_policy": payload.get("source_policy"),
        "state_changes": payload.get("state_changes"),
    }


def _revoked_present(field: str, value: str, values: Any) -> bool:
    if not isinstance(values, list):
        return False
    if field == "forbidden_paths":
        return any(is_text(item) and item == value for item in values)
    folded = value.casefold().strip()
    return any(is_text(item) and item.casefold().strip() == folded for item in values)


def validate(
    payload: Any,
    previous_payload: Any = None,
    previous_sha256: str | None = None,
    root: Path | None = None,
    _seen_children: frozenset[str] | None = None,
) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    seen_children = _seen_children or frozenset()

    def add(code: str, field: str, message: str) -> None:
        findings.append({"code": code, "field": field, "message": message})

    if not isinstance(payload, dict):
        add("ROOT_NOT_OBJECT", "$", "合同根要是对象")
        return _finish(payload, findings, [], [], [])

    unknown = sorted(set(payload) - TOP_KEYS)
    missing = sorted(TOP_KEYS - set(payload))
    for key in unknown:
        add("UNKNOWN_FIELD", key, "合同不接受未声明字段")
    for key in missing:
        add("MISSING_FIELD", key, "缺少字段")
    if payload.get("schema_version") != SCHEMA:
        add("SCHEMA_VERSION", "schema_version", "模式名不对")
    for key in ("task_id", "objective"):
        if not is_text(payload.get(key)):
            add("EMPTY_TEXT", key, "需要非空文本")
    if payload.get("status") not in STATUSES:
        add("INVALID_STATUS", "status", "状态不在允许集合里")

    revision = payload.get("revision")
    if not isinstance(revision, dict):
        add("REVISION_NOT_OBJECT", "revision", "修订要是对象")
        revision = {}
    sequence = revision.get("sequence")
    change_type = revision.get("change_type")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        add("REVISION_SEQUENCE", "revision.sequence", "序号要是正整数")
    if change_type not in CHANGE_TYPES:
        add("REVISION_CHANGE_TYPE", "revision.change_type", "变更类型未知")
    if not user_message_ok(revision.get("user_evidence")):
        add("REVISION_USER_EVIDENCE", "revision.user_evidence", "修订要绑定原始请求编号和原句")
    revoked = revision.get("revoked_items", [])
    retired = revision.get("retired_claim_ids", [])
    if not isinstance(revoked, list):
        add("REVOKED_ITEMS_TYPE", "revision.revoked_items", "撤回项要是数组")
        revoked = []
    if not isinstance(retired, list) or any(not is_text(item) for item in retired):
        add("RETIRED_CLAIMS_TYPE", "revision.retired_claim_ids", "退役主张编号要是非空文本数组")
        retired = []
    elif len(set(retired)) != len(retired):
        add("RETIRED_CLAIMS_DUPLICATE", "revision.retired_claim_ids", "退役编号重复")
    if sequence == 1:
        if change_type != "INITIAL" or revision.get("previous_contract_sha256") not in (None, ""):
            add("INITIAL_REVISION_CONFLICT", "revision", "第一版必须是 INITIAL 且没有前序摘要")
        if retired:
            add("INITIAL_RETIRED_CLAIMS", "revision.retired_claim_ids", "第一版不能退役旧主张")
    elif isinstance(sequence, int) and sequence > 1:
        expected_hash = revision.get("previous_contract_sha256")
        if not is_sha256(expected_hash):
            add("PREVIOUS_HASH_INVALID", "revision.previous_contract_sha256", "后续版本要带前序摘要")
        if previous_payload is None or previous_sha256 is None:
            add("PREVIOUS_CONTRACT_REQUIRED", "revision", "校验后续版本时要提供前序合同")
        elif isinstance(expected_hash, str) and expected_hash.casefold() != previous_sha256.casefold():
            add("PREVIOUS_HASH_MISMATCH", "revision.previous_contract_sha256", "前序摘要和提供的合同对不上")
        if isinstance(previous_payload, dict):
            previous_revision = previous_payload.get("revision")
            previous_sequence = previous_revision.get("sequence") if isinstance(previous_revision, dict) else None
            if payload.get("task_id") != previous_payload.get("task_id"):
                add("REVISION_TASK_ID_MISMATCH", "task_id", "同一任务的编号不能换")
            if isinstance(previous_sequence, bool) or not isinstance(previous_sequence, int) or sequence != previous_sequence + 1:
                add("REVISION_SEQUENCE_GAP", "revision.sequence", "序号只能加一")
        if retired and change_type not in {"REPLACE", "REVOKE"}:
            add("RETIRED_CLAIMS_CHANGE_TYPE", "revision.retired_claim_ids", "只有替换或撤回能退役主张")

    authority = payload.get("authority_basis")
    if not isinstance(authority, dict):
        add("AUTHORITY_NOT_OBJECT", "authority_basis", "授权依据要是对象")
        authority = {}
    else:
        if not is_text(authority.get("current_user_directive")):
            add("CURRENT_DIRECTIVE_MISSING", "authority_basis.current_user_directive", "要冻结当前明确指令")
        if not user_message_ok(authority.get("current_user_evidence")):
            add("CURRENT_USER_EVIDENCE", "authority_basis.current_user_evidence", "当前指令要有原始请求证据")
        if authority.get("stale_context_not_authority") is not True:
            add("STALE_CONTEXT_UNLOCKED", "authority_basis." + "stale_context_not_authority", "旧上下文不能扩大授权")
        if not text_list(authority.get("workspace_instructions", [])):
            add("WORKSPACE_INSTRUCTIONS_TYPE", "authority_basis.workspace_instructions", "工作区说明要是文本数组")

    scope = payload.get("scope")
    read_roots: list[str] = []
    write_roots: list[str] = []
    forbidden_paths: list[str] = []
    forbidden_topics: list[str] = []
    forbidden_actions: list[str] = []
    if not isinstance(scope, dict):
        add("SCOPE_NOT_OBJECT", "scope", "范围要是对象")
        scope = {}
    else:
        for key in ("read_roots", "write_roots", "forbidden_paths", "forbidden_topics", "forbidden_actions"):
            if not text_list(scope.get(key)):
                add("SCOPE_LIST_TYPE", f"scope.{key}", "范围列表要是非空字符串数组，没有就写空数组")
        read_roots = scope.get("read_roots", []) if text_list(scope.get("read_roots")) else []
        write_roots = scope.get("write_roots", []) if text_list(scope.get("write_roots")) else []
        forbidden_paths = scope.get("forbidden_paths", []) if text_list(scope.get("forbidden_paths")) else []
        forbidden_topics = scope.get("forbidden_topics", []) if text_list(scope.get("forbidden_topics")) else []
        forbidden_actions = scope.get("forbidden_actions", []) if text_list(scope.get("forbidden_actions")) else []
        for field, values in (("read_roots", read_roots), ("write_roots", write_roots), ("forbidden_paths", forbidden_paths)):
            for value in values:
                if not stable_relative(value):
                    add("PATH_UNSTABLE", f"scope.{field}", "路径要是稳定相对路径")
        if not read_roots:
            add("READ_SCOPE_EMPTY", "scope.read_roots", "至少要有一个读取根")
        if not write_roots:
            add("WRITE_SCOPE_EMPTY", "scope.write_roots", "至少要有一个写入根")
        for root_path in read_roots:
            for blocked in forbidden_paths:
                if stable_relative(root_path) and stable_relative(blocked) and inside_or_equal(root_path, blocked):
                    add("READ_INSIDE_FORBIDDEN", "scope.read_roots", "读取根落在禁止路径里")
        for root_path in write_roots:
            for blocked in forbidden_paths:
                if stable_relative(root_path) and stable_relative(blocked) and inside_or_equal(root_path, blocked):
                    add("WRITE_INSIDE_FORBIDDEN", "scope.write_roots", "写入根落在禁止路径里")
        for action in forbidden_actions:
            if action not in ACTIONS:
                add("FORBIDDEN_ACTION_UNKNOWN", "scope.forbidden_actions", "未知动作")

    if change_type == "REVOKE":
        if not revoked:
            add("REVOKE_ITEMS_MISSING", "revision.revoked_items", "撤回至少要点名一项")
        if not isinstance(previous_payload, dict):
            add("REVOKE_PREVIOUS_REQUIRED", "revision", "撤回要对照前序合同")
        else:
            previous_scope = previous_payload.get("scope") if isinstance(previous_payload.get("scope"), dict) else {}
            for index, item in enumerate(revoked):
                field = f"revision.revoked_items[{index}]"
                if (
                    not isinstance(item, dict)
                    or item.get("field") not in {"scope.forbidden_paths", "scope.forbidden_topics", "scope.forbidden_actions"}
                    or not is_text(item.get("value"))
                ):
                    add("REVOKED_ITEM_INVALID", field, "撤回项的字段或取值无效")
                    continue
                name = item["field"].split(".", 1)[1]
                if not _revoked_present(name, item["value"], previous_scope.get(name, [])):
                    add("REVOKED_ITEM_NOT_PREVIOUS", field, "这项原先不在合同里")
                if _revoked_present(name, item["value"], scope.get(name, [])):
                    add("REVOKED_ITEM_STILL_PRESENT", field, "撤回项仍留在当前合同里")

    changes = payload.get("state_changes")
    if not isinstance(changes, dict):
        add("STATE_CHANGES_NOT_OBJECT", "state_changes", "状态变更要是对象")
        changes = {}
    for key in sorted(STATE_KEYS):
        item = changes.get(key)
        if not isinstance(item, dict):
            add("STATE_CHANGE_MISSING", f"state_changes.{key}", "缺少状态变更条目")
            continue
        allowed = item.get("explicitly_authorized")
        evidence = item.get("authorization_evidence")
        if not isinstance(allowed, bool):
            add("AUTHORIZATION_NOT_BOOLEAN", f"state_changes.{key}.explicitly_authorized", "授权标记要是布尔值")
        elif allowed:
            if not user_message_ok(evidence):
                add("AUTHORITY_SOURCE_UNVERIFIED", f"state_changes.{key}.authorization_evidence", "状态变更只能由原始请求授权")
            if key in forbidden_actions:
                add("FORBIDDEN_ACTION_CONFLICT", f"state_changes.{key}", "同一动作既被禁止又被授权")
        elif evidence is not None:
            add("UNAUTHORIZED_SOURCE_PRESENT", f"state_changes.{key}.authorization_evidence", "未授权时证据要留空")

    operations = payload.get("operations")
    if not isinstance(operations, list) or not operations:
        add("OPERATIONS_REQUIRED", "operations", "至少要有一个计划动作")
        operations = []
    seen_operations: set[str] = set()
    for index, operation in enumerate(operations):
        field = f"operations[{index}]"
        if not isinstance(operation, dict):
            add("OPERATION_NOT_OBJECT", field, "动作要是对象")
            continue
        operation_id = operation.get("operation_id")
        action = operation.get("action")
        target_type = operation.get("target_type")
        target = operation.get("target")
        topics = operation.get("topics")
        if not is_text(operation_id) or operation_id in seen_operations:
            add("OPERATION_ID", f"{field}.operation_id", "动作编号要唯一且非空")
        elif is_text(operation_id):
            seen_operations.add(operation_id)
        if action not in ACTIONS:
            add("OPERATION_ACTION", f"{field}.action", "动作类型未知")
            continue
        if action in forbidden_actions:
            add("PLANNED_FORBIDDEN_ACTION", f"{field}.action", "计划了被禁止的动作")
        if not text_list(topics):
            add("OPERATION_TOPICS", f"{field}.topics", "主题要是非空文本数组")
            topics = []
        blocked_topics = {item.casefold() for item in forbidden_topics}
        for topic in topics:
            if topic.casefold() in blocked_topics:
                add("PLANNED_FORBIDDEN_TOPIC", f"{field}.topics", "计划碰到了禁止主题")
        if action in STATE_KEYS:
            state_item = changes.get(action) if isinstance(changes.get(action), dict) else {}
            if state_item.get("explicitly_authorized") is not True:
                add("OPERATION_NOT_AUTHORIZED", f"{field}.action", "状态类动作缺少授权")
        if target_type == "PATH":
            if not stable_relative(target):
                add("OPERATION_PATH_INVALID", f"{field}.target", "路径目标要是稳定相对路径")
                continue
            if any(stable_relative(item) and inside_or_equal(target, item) for item in forbidden_paths):
                add("OPERATION_TARGET_FORBIDDEN", f"{field}.target", "目标落在禁止路径里")
            if action in READ_ACTIONS and not any(inside_or_equal(target, item) for item in read_roots if stable_relative(item)):
                add("OPERATION_OUTSIDE_READ_SCOPE", f"{field}.target", "读取目标在读取根之外")
            if action in WRITE_ACTIONS and not any(inside_or_equal(target, item) for item in write_roots if stable_relative(item)):
                add("OPERATION_OUTSIDE_WRITE_SCOPE", f"{field}.target", "写入目标在写入根之外")
            if action == "test" and not any(
                inside_or_equal(target, item) for item in read_roots + write_roots if stable_relative(item)
            ):
                add("OPERATION_OUTSIDE_SCOPE", f"{field}.target", "测试目标不在允许根里")
        elif target_type in {"PROCESS", "EXTERNAL"}:
            if not is_text(target):
                add("OPERATION_TARGET_EMPTY", f"{field}.target", "进程或外部目标不能为空")
        else:
            add("OPERATION_TARGET_TYPE", f"{field}.target_type", "目标类型用 PATH、PROCESS 或 EXTERNAL")

    policy = payload.get("source_policy")
    if not isinstance(policy, dict):
        add("SOURCE_POLICY_NOT_OBJECT", "source_policy", "来源策略要是对象")
    else:
        for key in ("preserve_originals", "candidate_before_installed", "unrelated_changes_untouched"):
            if policy.get(key) is not True:
                add("SOURCE_POLICY_REQUIRED", f"source_policy.{key}", "这项策略必须为真")

    integrity = payload.get("integrity_gates")
    if not isinstance(integrity, dict):
        add("INTEGRITY_NOT_OBJECT", "integrity_gates", "完整性开关要是对象")
    else:
        for key in ("truthfulness_required", "permission_separated", "training_claims_bounded", "retrieval_claims_bounded"):
            if integrity.get(key) is not True:
                add("INTEGRITY_GATE_OPEN", f"integrity_gates.{key}", "开关必须为真")

    claims = payload.get("claims")
    if not isinstance(claims, list) or not claims:
        add("CLAIMS_REQUIRED", "claims", "至少要有一条主张")
        claims = []
    seen_claims: set[str] = set()
    for index, claim in enumerate(claims):
        field = f"claims[{index}]"
        if not isinstance(claim, dict):
            add("CLAIM_NOT_OBJECT", field, "主张要是对象")
            continue
        claim_id = claim.get("claim_id")
        source_type = claim.get("source_type")
        state = claim.get("state")
        previous_state = claim.get("previous_state")
        if not is_text(claim_id) or claim_id in seen_claims:
            add("CLAIM_ID", f"{field}.claim_id", "主张编号要唯一且非空")
        elif is_text(claim_id):
            seen_claims.add(claim_id)
        if not is_text(claim.get("statement")) or not is_text(claim.get("evidence_ref")):
            add("CLAIM_TEXT", field, "主张正文和证据引用不能为空")
        if source_type not in SOURCE_STATES:
            add("CLAIM_SOURCE_TYPE", f"{field}.source_type", "来源类型未知")
        elif state not in SOURCE_STATES[source_type]:
            add("CLAIM_SOURCE_STATE_CONFLICT", f"{field}.state", "这个来源到不了这个状态")
        if state not in CLAIM_STATES:
            add("CLAIM_STATE", f"{field}.state", "主张状态未知")
        if previous_state is not None:
            if previous_state not in CLAIM_STATES or (
                state != previous_state and state not in TRANSITIONS.get(previous_state, set())
            ):
                add("ILLEGAL_CLAIM_TRANSITION", f"{field}.previous_state", "主张状态不能这样迁移")
        if state == "AUTHORIZED" and not user_message_ok(claim.get("authorization_evidence")):
            add("CLAIM_AUTHORITY_SOURCE_UNVERIFIED", f"{field}.authorization_evidence", "已授权状态要有原始请求证据")
        if state != "AUTHORIZED" and claim.get("authorization_evidence") is not None:
            add("CLAIM_AUTHORITY_EVIDENCE_CONFLICT", f"{field}.authorization_evidence", "只有已授权主张能带授权证据")

    if isinstance(previous_payload, dict):
        previous_claim_list = previous_payload.get("claims")
        if previous_payload.get("schema_version") != SCHEMA:
            add("PREVIOUS_SCHEMA_VERSION", "previous_contract.schema_version", "前序合同模式不对")
        if not isinstance(previous_claim_list, list) or not previous_claim_list:
            add("PREVIOUS_CLAIMS_INVALID", "previous_contract.claims", "前序合同要有主张")
            previous_claim_list = []
        previous_ids = [item.get("claim_id") for item in previous_claim_list if isinstance(item, dict) and is_text(item.get("claim_id"))]
        if len(previous_ids) != len(set(previous_ids)):
            add("PREVIOUS_CLAIM_ID_INVALID", "previous_contract.claims", "前序主张编号重复")
        previous_claims = {
            item.get("claim_id"): item
            for item in previous_claim_list
            if isinstance(item, dict) and is_text(item.get("claim_id"))
        }
        current_claims = {
            item.get("claim_id"): item for item in claims if isinstance(item, dict) and is_text(item.get("claim_id"))
        }
        retired_ids = set(retired)
        missing_previous = set(previous_claims) - set(current_claims)
        if retired_ids - set(previous_claims):
            add("RETIRED_CLAIM_UNKNOWN", "revision.retired_claim_ids", "退役了前序里没有的主张")
        if retired_ids & set(current_claims):
            add("RETIRED_CLAIM_STILL_PRESENT", "revision.retired_claim_ids", "退役主张仍在当前合同里")
        if missing_previous - retired_ids:
            add("CLAIM_DROPPED_ACROSS_REVISION", "claims", "旧主张消失时没有退役记录")
        for claim_id, current_claim in current_claims.items():
            prior = previous_claims.get(claim_id)
            field = f"claims[{claim_id}]"
            if prior is None:
                if current_claim.get("previous_state") is not None:
                    add("NEW_CLAIM_HAS_PREVIOUS_STATE", f"{field}.previous_state", "新主张不能声明前序状态")
                continue
            actual_previous = prior.get("state")
            current_state = current_claim.get("state")
            if current_claim.get("previous_state") != actual_previous:
                add("CLAIM_PREVIOUS_STATE_MISMATCH", f"{field}.previous_state", "前序状态要等于上一份合同里的状态")
            elif current_state != actual_previous and current_state not in TRANSITIONS.get(actual_previous, set()):
                add("ILLEGAL_CLAIM_TRANSITION", f"{field}.state", "跨版本状态迁移不成立")
            if current_claim.get("source_type") != prior.get("source_type"):
                add("CLAIM_SOURCE_RETYPE", f"{field}.source_type", "同一编号的来源不能改写，新来源用新编号")
            if current_claim.get("statement") != prior.get("statement"):
                add("CLAIM_STATEMENT_REWRITE", f"{field}.statement", "同一编号的正文不能改写")
            if current_claim.get("evidence_ref") != prior.get("evidence_ref"):
                add("CLAIM_EVIDENCE_REWRITE", f"{field}.evidence_ref", "同一编号的证据引用不能改写")

    evidence = payload.get("evidence")
    required_evidence: list[str] = []
    observed_evidence: list[str] = []
    open_evidence: list[str] = []
    if not isinstance(evidence, dict):
        add("EVIDENCE_NOT_OBJECT", "evidence", "证据清单要是对象")
    else:
        for key in ("required", "observed", "open_items"):
            if not text_list(evidence.get(key)):
                add("EVIDENCE_LIST_TYPE", f"evidence.{key}", "证据编号要是非空文本数组")
        required_evidence = evidence.get("required", []) if text_list(evidence.get("required")) else []
        observed_evidence = evidence.get("observed", []) if text_list(evidence.get("observed")) else []
        open_evidence = evidence.get("open_items", []) if text_list(evidence.get("open_items")) else []
        if len(set(required_evidence)) != len(required_evidence) or len(set(observed_evidence)) != len(observed_evidence):
            add("EVIDENCE_DUPLICATE", "evidence", "证据编号重复")
        if set(observed_evidence) & set(open_evidence):
            add("EVIDENCE_STATE_CONFLICT", "evidence", "同一项不能既已观察又未关闭")
        if not set(open_evidence).issubset(set(required_evidence)):
            add("OPEN_EVIDENCE_NOT_REQUIRED", "evidence.open_items", "未关闭项要来自必需证据")
        if payload.get("status") == "COMPLETED":
            if open_evidence:
                add("COMPLETION_EVIDENCE_OPEN", "evidence.open_items", "完成状态不能留着未关闭证据")
            missing_observed = sorted(set(required_evidence) - set(observed_evidence))
            if missing_observed:
                add("COMPLETION_EVIDENCE_MISSING", "evidence.observed", "完成状态还有必需证据没观察到")

    runtime_policy = payload.get("runtime_policy")
    if not isinstance(runtime_policy, dict):
        add("RUNTIME_POLICY_NOT_OBJECT", "runtime_policy", "运行策略要是对象")
        runtime_policy = {}
    else:
        if runtime_policy.get("append_only_ledger_required") is not True:
            add("RUNTIME_LEDGER_NOT_REQUIRED", "runtime_policy." + "append_only_ledger_required", "需要只追加的运行账")
        capabilities = runtime_policy.get("capabilities")
        opt_ins = runtime_policy.get("experimental_opt_ins")
        if not isinstance(capabilities, list) or any(not isinstance(item, dict) for item in capabilities):
            add("RUNTIME_CAPABILITIES_TYPE", "runtime_policy.capabilities", "能力列表要是对象数组")
            capabilities = []
        elif not capabilities:
            add("RUNTIME_CAPABILITIES_EMPTY", "runtime_policy.capabilities", "至少声明一项能力")
        if not isinstance(opt_ins, list) or any(not isinstance(item, dict) for item in opt_ins):
            add("EXPERIMENTAL_OPT_INS_TYPE", "runtime_policy.experimental_opt_ins", "试验开关要是对象数组")
            opt_ins = []
        capability_names: set[str] = set()
        experimental_names: set[str] = set()
        for index, capability in enumerate(capabilities):
            name = capability.get("name")
            stability = capability.get("stability")
            if not is_text(name) or name in capability_names:
                add("RUNTIME_CAPABILITY_NAME", f"runtime_policy.capabilities[{index}].name", "能力名要唯一且非空")
            elif is_text(name):
                capability_names.add(name)
            if stability not in {"stable", "experimental"}:
                add("RUNTIME_CAPABILITY_STABILITY", f"runtime_policy.capabilities[{index}].stability", "稳定性用 stable 或 experimental")
            elif stability == "experimental" and is_text(name):
                experimental_names.add(name)
        opted_names: set[str] = set()
        for index, opt_in in enumerate(opt_ins):
            capability = opt_in.get("capability")
            if not is_text(capability) or not user_message_ok(opt_in.get("user_evidence")):
                add("EXPERIMENTAL_OPT_IN_INVALID", f"runtime_policy.experimental_opt_ins[{index}]", "试验能力要有名称和原始请求")
            elif is_text(capability):
                opted_names.add(capability)
        if experimental_names - opted_names:
            add("EXPERIMENTAL_OPT_IN_MISSING", "runtime_policy.experimental_opt_ins", "试验能力缺少开启记录")
        if opted_names - experimental_names:
            add("EXPERIMENTAL_OPT_IN_UNKNOWN", "runtime_policy.experimental_opt_ins", "开启记录没有对应的试验能力")

    acceptance = payload.get("acceptance_policy")
    if not isinstance(acceptance, dict):
        add("ACCEPTANCE_POLICY_NOT_OBJECT", "acceptance_policy", "验收策略要是对象")
    else:
        extra = sorted(set(acceptance) - set(ACCEPTANCE_REQUIRED))
        absent = sorted(set(ACCEPTANCE_REQUIRED) - set(acceptance))
        for key in extra:
            add("ACCEPTANCE_POLICY_UNKNOWN_FIELD", f"acceptance_policy.{key}", "验收策略有未声明字段")
        for key in absent:
            add("ACCEPTANCE_POLICY_MISSING_FIELD", f"acceptance_policy.{key}", "验收策略缺字段")
        for key, expected in ACCEPTANCE_REQUIRED.items():
            if key in acceptance and acceptance.get(key) != expected:
                add("ACCEPTANCE_POLICY_WEAKENED", f"acceptance_policy.{key}", "验收策略被放宽")

    computed_boundary = canonical_hash(boundary_projection(payload)) if isinstance(payload, dict) else ""
    delegation = payload.get("delegation")
    if not isinstance(delegation, dict):
        add("DELEGATION_NOT_OBJECT", "delegation", "委托要是对象")
    else:
        allowed = delegation.get("allowed")
        recipients = delegation.get("recipients")
        handoffs = delegation.get("handoffs")
        if not isinstance(allowed, bool) or not text_list(recipients) or not isinstance(handoffs, list):
            add("DELEGATION_FORMAT", "delegation", "委托格式要包含布尔开关、接收人数组和交接数组")
            recipients = []
            handoffs = []
        delegation_evidence = delegation.get("authorization_evidence")
        if allowed is True and not user_message_ok(delegation_evidence):
            add("DELEGATION_AUTHORITY_SOURCE_UNVERIFIED", "delegation.authorization_evidence", "委托要有原始请求")
        if allowed is False and delegation_evidence is not None:
            add("DELEGATION_AUTHORITY_CONFLICT", "delegation.authorization_evidence", "未委托时授权证据要留空")
        if allowed is False and (recipients or handoffs):
            add("DELEGATION_CONFLICT", "delegation", "未委托时不能有接收人或交接")
        if allowed is True and root is not None:
            if not recipients:
                add("DELEGATION_RECIPIENTS_EMPTY", "delegation.recipients", "已委托时要有接收人")
            handoff_recipients: list[str] = []
            for index, handoff in enumerate(handoffs):
                field = f"delegation.handoffs[{index}]"
                if not isinstance(handoff, dict):
                    add("HANDOFF_NOT_OBJECT", field, "交接要是对象")
                    continue
                recipient = handoff.get("recipient")
                contract_path = handoff.get("contract_path")
                declared_hash = handoff.get("boundary_sha256")
                declared_contract_hash = handoff.get("contract_sha256")
                if not is_text(recipient):
                    add("HANDOFF_RECIPIENT", f"{field}.recipient", "缺少接收人")
                    continue
                handoff_recipients.append(recipient)
                if not stable_relative(contract_path):
                    add("HANDOFF_PATH", f"{field}.contract_path", "子合同路径要是稳定相对路径")
                    continue
                try:
                    child_path = resolve_inside(root, contract_path)
                    resolved = str(child_path)
                    if resolved in seen_children:
                        add("HANDOFF_CYCLE", f"{field}.contract_path", "委托合同形成了环")
                        continue
                    child_payload = json.loads(child_path.read_text(encoding="utf-8"))
                    child_report = validate(
                        child_payload,
                        root=root,
                        _seen_children=seen_children | frozenset({resolved}),
                    )
                    if not child_report["passed"]:
                        add("HANDOFF_CHILD_INVALID", f"{field}.contract_path", "子合同本身没有通过")
                    if isinstance(child_payload, dict) and child_payload.get("status") != "FROZEN":
                        add("HANDOFF_CHILD_STATUS", f"{field}.contract_path", "交接出去的子合同要处于冻结状态")
                    child_hash = canonical_hash(boundary_projection(child_payload)) if isinstance(child_payload, dict) else ""
                    child_contract_hash = file_sha256(child_path)
                except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
                    add("HANDOFF_READ_ERROR", f"{field}.contract_path", str(exc))
                    continue
                if not isinstance(declared_contract_hash, str) or declared_contract_hash.casefold() != child_contract_hash.casefold():
                    add("HANDOFF_CONTRACT_HASH_MISMATCH", f"{field}.contract_sha256", "子合同字节摘要对不上")
                if not isinstance(declared_hash, str) or declared_hash.casefold() != child_hash.casefold():
                    add("HANDOFF_DECLARED_HASH_MISMATCH", f"{field}.boundary_sha256", "子合同边界摘要对不上")
                if child_hash != computed_boundary:
                    add("HANDOFF_BOUNDARY_MISMATCH", field, "子合同边界和父合同不一致")
            if sorted(recipients) != sorted(handoff_recipients):
                add("HANDOFF_RECIPIENT_MISMATCH", "delegation", "每个接收人要有且只有一份交接")

    return _finish(payload, findings, operations, claims, required_evidence, open_evidence, computed_boundary)


def _finish(
    payload: Any,
    findings: list[dict[str, str]],
    operations: list[Any],
    claims: list[Any],
    required_evidence: list[str],
    open_evidence: list[str] | None = None,
    computed_boundary: str = "",
) -> dict[str, Any]:
    findings = sorted(findings, key=lambda item: (item["code"], item["field"], item["message"]))
    body = payload if isinstance(payload, dict) else {}
    return {
        "computed_boundary_sha256": computed_boundary,
        "finding_count": len(findings),
        "findings": findings,
        "passed": not findings,
        "schema_version": "fournets.task_contract.validation.v1",
        "summary": {
            "claim_count": len(claims),
            "open_evidence_count": len(open_evidence or []),
            "operation_count": len(operations),
            "required_evidence_count": len(required_evidence),
            "status": body.get("status"),
            "task_id": body.get("task_id"),
        },
    }
