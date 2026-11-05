# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""运行账：只追加的执行记录，完成声明必须有执行级证据。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from three_inequality_nets.core.claim import binding as claim_binding
from three_inequality_nets.core.contract import validate as validate_contract
from three_inequality_nets.core.evidence import assess, level_rank
from three_inequality_nets.core.schema import canonical_hash, file_sha256, is_sha256, is_text, resolve_inside

SCHEMA = "fournets.run_ledger.v1"
PROOF_SCHEMA = "fournets.adversarial_result.v1"
CAPABILITY_STATES = ("declared", "parsed", "observed", "enforced")
TERMINAL_EVENTS = {"run.completed", "run.blocked", "run.interrupted", "run.failed"}
OP_END_EVENTS = {"operation.completed", "operation.interrupted", "operation.failed"}
STATE_ACTIONS = {"installation", "running_replacement", "deletion", "publishing", "external_writes", "restart"}
TOP_KEYS = {
    "schema_version",
    "run_id",
    "contract",
    "contract_sha256",
    "attested",
    "visible_claim_ids",
    "events",
    "completion_evidence",
}


def _proof_problems(raw: dict[str, Any], capability: str, root: Path) -> list[str]:
    problems: list[str] = []
    if raw.get("adversarial_case_blocked") is not True:
        problems.append("enforced_flag")
    case_id = raw.get("case_id")
    evidence_path = raw.get("evidence_path")
    evidence_hash = raw.get("evidence_sha256")
    if not is_text(case_id):
        problems.append("missing_case")
    if not is_text(evidence_path) or not is_sha256(evidence_hash):
        problems.append("proof_binding")
        return problems
    try:
        path = resolve_inside(root, evidence_path)
        actual = file_sha256(path)
        evidence = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        problems.append(f"proof_read:{exc.__class__.__name__}")
        return problems
    if actual.casefold() != str(evidence_hash).casefold():
        problems.append("proof_hash_mismatch")
    if not isinstance(evidence, dict) or evidence.get("schema_version") != PROOF_SCHEMA:
        problems.append("proof_schema")
        return problems
    if evidence.get("case_id") != case_id or evidence.get("capability") != capability:
        problems.append("proof_identity")
    if evidence.get("adversarial") is not True or evidence.get("expected_pass") is not False or evidence.get("observed_pass") is not False:
        problems.append("proof_not_rejection")
    exit_code = evidence.get("validator_exit_code")
    if isinstance(exit_code, bool) or not isinstance(exit_code, int) or exit_code == 0:
        problems.append("proof_zero_exit")
    return problems


def evaluate(ledger: Any, root: Path) -> dict[str, Any]:
    violations: list[dict[str, str]] = []

    def add(location: str, code: str) -> None:
        violations.append({"code": code, "location": location})

    if not isinstance(ledger, dict):
        add("$", "root_not_object")
        return _finish(ledger, violations, None, {}, set(), set())
    for key in sorted(set(ledger) - TOP_KEYS):
        add(key, "unknown_field")
    for key in sorted(TOP_KEYS - set(ledger)):
        add(key, "missing_field")
    if ledger.get("schema_version") != SCHEMA:
        add("schema_version", "schema")
    contract = ledger.get("contract")
    contract_report = validate_contract(contract, root=root) if isinstance(contract, dict) else {"passed": False, "findings": []}
    if contract_report.get("passed") is not True:
        add("contract", "contract_invalid")
    expected_hash = canonical_hash(contract) if isinstance(contract, dict) else ""
    declared_hash = ledger.get("contract_sha256")
    if not isinstance(declared_hash, str) or declared_hash.casefold() != expected_hash.casefold():
        add("contract_sha256", "contract_hash")
    if not isinstance(ledger.get("attested"), bool):
        add("attested", "attested_type")
    if not is_text(ledger.get("run_id")):
        add("run_id", "run_id")

    events = ledger.get("events")
    if not isinstance(events, list) or not events:
        add("events", "events_empty")
        events = []
    visible = ledger.get("visible_claim_ids")
    if not isinstance(visible, list) or any(not is_text(item) for item in visible):
        add("visible_claim_ids", "visible_claims_type")
        visible = []

    contract_body = contract if isinstance(contract, dict) else {}
    operations = {
        item.get("operation_id"): item
        for item in contract_body.get("operations", [])
        if isinstance(item, dict) and is_text(item.get("operation_id"))
    }
    claims = {
        item.get("claim_id"): item
        for item in contract_body.get("claims", [])
        if isinstance(item, dict) and is_text(item.get("claim_id"))
    }
    capabilities = {
        item.get("name"): item.get("stability")
        for item in contract_body.get("runtime_policy", {}).get("capabilities", [])
        if isinstance(item, dict) and is_text(item.get("name"))
    }
    opted = {
        item.get("capability")
        for item in contract_body.get("runtime_policy", {}).get("experimental_opt_ins", [])
        if isinstance(item, dict) and is_text(item.get("capability"))
    }
    state_changes = contract_body.get("state_changes") if isinstance(contract_body.get("state_changes"), dict) else {}

    last_seq: int | None = None
    run_started = False
    contract_loaded = False
    contract_validated = False
    terminal: str | None = None
    active: str | None = None
    operation_terminals: dict[str, str] = {}
    authority_checks: set[str] = set()
    effects: set[str] = set()
    disposed: set[str] = set()
    presented: set[str] = set()
    progress: dict[str, int] = {}
    proofs: set[str] = set()

    for index, raw in enumerate(events):
        location = f"events[{index}]"
        if not isinstance(raw, dict):
            add(location, "event_not_object")
            continue
        seq = raw.get("seq")
        event_type = raw.get("type")
        if isinstance(seq, bool) or not isinstance(seq, int):
            add(f"{location}.seq", "seq_type")
        elif last_seq is not None and seq <= last_seq:
            add(f"{location}.seq", "seq_order")
        else:
            last_seq = seq
        if not is_text(event_type):
            add(f"{location}.type", "type_missing")
            continue
        if terminal is not None:
            add(location, "after_terminal")
            continue
        if event_type not in {"run.started", "contract.loaded", "contract.validated"} and not contract_validated:
            add(location, "before_contract_validated")

        if event_type == "run.started":
            if run_started or index != 0:
                add(location, "start_position")
            run_started = True
        elif event_type == "contract.loaded":
            if not run_started or contract_loaded or index != 1:
                add(location, "loaded_position")
            if str(raw.get("contract_sha256", "")).casefold() != expected_hash.casefold():
                add(location, "loaded_hash")
            contract_loaded = True
        elif event_type == "contract.validated":
            if not contract_loaded or contract_validated or index != 2:
                add(location, "validated_position")
            if raw.get("passed") is not True:
                add(location, "validated_not_passed")
            contract_validated = True
        elif event_type == "authority.checked":
            operation_id = raw.get("operation_id")
            operation = operations.get(operation_id)
            action = operation.get("action") if isinstance(operation, dict) else None
            state_item = state_changes.get(action) if isinstance(state_changes.get(action), dict) else {}
            evidence = state_item.get("authorization_evidence") if isinstance(state_item.get("authorization_evidence"), dict) else {}
            if operation is None:
                add(location, "unknown_operation")
            elif action not in STATE_ACTIONS:
                add(location, "authority_not_state_action")
            elif raw.get("authorized") is not True or state_item.get("explicitly_authorized") is not True:
                add(location, "authority_mismatch")
            elif raw.get("authorization_message_id") != evidence.get("message_id"):
                add(location, "authority_message")
            else:
                authority_checks.add(operation_id)
        elif event_type == "operation.started":
            operation_id = raw.get("operation_id")
            operation = operations.get(operation_id)
            if operation is None:
                add(location, "unknown_operation")
            elif operation.get("action") in STATE_ACTIONS and operation_id not in authority_checks:
                add(location, "state_action_without_authority")
            if active is not None:
                add(location, "overlapping_operation")
            else:
                active = operation_id if is_text(operation_id) else None
        elif event_type in OP_END_EVENTS:
            operation_id = raw.get("operation_id")
            if active != operation_id:
                add(location, "operation_terminal_mismatch")
            else:
                active = None
                if is_text(operation_id):
                    operation_terminals[operation_id] = event_type
        elif event_type == "effect.registered":
            effect_id = raw.get("effect_id")
            if not is_text(effect_id) or effect_id in effects:
                add(location, "effect_id")
            else:
                effects.add(effect_id)
                if raw.get("disposer_declared") is not True:
                    add(location, "disposer_missing")
        elif event_type == "effect.disposed":
            effect_id = raw.get("effect_id")
            if effect_id not in effects:
                add(location, "unknown_effect")
            elif effect_id in disposed:
                add(location, "effect_double_dispose")
            elif is_text(effect_id):
                disposed.add(effect_id)
        elif event_type == "claim.presented":
            claim_id = raw.get("claim_id")
            if claim_id not in claims:
                add(location, "unknown_claim")
            elif raw.get("state") != claims[claim_id].get("state"):
                add(location, "claim_state")
            elif is_text(claim_id):
                presented.add(claim_id)
        elif event_type.startswith("capability."):
            state = event_type.split(".", 1)[1]
            capability = raw.get("capability")
            if capability not in capabilities or state not in CAPABILITY_STATES:
                add(location, "capability_unknown")
            else:
                expected_index = progress.get(capability, -1) + 1
                actual_index = CAPABILITY_STATES.index(state)
                if actual_index != expected_index:
                    add(location, "capability_order")
                else:
                    progress[capability] = actual_index
                if capabilities[capability] == "experimental" and capability not in opted:
                    add(location, "experimental_opt_in")
                if state == "enforced":
                    proof_issues = _proof_problems(raw, capability, root)
                    for issue in proof_issues:
                        add(location, issue)
                    if not proof_issues:
                        proofs.add(capability)
        elif event_type in TERMINAL_EVENTS:
            if not run_started or active is not None:
                add(location, "terminal_while_active")
            if event_type == "run.completed":
                incomplete = sorted(set(operations) - {key for key, value in operation_terminals.items() if value == "operation.completed"})
                if incomplete:
                    add(location, "completed_with_open_operations")
                if contract_body.get("status") != "COMPLETED":
                    add(location, "contract_not_completed")
                completion = ledger.get("completion_evidence")
                if not isinstance(completion, list) or not completion:
                    add("completion_evidence", "completion_missing")
                else:
                    # 规则 2：完成证据的执行回执必须绑定这一份台账（run_id + 台账全文哈希）。
                    bound = claim_binding({**ledger, "id": ledger.get("run_id")})
                    for evidence_index, item in enumerate(completion):
                        level, _reasons, forged = assess(item, root, bound)
                        if forged or level_rank(level) < level_rank("executed"):
                            add(f"completion_evidence[{evidence_index}]", "completion_not_executed")
                            break
            terminal = event_type
        else:
            add(location, "unknown_event")

    if run_started and terminal is None:
        add("events", "missing_terminal")
    if active is not None:
        add("events", "operation_still_active")
    for effect_id in sorted(effects - disposed):
        add("events", f"effect_open:{effect_id}")
    if sorted(set(visible) - presented):
        add("visible_claim_ids", "visible_not_presented")
    if sorted(set(visible) - set(claims)):
        add("visible_claim_ids", "visible_unknown")
    if sorted(set(claims) - set(visible)):
        add("visible_claim_ids", "claim_omitted")
    if ledger.get("attested") is True:
        not_enforced = sorted(name for name in capabilities if progress.get(name) != CAPABILITY_STATES.index("enforced"))
        if not_enforced or sorted(set(capabilities) - proofs):
            add("attested", "attested_without_enforcement")
    if terminal != "run.completed" and ledger.get("completion_evidence") not in ([], None) and ledger.get("completion_evidence") != []:
        # 非完成终态不要求执行证据；空数组可以留下。
        pass

    return _finish(ledger, violations, terminal, progress, proofs, presented)


def _finish(
    ledger: Any,
    violations: list[dict[str, str]],
    terminal: str | None,
    progress: dict[str, int],
    proofs: set[str],
    presented: set[str],
) -> dict[str, Any]:
    violations = sorted(violations, key=lambda item: (item["location"], item["code"]))
    attested = isinstance(ledger, dict) and ledger.get("attested") is True
    highest = max(progress.values(), default=-1)
    if violations:
        status = "RUNTIME_EVIDENCE_FAILED"
    elif attested and proofs and highest == CAPABILITY_STATES.index("enforced"):
        status = "RUNTIME_ENFORCED"
    elif highest >= CAPABILITY_STATES.index("observed"):
        status = "RUNTIME_OBSERVED"
    elif highest >= CAPABILITY_STATES.index("parsed"):
        status = "RUNTIME_PARSED"
    else:
        status = "RUNTIME_DECLARED"
    return {
        "attested": attested,
        "capability_states": {name: CAPABILITY_STATES[index] for name, index in sorted(progress.items())},
        "passed": not violations,
        "presented_claims": sorted(presented),
        "schema_version": "fournets.run_ledger.validation.v1",
        "status": status,
        "terminal_event": terminal,
        "verified_enforcement_proofs": sorted(proofs),
        "violations": violations,
    }
