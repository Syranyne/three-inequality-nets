# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

import copy

from three_inequality_nets.core.contract import validate
from tests.support import ROOT, load_json


def _payload():
    return load_json(ROOT / "templates" / "task_contract.json")


def test_template_contract_passes():
    report = validate(_payload(), root=ROOT)
    assert report["passed"] is True


def test_missing_objective_fails():
    payload = _payload()
    payload["objective"] = " "
    report = validate(payload, root=ROOT)
    assert report["passed"] is False
    assert any(item["code"] == "EMPTY_TEXT" for item in report["findings"])


def test_retrieved_text_cannot_authorize():
    payload = _payload()
    payload["claims"][0]["source_type"] = "RETRIEVED_DOCUMENT"
    payload["claims"][0]["state"] = "AUTHORIZED"
    report = validate(payload, root=ROOT)
    assert any(item["code"] == "CLAIM_SOURCE_STATE_CONFLICT" for item in report["findings"])


def test_parent_segment_is_rejected():
    payload = _payload()
    payload["scope"]["read_roots"] = ["workspace/" + ".." + "/outside"]
    report = validate(payload, root=ROOT)
    assert any(item["code"] == "PATH_UNSTABLE" for item in report["findings"])


def test_drive_path_is_rejected():
    payload = _payload()
    payload["operations"][0]["target"] = "D:" + "\\" + "outside"
    report = validate(payload, root=ROOT)
    assert any(item["code"] == "OPERATION_PATH_INVALID" for item in report["findings"])


def test_claim_statement_cannot_be_rewritten_in_place():
    previous = _payload()
    current = copy.deepcopy(previous)
    current["revision"]["sequence"] = 2
    current["revision"]["change_type"] = "CLARIFY"
    current["revision"]["previous_contract_sha256"] = "ab" * 32
    current["claims"][0]["statement"] = "rewritten statement"
    current["claims"][0]["previous_state"] = previous["claims"][0]["state"]
    report = validate(current, previous, "ab" * 32, root=ROOT)
    assert any(item["code"] == "CLAIM_STATEMENT_REWRITE" for item in report["findings"])
