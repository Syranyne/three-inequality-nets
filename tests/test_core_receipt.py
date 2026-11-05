# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

from three_inequality_nets.core.receipt import validate
from tests.support import ROOT, load_json


def test_template_receipt_passes():
    report = validate(load_json(ROOT / "templates" / "receipt.json"), ROOT)
    assert report["passed"] is True
    assert report["candidate_passed"] is True


def test_self_report_alone_fails():
    payload = load_json(ROOT / "templates" / "receipt.json")
    payload["self_report_not_sufficient"] = False
    report = validate(payload, ROOT)
    assert any(item["code"] == "SELF_REPORT_ONLY" for item in report["findings"])


def test_green_result_must_exit_zero():
    payload = load_json(ROOT / "templates" / "receipt.json")
    for item in payload["tests"]:
        if item["phase"] == "GREEN":
            item["observed_exit_code"] = 1
    report = validate(payload, ROOT)
    assert any(item["code"] == "GREEN_RESULT" for item in report["findings"])
