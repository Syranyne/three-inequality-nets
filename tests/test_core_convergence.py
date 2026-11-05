# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

import copy

from three_inequality_nets.core.convergence import validate
from three_inequality_nets.core.schema import canonical_hash, file_sha256
from tests.support import ROOT, load_json


def test_template_convergence_passes():
    report = validate(load_json(ROOT / "templates" / "convergence.json"), ROOT)
    assert report["passed"] is True


def test_pass_closure_cannot_hide_an_open_blocker():
    payload = load_json(ROOT / "templates" / "convergence.json")
    digest = file_sha256(ROOT / "templates" / "fixtures" / "candidate.txt")
    payload["findings"] = [
        {
            "classification": "FROZEN_REQUIREMENT_VIOLATION",
            "criterion_id": "AC-01",
            "current_candidate_effect": "BLOCK_CURRENT_CANDIDATE",
            "evidence": {
                "observed_violation": "the frozen check is still open",
                "path": "templates/fixtures/candidate.txt",
                "sha256": digest,
            },
            "finding_id": "F-01",
            "severity": "P1",
            "status": "OPEN",
        }
    ]
    report = validate(payload, ROOT)
    codes = {item["code"] for item in report["findings"]}
    assert "BLOCKER_DERIVATION" in codes
    assert "OPEN_BLOCKER_STATE" in codes


def test_baseline_change_without_binding_fails():
    previous = load_json(ROOT / "templates" / "convergence.json")
    current = copy.deepcopy(previous)
    current["baseline"]["baseline_id"] = "base-2"
    current["revision"]["sequence"] = 2
    current["revision"]["change_type"] = "AUTHORIZE"
    current["revision"]["previous_record_sha256"] = "cd" * 32
    current["round_state"]["attempt_number"] = 2
    report = validate(current, ROOT, previous, "cd" * 32)
    assert any(item["code"] == "BASELINE_UNBOUND" for item in report["findings"])


def test_binding_name_is_not_a_channel_secret():
    source = (ROOT / "three_inequality_nets" / "core" / "convergence.py").read_text(encoding="utf-8")
    assert "binding_sha256" in source
    assert "BASELINE_UNBOUND" in source
