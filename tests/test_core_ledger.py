# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

import copy

from three_inequality_nets.core.ledger import evaluate
from three_inequality_nets.core.schema import canonical_hash
from tests.support import ROOT, load_json


def test_template_ledger_passes():
    report = evaluate(load_json(ROOT / "templates" / "run_ledger.json"), ROOT)
    assert report["passed"] is True


def test_attested_without_proof_fails():
    payload = load_json(ROOT / "templates" / "run_ledger.json")
    payload["attested"] = True
    report = evaluate(payload, ROOT)
    assert report["passed"] is False
    assert any(item["code"] == "attested_without_enforcement" for item in report["violations"])


def test_completion_requires_executed_evidence():
    payload = load_json(ROOT / "templates" / "run_ledger.json")
    payload["events"][-1]["type"] = "run.completed"
    payload["contract"]["status"] = "COMPLETED"
    payload["contract"]["evidence"]["open_items"] = []
    payload["contract"]["evidence"]["observed"] = list(payload["contract"]["evidence"]["required"])
    payload["contract_sha256"] = canonical_hash(payload["contract"])
    payload["events"][1]["contract_sha256"] = payload["contract_sha256"]
    payload["completion_evidence"] = [{"kind": "note", "produced_by": "worker-a", "timestamp": "2026-01-15T00:00:00Z"}]
    report = evaluate(payload, ROOT)
    assert any(item["code"] == "completion_not_executed" for item in report["violations"])
    assert copy.deepcopy(payload)["completion_evidence"][0]["kind"] == "note"


def test_completion_accepts_receipt_bound_to_this_ledger(tmp_path):
    import shutil
    from three_inequality_nets.core.claim import binding
    from three_inequality_nets.core.sealing import write_receipt
    from three_inequality_nets.core.schema import file_sha256
    (tmp_path / "reviewers").mkdir()
    shutil.copyfile(ROOT / "reviewers" / "roster.json", tmp_path / "reviewers" / "roster.json")
    (tmp_path / "note.txt").write_text("done\n", encoding="utf-8")
    (tmp_path / "out.txt").write_text("ran\n", encoding="utf-8")
    payload = load_json(ROOT / "templates" / "run_ledger.json")
    payload["events"][-1]["type"] = "run.completed"
    payload["contract"]["status"] = "COMPLETED"
    payload["contract"]["evidence"]["open_items"] = []
    payload["contract"]["evidence"]["observed"] = list(payload["contract"]["evidence"]["required"])
    payload["contract_sha256"] = canonical_hash(payload["contract"])
    payload["events"][1]["contract_sha256"] = payload["contract_sha256"]
    item = {"kind": "note", "path": "note.txt", "sha256": file_sha256(tmp_path / "note.txt"),
            "produced_by": "worker-a", "timestamp": "2026-01-15T00:00:00Z", "command": ["py", "-3", "x"],
            "exit_code": 0, "output_summary": "ran", "output_path": "out.txt",
            "output_sha256": file_sha256(tmp_path / "out.txt"),
            "started_at": "2026-01-15T00:00:00Z", "finished_at": "2026-01-15T00:00:01Z"}
    payload["completion_evidence"] = [item]
    write_receipt(tmp_path, binding({**payload, "id": payload["run_id"]}), item)
    report = evaluate(payload, tmp_path)
    assert not any(v["code"] == "completion_not_executed" for v in report["violations"]), report
    other = copy.deepcopy(payload)
    other["run_id"] = "another-run"
    report = evaluate(other, tmp_path)
    assert any(v["code"] == "completion_not_executed" for v in report["violations"])
