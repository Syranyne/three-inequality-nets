# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

import hashlib

from three_inequality_nets.core.evidence import assess


def _item(digest: str, **extra):
    item = {
        "kind": "note",
        "path": "note.txt",
        "produced_by": "worker-a",
        "reviewed_by": "reviewer-b",
        "sha256": digest,
        "timestamp": "2026-01-15T00:00:02Z",
    }
    item.update(extra)
    return item


def _file(tmp_path):
    target = tmp_path / "note.txt"
    target.write_bytes(b"hello\n")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    return digest


def test_hash_mismatch(tmp_path):
    _file(tmp_path)
    level, reasons, forged = assess(_item("0" * 64, reviewed_by=""), tmp_path)
    assert forged is True
    assert level == "claimed"
    assert "hash_mismatch" in reasons


def test_reviewer_matches_executor(tmp_path):
    digest = _file(tmp_path)
    out = tmp_path / "out.txt"
    out.write_text("one line\n", encoding="utf-8")
    level, reasons, forged = assess(
        _item(
            digest,
            produced_by="worker-a",
            reviewed_by="worker-a",
            command=["py", "-3", "check"],
            exit_code=0,
            output_summary="one line",
            output_path="out.txt",
            output_sha256=hashlib.sha256(out.read_bytes()).hexdigest(),
            started_at="2026-01-15T00:00:00Z",
            finished_at="2026-01-15T00:00:02Z",
        ),
        tmp_path,
    )
    # 没有独立执行回执：执行自报不算数（规则 1），直接判伪造。
    assert forged is True
    assert level == "artifact"
    assert "execution_unverified" in reasons


def test_reviewer_matches_executor_with_receipt(tmp_path):
    import shutil
    from three_inequality_nets.core.sealing import write_receipt
    from tests.support import ROOT
    (tmp_path / "reviewers").mkdir()
    shutil.copyfile(ROOT / "reviewers" / "roster.json", tmp_path / "reviewers" / "roster.json")
    digest = _file(tmp_path)
    out = tmp_path / "out.txt"
    out.write_text("one line\n", encoding="utf-8")
    item = _item(
        digest,
        produced_by="worker-a",
        reviewed_by="worker-a",
        command=["py", "-3", "check"],
        exit_code=0,
        output_summary="one line",
        output_path="out.txt",
        output_sha256=hashlib.sha256(out.read_bytes()).hexdigest(),
        started_at="2026-01-15T00:00:00Z",
        finished_at="2026-01-15T00:00:02Z",
    )
    write_receipt(tmp_path, ("t", "0" * 64), item)
    level, reasons, forged = assess(item, tmp_path, ("t", "0" * 64))
    assert forged is True
    assert level == "executed"
    assert "reviewer_is_executor" in reasons


def test_exit_zero_without_output(tmp_path):
    digest = _file(tmp_path)
    level, reasons, forged = assess(
        _item(digest, reviewed_by="", exit_code=0, output_summary="", command=[]),
        tmp_path,
    )
    assert forged is True
    assert level == "artifact"
    assert "exit_without_output" in reasons
