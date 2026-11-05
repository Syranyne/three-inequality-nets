# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

from three_inequality_nets.demo_run import render
from tests.support import ROOT


def test_demo_catches_each_required_claim_and_one_pass():
    text, code = render(ROOT)
    rows = [line.split("\t") for line in text.splitlines()[1:]]
    assert code == 1
    assert [row[1] for row in rows] == ["FAIL", "FAIL", "FAIL", "FAIL", "FAIL", "PASS", "FAIL", "FAIL"]
    assert rows[0][3] == "claimed"
    assert rows[1][2] == "事实主张→写入授权"
    assert rows[2][2] == "窗口收到→进入训练集"
    assert rows[3][2] == "检索命中→语义理解"
    assert rows[4][2] == "生成能力→生产能力"
    assert rows[5][1] == "PASS"
    assert rows[6][2] == "冲突时会正确调权→造成后果后能自主纠偏"
    assert rows[6][3] == "L3"
    assert rows[7][2] == "能同时做→冲突时会正确调权"
    assert rows[7][3] == "L2"
    assert "outside_model:explained_by_net" in rows[7][4]
    expected = (ROOT / "examples" / "demo" / "expected_output.txt").read_bytes()
    assert text.encode("utf-8") == expected
