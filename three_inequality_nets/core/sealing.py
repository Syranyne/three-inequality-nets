# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""测试与样例用：用名册里的公开测试密钥补执行回执、复核签名和基线/竞品出具签名。

只用 fixture 条目的公开密钥，真实主张校验时这些签名不被承认（见 reviewers.py）。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from three_inequality_nets.core import reviewers as roster
from three_inequality_nets.core.claim import binding as claim_binding
from three_inequality_nets.core.evidence import RECEIPT_SCHEMA, receipt_parts, review_parts
from three_inequality_nets.core.schema import file_sha256

RUNNER = "runner-lab-a"


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def receipt_relative(item: dict[str, Any]) -> str:
    base = str(item.get("output_path") or item.get("path"))
    return base + ".receipt.json"


def write_receipt(root: Path, bound: tuple[str, str], item: dict[str, Any], runner: str = RUNNER,
                  producer: str | None = None, relative: str | None = None) -> None:
    rel = relative or receipt_relative(item)
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "case_id": bound[0],
        "claim_sha256": bound[1],
        "evidence_sha256": str(item.get("sha256", "")).casefold(),
        "command": item.get("command"),
        "exit_code": item.get("exit_code"),
        "output_sha256": str(item.get("output_sha256", "")).casefold(),
        "started_at": item.get("started_at"),
        "finished_at": item.get("finished_at"),
        "producer": producer if producer is not None else item.get("produced_by"),
        "runner": runner,
    }
    receipt["signature"] = roster.fixture_sign(root, runner, bound[0], bound[1], "runner", *receipt_parts(receipt))
    _write_json(Path(root) / rel, receipt)
    item["receipt_path"] = rel
    item["receipt_sha256"] = file_sha256(Path(root) / rel)


def sign_review(root: Path, bound: tuple[str, str], item: dict[str, Any]) -> None:
    path = Path(root) / str(item["review_path"])
    record = json.loads(path.read_text(encoding="utf-8"))
    record["case_id"] = bound[0]
    record["claim_sha256"] = bound[1]
    record["signature"] = roster.fixture_sign(
        root, str(record["reviewer"]), bound[0], bound[1], "reviewer",
        *review_parts(str(record["evidence_sha256"]).casefold(), str(record["reviewer"]), record["conclusion"],
                      item.get("produced_by")),
    )
    _write_json(path, record)
    item["review_sha256"] = file_sha256(path)


def sign_source(root: Path, bound: tuple[str, str], row: dict[str, Any], metric: str) -> None:
    from three_inequality_nets.nets.production.validator import benchmark_parts

    path = Path(root) / str(row["source_ref"])
    data = json.loads(path.read_text(encoding="utf-8"))
    data["case_id"] = bound[0]
    data["claim_sha256"] = bound[1]
    data["signature"] = roster.fixture_sign(
        root, str(data["attested_by"]), bound[0], bound[1], "attester",
        *benchmark_parts(row.get("name"), metric, data["value"], data["origin"]),
    )
    _write_json(path, data)
    row["source_sha256"] = file_sha256(path)


def seal(payload: dict[str, Any], root: Path, receipts: bool = True) -> dict[str, Any]:
    """给能执行的证据补回执、给复核和出具文件重签，原地修改并返回 payload。"""
    bound = claim_binding(payload)
    if bound is None:
        return payload
    for slot in (payload.get("stages") or {}).values():
        for item in slot.get("evidence", []):
            if receipts and item.get("command") and item.get("exit_code") == 0 and item.get("output_path"):
                write_receipt(root, bound, item)
            if item.get("review_path"):
                sign_review(root, bound, item)
    bench = (payload.get("signals") or {}).get("benchmark")
    if isinstance(bench, dict):
        for row in [bench.get("baseline"), *(bench.get("competitors") or [])]:
            if isinstance(row, dict) and row.get("source_ref"):
                sign_source(root, bound, row, str(bench.get("metric")))
    return payload


def reseal(payload: dict[str, Any], root: Path) -> dict[str, Any]:
    """改动声明之后重签已有的回执、复核与出具文件（原路径），用来隔离语义检查。

    只在测试沙箱里用：相当于独立执行方、复核人、出具方对改动后的声明重新签字。
    """
    bound = claim_binding(payload)
    if bound is None:
        return payload
    for slot in (payload.get("stages") or {}).values():
        for item in slot.get("evidence", []):
            if item.get("receipt_path") and (Path(root) / str(item["receipt_path"])).is_file():
                old = json.loads((Path(root) / str(item["receipt_path"])).read_text(encoding="utf-8"))
                write_receipt(root, bound, item, runner=str(old.get("runner", RUNNER)), relative=str(item["receipt_path"]))
            if item.get("review_path") and (Path(root) / str(item["review_path"])).is_file():
                try:
                    sign_review(root, bound, item)
                except (KeyError, ValueError, TypeError):
                    pass
    bench = (payload.get("signals") or {}).get("benchmark")
    if isinstance(bench, dict):
        for row in [bench.get("baseline"), *(bench.get("competitors") or [])]:
            if isinstance(row, dict) and row.get("source_ref") and (Path(root) / str(row["source_ref"])).is_file():
                try:
                    sign_source(root, bound, row, str(bench.get("metric")))
                except (KeyError, ValueError, TypeError):
                    pass
    return payload
