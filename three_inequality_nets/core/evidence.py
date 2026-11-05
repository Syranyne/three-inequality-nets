# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""证据从声称晋升到独立复核。"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from three_inequality_nets.core.attest import attest, same_principal
from three_inequality_nets.core.schema import file_sha256, is_sha256, is_text, stable_relative
from three_inequality_nets.nets.composition.schema import parse_time

LEVELS = ("claimed", "artifact", "executed", "reviewed")


def level_rank(level: str | None) -> int:
    if level in LEVELS:
        return LEVELS.index(level)
    return -1


def _command_ok(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(is_text(part) for part in value)


def _resolve_file(root: Path, relative: Any) -> Path | None:
    if not stable_relative(relative):
        return None
    try:
        target = (root.resolve() / str(relative)).resolve()
        base = root.resolve()
        if target != base and base not in target.parents:
            return None
        return target
    except OSError:
        return None


def _hash_matches(path: Path, digest: Any) -> bool:
    if not is_sha256(digest) or not path.is_file():
        return False
    return file_sha256(path).casefold() == str(digest).casefold()


def _times_ok(started: Any, finished: Any) -> tuple[bool, bool]:
    """返回 (可比较, 顺序正确)。解析失败视为不可比较。"""
    try:
        start = parse_time(started)
        end = parse_time(finished)
    except (TypeError, ValueError, OverflowError):
        return False, False
    return True, start <= end


# 允许的时钟偏差。证据时间晚于「校验时刻 + 偏差」即视为伪造。
CLOCK_SKEW = timedelta(minutes=5)
NOW_ENV = "FOURNETS_NOW"


def check_now() -> datetime:
    """校验时刻。可用 FOURNETS_NOW（带时区 ISO 8601）固定，便于复现。"""
    raw = os.environ.get(NOW_ENV)
    if raw:
        try:
            return parse_time(raw)
        except (TypeError, ValueError, OverflowError):
            pass
    return datetime.now(timezone.utc)


def _future(value: Any) -> bool:
    if not is_text(value):
        return False
    try:
        moment = parse_time(value)
    except (TypeError, ValueError, OverflowError):
        return False
    return moment > check_now() + CLOCK_SKEW


RECEIPT_SCHEMA = "fournets.exec_receipt.v1"

# 证据条目允许的字段（规则 4：默认拒绝，未列出的字段一律判伪造）。
ITEM_FIELDS = frozenset({
    "kind", "path", "sha256", "produced_by", "reviewed_by", "timestamp", "forged",
    "command", "exit_code", "output_summary", "started_at", "finished_at",
    "output_path", "output_sha256", "receipt_path", "receipt_sha256", "review_path", "review_sha256",
})


def receipt_parts(receipt: dict[str, Any]) -> tuple[Any, ...]:
    """执行回执签名覆盖的字段（绑定与角色由 attest 统一加在前面）。"""
    return (
        str(receipt.get("evidence_sha256", "")).casefold(),
        json.dumps(receipt.get("command"), ensure_ascii=False, separators=(",", ":")),
        receipt.get("exit_code"),
        str(receipt.get("output_sha256", "")).casefold(),
        receipt.get("started_at"),
        receipt.get("finished_at"),
        receipt.get("producer"),
        receipt.get("runner"),
    )


def review_parts(evidence_digest: str, reviewer: str, conclusion: Any, producer: Any) -> tuple[Any, ...]:
    return (evidence_digest, reviewer, conclusion, producer)


def _same_time(left: Any, right: Any) -> bool:
    try:
        return parse_time(left) == parse_time(right)
    except (TypeError, ValueError, OverflowError):
        return False


def _load(path: Path | None) -> Any:
    if path is None:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None


def verify_receipt(
    item: dict[str, Any], root: Path, binding: tuple[str, str] | None, taken: set[Path]
) -> tuple[str | None, list[str], bool]:
    """执行回执（规则 1 的「独立来源」）。返回 (回执记录的产出者, 原因, 是否伪造)。"""
    receipt_path = item.get("receipt_path")
    if receipt_path in (None, "") and item.get("receipt_sha256") in (None, ""):
        return None, ["execution_unverified"], True
    receipt_file = _resolve_file(root, receipt_path)
    if receipt_file is None or not _hash_matches(receipt_file, item.get("receipt_sha256")):
        return None, ["receipt_missing"], True
    if receipt_file in taken:
        return None, ["receipt_is_evidence"], True
    receipt = _load(receipt_file)
    if not isinstance(receipt, dict) or receipt.get("schema_version") != RECEIPT_SCHEMA:
        return None, ["receipt_missing"], True
    digest = item.get("sha256")
    if (
        not is_sha256(digest)
        or str(receipt.get("evidence_sha256", "")).casefold() != str(digest).casefold()
        or receipt.get("command") != item.get("command")
        or receipt.get("exit_code") != item.get("exit_code")
        or str(receipt.get("output_sha256", "")).casefold() != str(item.get("output_sha256", "")).casefold()
        or not _same_time(receipt.get("started_at"), item.get("started_at"))
        or not _same_time(receipt.get("finished_at"), item.get("finished_at"))
        or not is_text(receipt.get("producer"))
    ):
        return None, ["receipt_mismatch"], True
    failure = attest(root, binding, "runner", receipt.get("runner"), receipt.get("signature"),
                     receipt_parts(receipt), claimants=[receipt["producer"]])
    if failure is not None:
        return None, ["receipt_" + failure], True
    return str(receipt["producer"]), [], False


def assess(
    item: Any,
    root: Path,
    binding: tuple[str, str] | None = None,
) -> tuple[str, list[str], bool]:
    """返回 (已证明等级, 原因, 是否伪造)。

    artifact：验证器自己重算文件哈希得到。
    executed：只认独立执行方签名的回执（规则 1），产出者身份取回执（规则 3）。
    reviewed：只认名册复核人对本次声明（规则 2）的签名，复核人与产出者 principal 不同。
    凡是声称执行或复核的条目，不论阶段都完整核验；声称了却核不过即判伪造（规则 4）。
    binding 为 None（调用方没有声明可绑定）时，任何签名都不承认。
    """
    reasons: list[str] = []
    forged = False
    if not isinstance(item, dict) or not is_text(item.get("kind")):
        return "claimed", ["missing_kind"], True
    unknown = sorted(set(item) - ITEM_FIELDS)
    if unknown:
        return "claimed", ["unknown_field"], True

    level = "claimed"
    relative = item.get("path")
    digest = item.get("sha256")
    evidence_file = _resolve_file(root, relative)
    if evidence_file is None or not is_sha256(digest):
        reasons.append("bad_path")
        forged = True
    elif not evidence_file.is_file():
        reasons.append("missing_file")
        forged = True
    elif file_sha256(evidence_file).casefold() != str(digest).casefold():
        reasons.append("hash_mismatch")
        forged = True
    else:
        level = "artifact"

    for key in ("started_at", "finished_at", "timestamp"):
        if _future(item.get(key)):
            reasons.append("future_time")
            forged = True
            break
    started, finished = item.get("started_at"), item.get("finished_at")
    if is_text(started) or is_text(finished):
        comparable, ordered = _times_ok(started, finished)
        if not (comparable and ordered):
            reasons.append("time_order")
            forged = True

    claims_execution = any(item.get(key) not in (None, "") for key in ("command", "exit_code", "output_path", "receipt_path"))
    if not claims_execution:
        if item.get("review_path") not in (None, "") or is_text(item.get("reviewed_by")):
            reasons.append("review_without_execution")
            forged = True
        return level, reasons, forged

    out_file = _resolve_file(root, item.get("output_path"))
    review_file = _resolve_file(root, item.get("review_path"))
    if (
        not _command_ok(item.get("command"))
        or type(item.get("exit_code")) is not int
        or item.get("exit_code") != 0
        or out_file is None
        or not _hash_matches(out_file, item.get("output_sha256"))
    ):
        reasons.append("exit_without_output")
        return level, reasons, True
    if out_file == evidence_file or str(item.get("output_sha256")).casefold() == str(digest).casefold():
        reasons.append("output_is_evidence")
        return level, reasons, True
    taken = {path for path in (evidence_file, out_file, review_file) if path is not None}
    producer, receipt_reasons, receipt_forged = verify_receipt(item, root, binding, taken)
    reasons.extend(receipt_reasons)
    if producer is None or forged or level != "artifact":
        return level, reasons, True
    if not is_text(item.get("produced_by")) or not same_principal(root, item.get("produced_by"), producer):
        reasons.append("producer_mismatch")
        return level, reasons, True
    level = "executed"

    reviewed = item.get("reviewed_by")
    if item.get("review_path") in (None, "") and not is_text(reviewed):
        return level, reasons, False
    if not is_text(reviewed) or same_principal(root, reviewed, producer):
        reasons.append("reviewer_is_executor")
        return level, reasons, True
    receipt_file = _resolve_file(root, item.get("receipt_path"))
    if review_file is None or review_file in (evidence_file, out_file, receipt_file):
        reasons.append("review_is_evidence")
        return level, reasons, True
    if not _hash_matches(review_file, item.get("review_sha256")):
        reasons.append("review_missing")
        return level, reasons, True
    record = _load(review_file)
    if (
        not isinstance(record, dict)
        or str(record.get("evidence_sha256", "")).casefold() != str(digest).casefold()
        or record.get("reviewer") != reviewed
        or record.get("conclusion") not in ("accept", "pass", True)
    ):
        reasons.append("review_missing")
        return level, reasons, True
    failure = attest(root, binding, "reviewer", reviewed, record.get("signature"),
                     review_parts(str(digest).casefold(), str(reviewed), record.get("conclusion"), producer),
                     claimants=[producer, item.get("produced_by")])
    if failure is not None:
        reasons.append("review_" + failure if failure in ("unbound", "not_independent") else failure)
        return level, reasons, True
    return "reviewed", reasons, False
