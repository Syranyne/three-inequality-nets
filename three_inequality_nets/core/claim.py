# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""声明绑定（规则 2）：一份签名只对一次声明有效。

claim_sha256 覆盖声明全文，只去掉「签名文件自身的位置与哈希」这几类字段
（复核、回执、基线竞品出具文件：它们的签名又要覆盖声明哈希，放进来会循环），
以及例外归档开关 outside_model / unexplained（归档另有哈希绑定）。
时间字段按解析后的时刻规范化，书写格式不同的同一时刻哈希相同。
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from three_inequality_nets.core.schema import is_text
from three_inequality_nets.nets.composition.schema import parse_time

TOP_EXCLUDED = ("outside_model", "unexplained")
SIGNED_FILE_KEYS = frozenset({
    "review_path", "review_sha256", "receipt_path", "receipt_sha256",
})
SOURCE_KEYS = frozenset({"source_ref", "source_sha256"})


def _canon(value: Any, key: str = "", in_bench_row: bool = False) -> Any:
    if isinstance(value, dict):
        out = {}
        for name, inner in value.items():
            if name in SIGNED_FILE_KEYS or (in_bench_row and name in SOURCE_KEYS):
                continue
            row = name in ("baseline", "competitors") and key == "benchmark"
            out[name] = _canon(inner, name, row)
        return out
    if isinstance(value, list):
        return [_canon(inner, key, in_bench_row) for inner in value]
    if isinstance(value, str) and (key.endswith("_at") or key == "timestamp"):
        try:
            return parse_time(value).isoformat()
        except (TypeError, ValueError, OverflowError):
            return value
    return value


def claim_sha256(payload: dict[str, Any]) -> str:
    core = {key: value for key, value in payload.items() if key not in TOP_EXCLUDED}
    text = json.dumps(_canon(core), sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def binding(payload: Any) -> tuple[str, str] | None:
    """(case_id, claim_sha256)。没有用例 id 返回 None：一切签名都过不了（规则 4）。"""
    if not isinstance(payload, dict) or not is_text(payload.get("id")):
        return None
    try:
        return str(payload["id"]), claim_sha256(payload)
    except (TypeError, ValueError):
        return None
