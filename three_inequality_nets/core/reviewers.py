# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""独立复核人名册与复核签名。

- 名册固定在 `reviewers/roster.json`（或环境变量 FOURNETS_REVIEWER_ROSTER 指向的文件），
  不在证据允许目录内，声称方的输入不能指定名册位置。
- 每位复核人登记 `key_sha256`。复核记录必须带 `signature`
  = HMAC-SHA256(key, message)。密钥只从环境变量
  FOURNETS_REVIEWER_KEY_<ID> 读取（ID 取复核人 id 的大写字母数字，其余字符换成 _）。
- 每个条目用 `roles` 登记能签什么：reviewer / attester / runner。
- 名册里标 `"fixture": true` 的条目附带公开测试密钥，只在环境变量
  FOURNETS_FIXTURE_REVIEWERS=1 时承认（测试、run-cases、demo），校验真实主张时不承认。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from pathlib import Path
from typing import Any

from three_inequality_nets.nets.composition.identity import identity_key

ROSTER_RELATIVE = "reviewers/roster.json"
FIXTURE_ENV = "FOURNETS_FIXTURE_REVIEWERS"
ROSTER_ENV = "FOURNETS_REVIEWER_ROSTER"


def fixture_mode() -> bool:
    return os.environ.get(FIXTURE_ENV) == "1"


def _env_name(reviewer_id: str) -> str:
    return "FOURNETS_REVIEWER_KEY_" + re.sub(r"[^A-Z0-9]", "_", reviewer_id.upper())


def load_roster(root: Path) -> list[dict[str, Any]]:
    override = os.environ.get(ROSTER_ENV)
    path = Path(override) if override else Path(root) / ROSTER_RELATIVE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return []
    rows = data.get("reviewers") if isinstance(data, dict) else None
    return [row for row in rows if isinstance(row, dict) and isinstance(row.get("id"), str)] if isinstance(rows, list) else []


def _key_for(row: dict[str, Any]) -> bytes | None:
    expected = row.get("key_sha256")
    if not isinstance(expected, str):
        return None
    if row.get("fixture") is True:
        if not fixture_mode() or not isinstance(row.get("fixture_key"), str):
            return None
        key = row["fixture_key"].encode("utf-8")
    else:
        raw = os.environ.get(_env_name(row["id"]))
        if not raw:
            return None
        key = raw.encode("utf-8")
    if hashlib.sha256(key).hexdigest() != expected.casefold():
        return None
    return key


def find(root: Path, name: str) -> dict[str, Any] | None:
    """按同形字折叠后的 id 找名册条目；名册内必须是精确 id 才算。"""
    for row in load_roster(root):
        if row["id"] == name:
            return row
    return None


def message(*parts: Any) -> bytes:
    return "\n".join(str(part) for part in parts).encode("utf-8")


def sign(key: bytes, *parts: Any) -> str:
    return hmac.new(key, message(*parts), hashlib.sha256).hexdigest()


ROLES = ("reviewer", "attester", "runner")


def verify(root: Path, reviewer: Any, signature: Any, *parts: Any, role: str | None = None) -> str | None:
    """返回 None 表示通过，否则返回原因码。

    role：名册条目必须在 `roles` 里登记这个角色（reviewer 复核 / attester 出具基线竞品 /
    runner 执行回执）。一把密钥只能干登记过的事。
    """
    if not isinstance(reviewer, str) or not reviewer:
        return "reviewer_not_in_roster"
    row = find(root, reviewer)
    if row is None:
        return "reviewer_not_in_roster"
    if identity_key(row["id"]) != identity_key(reviewer):
        return "reviewer_not_in_roster"
    if role is not None:
        roles = row.get("roles")
        if not isinstance(roles, list) or role not in roles:
            return "reviewer_role"
    key = _key_for(row)
    if key is None:
        return "reviewer_key_unavailable"
    if not isinstance(signature, str) or not hmac.compare_digest(sign(key, *parts), signature):
        return "review_signature"
    return None


def fixture_sign(root: Path, reviewer: str, *parts: Any) -> str:
    """测试与样例用：用名册里公开的测试密钥签名。"""
    row = find(root, reviewer)
    if row is None or row.get("fixture") is not True:
        raise KeyError(reviewer)
    return sign(row["fixture_key"].encode("utf-8"), *parts)
