# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""通用字段、相对路径和摘要。"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


def is_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def text_list(value: Any) -> bool:
    return isinstance(value, list) and all(is_text(item) for item in value)


def is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in value)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stable_relative(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip()
    if text != value or not text:
        return False
    if "\\" in text or text.startswith(("/", "~")):
        return False
    if "$" in text or "%" in text:
        return False
    if re.match(r"^[A-Za-z]:", text):
        return False
    parts = text.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return False
    return True


def inside_or_equal(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def resolve_inside(root: Path, relative: str) -> Path:
    if not stable_relative(relative):
        raise ValueError("path is not a stable relative path")
    base = root.resolve()
    target = (base / relative).resolve()
    if target != base and base not in target.parents:
        raise ValueError("path escapes the project root")
    return target


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def user_message_ok(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and value.get("source_type") == "USER_MESSAGE"
        and is_text(value.get("message_id"))
        and is_text(value.get("exact_quote"))
    )
