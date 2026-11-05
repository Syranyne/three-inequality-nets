# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""用例装载。"""

from __future__ import annotations

import json
from pathlib import Path

from three_inequality_nets.nets.catalog import NETS
from three_inequality_nets.cli import check_path

ROOT = Path(__file__).resolve().parents[1]


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def case_paths(net: str | None = None) -> list[Path]:
    nets = [net] if net else list(NETS)
    found: list[Path] = []
    for name in nets:
        found.extend(sorted((ROOT / "cases" / name).glob("*.input.json")))
    return found


def matches(path: Path) -> bool:
    payload = load_json(path)
    expect = load_json(path.with_name(path.name.replace(".input.json", ".expect.json")))
    result = check_path(payload["net"], path, ROOT)
    return (result["verdict"] == expect["verdict"] and result["broken_link"] == expect["broken_link"]
            and all(code in result["reasons"] for code in expect.get("required_reasons", [])))


def referenced_files(obj) -> set[str]:
    """payload 里所有指向仓库文件的相对路径（*_path / *_ref / path）。"""
    found: set[str] = set()

    def walk(value, key=""):
        if isinstance(value, dict):
            for name, inner in value.items():
                walk(inner, name)
        elif isinstance(value, list):
            for inner in value:
                walk(inner, key)
        elif isinstance(value, str) and (key == "path" or key.endswith("_path") or key.endswith("_ref")):
            if (ROOT / value).is_file():
                found.add(value)

    walk(obj)
    return found


def sandbox_root(obj, dest: Path | None = None) -> Path:
    """把 payload 引用的文件和名册复制到临时目录，返回沙箱根目录（不写仓库）。"""
    import shutil
    import tempfile

    root = Path(dest) if dest is not None else Path(tempfile.mkdtemp(prefix="three_inequality_nets-sb-"))
    for rel in sorted(referenced_files(obj) | {"reviewers/roster.json"}):
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel, target)
    return root


def resealed(obj, dest: Path | None = None):
    """沙箱 + 按改动后的声明重签（隔离语义检查用）。返回 (obj, root)。"""
    from three_inequality_nets.core.sealing import reseal

    root = sandbox_root(obj, dest)
    reseal(obj, root)
    return obj, root
