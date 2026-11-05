# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""目录、发布清单和 README 结构。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REQUIRED_DIRS = (
    "three_inequality_nets",
    "three_inequality_nets/core",
    "three_inequality_nets/nets/authority",
    "three_inequality_nets/nets/learning_claim",
    "three_inequality_nets/nets/retrieval",
    "three_inequality_nets/nets/production",
    "three_inequality_nets/nets/composition",
    "templates",
    "cases/authority",
    "cases/learning_claim",
    "cases/retrieval",
    "cases/production",
    "cases/composition",
    "cases/core",
    "examples/demo",
    "tests",
    "dev_tools",
    "docs",
)
README_HEADINGS = (
    "## 为什么需要它",
    "## 五张网",
    "## 快速开始",
    "## 定位",
    "## 反例贡献",
    "## 许可证",
)
_mark = "\u5948"
EXCLUDED_FILES = {"第五张网_工程单.md", "第五张网_开工提示词.md", "四张网_代码_工程单.md", "验收报告.md", "待" + _mark + _mark + "确认.md"}
EXCLUDED_DIRS = {"_备份", "__pycache__", ".pytest_cache", ".git"}


def _configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if not callable(reconfigure):
            continue
        try:
            reconfigure(encoding="utf-8")
        except (OSError, ValueError):
            pass


def _emit(text: str) -> None:
    sys.stdout.buffer.write(text.encode("utf-8"))


def _whitelist(root: Path) -> list[str]:
    path = root / "release_whitelist.txt"
    if not path.is_file():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    parser = argparse.ArgumentParser(description="check repository shape")
    parser.add_argument("--root", default=".")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    problems: list[str] = []
    for relative in REQUIRED_DIRS:
        if not (root / relative).is_dir():
            problems.append(f"dir {relative}")
    readme = root / "README.md"
    if not readme.is_file():
        problems.append("readme")
    else:
        text = readme.read_text(encoding="utf-8")
        positions = [text.find(heading) for heading in README_HEADINGS]
        if any(pos < 0 for pos in positions) or positions != sorted(positions):
            problems.append("readme headings")
        if "three_inequality_nets demo" not in text or "Issues" not in text or "@" in text:
            problems.append("readme markers")
        if len(text.splitlines()) > 120:
            problems.append("readme length")
    listed = _whitelist(root)
    if not listed:
        problems.append("whitelist")
    if listed != sorted(listed):
        problems.append("whitelist order")
    for item in listed:
        if "\\" in item or item in EXCLUDED_FILES or item.split("/")[0] in EXCLUDED_DIRS:
            problems.append(f"whitelist bad {item}")
        elif not (root / item).is_file():
            problems.append(f"missing {item}")
    listed_set = set(listed)
    if root.is_dir():
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in EXCLUDED_DIRS for part in path.parts):
                continue
            relative = path.relative_to(root).as_posix()
            if relative in EXCLUDED_FILES:
                if relative in listed_set:
                    problems.append(f"excluded listed {relative}")
                continue
            if relative not in listed_set:
                problems.append(f"extra {relative}")
    if problems:
        _emit("FAIL " + "; ".join(problems) + "\n")
        return 1
    _emit("PASS\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
