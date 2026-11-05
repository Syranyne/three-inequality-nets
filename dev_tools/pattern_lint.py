# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""拦住把两个环节写成对照句式的文本。"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


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


def _patterns() -> list[tuple[str, re.Pattern[str]]]:
    first = "不" + "是"
    second = "并" + "非"
    third = "而" + "是"
    fourth = "，"
    fifth = "是"
    return [
        ("contrast#1", re.compile(first + r"[\s\S]{0,80}?" + third)),
        ("contrast#2", re.compile(second + r"[\s\S]{0,80}?" + third)),
        ("contrast#3", re.compile(first + r"[\s\S]{0,40}?" + fourth + r"[\s\S]{0,40}?" + fifth)),
    ]


def _files(root: Path, target: str | None) -> list[Path]:
    if target:
        path = Path(target)
        return [path if path.is_absolute() else root / path]
    whitelist = root / "release_whitelist.txt"
    if not whitelist.is_file():
        return []
    found: list[Path] = []
    for line in whitelist.read_text(encoding="utf-8").splitlines():
        item = line.strip()
        if item.endswith((".md", ".py", ".txt", ".json")):
            found.append(root / item)
    return found


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    parser = argparse.ArgumentParser(description="lint contrast patterns")
    parser.add_argument("--target")
    parser.add_argument("--root", default=".")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    hits: list[str] = []
    patterns = _patterns()
    for path in _files(root, args.target):
        if not path.is_file():
            hits.append(f"{path.name}:0:missing#1")
            continue
        text = path.read_text(encoding="utf-8")
        try:
            relative = path.resolve().relative_to(root).as_posix()
        except ValueError:
            relative = path.name
        for lineno, line in enumerate(text.splitlines(), start=1):
            window = text
            for name, pattern in patterns:
                if pattern.search(window):
                    hits.append(f"{relative}:{lineno}:{name}")
                    break
            break
        else:
            continue
        # The search above is document-wide; one hit per file is enough.
    # Re-scan properly per file without the accidental loop break logic.
    hits = []
    for path in _files(root, args.target):
        if not path.is_file():
            hits.append(f"{path.name}:0:missing#1")
            continue
        text = path.read_text(encoding="utf-8")
        try:
            relative = path.resolve().relative_to(root).as_posix()
        except ValueError:
            relative = path.name
        for name, pattern in patterns:
            match = pattern.search(text)
            if match:
                lineno = text[: match.start()].count("\n") + 1
                hits.append(f"{relative}:{lineno}:{name}")
    if hits:
        _emit("\n".join(hits) + "\n")
        _emit("FAIL\n")
        return 1
    _emit("PASS\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
