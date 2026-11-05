# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""按外部词表和通用规则扫描发布清单。词和源路径都不写死在脚本里。"""

from __future__ import annotations

import argparse
import os
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


def _terms_from(path: Path, root: Path) -> list[str] | None:
    try:
        resolved = path.resolve()
    except OSError:
        return None
    if not resolved.is_file():
        return None
    try:
        root_resolved = root.resolve()
    except OSError:
        return None
    if resolved == root_resolved or root_resolved in resolved.parents:
        return None
    text = resolved.read_text(encoding="utf-8")
    terms = [line.strip() for line in text.splitlines() if line.strip()]
    if not terms:
        return None
    return terms


def _builtin_hits(line: str) -> list[str]:
    hits: list[str] = []
    drive = re.compile(r"[A-Za-z]:" + "\\\\")
    users = re.compile("\\\\" + "Users" + "\\\\", re.IGNORECASE)
    home = re.compile("/" + "home" + "/")
    temp = re.compile("%" + "TEMP" + "%", re.IGNORECASE)
    mail = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    prefix = re.compile("cod" + "ex-", re.IGNORECASE)
    if drive.search(line):
        hits.append("path#1")
    if users.search(line):
        hits.append("path#2")
    if home.search(line):
        hits.append("path#3")
    if temp.search(line):
        hits.append("path#4")
    if mail.search(line):
        hits.append("email#1")
    if prefix.search(line):
        hits.append("schema_prefix#1")
    return hits


def _scan_text(relative: str, text: str, terms: list[str]) -> list[str]:
    hits: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        folded = line.casefold()
        for index, term in enumerate(terms, start=1):
            if term.casefold() in folded:
                hits.append(f"{relative}:{lineno}:term#{index}")
        for kind in _builtin_hits(line):
            hits.append(f"{relative}:{lineno}:{kind}")
    return hits


def _iter_targets(root: Path, target: str | None) -> list[Path]:
    if target:
        path = Path(target)
        if not path.is_absolute():
            path = root / path
        return [path]
    whitelist = root / "release_whitelist.txt"
    if not whitelist.is_file():
        raise FileNotFoundError("whitelist")
    paths: list[Path] = []
    for line in whitelist.read_text(encoding="utf-8").splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        paths.append(root / item)
    return paths


def _files_under(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    if path.is_dir():
        return [item for item in sorted(path.rglob("*")) if item.is_file() and "__pycache__" not in item.parts]
    return []


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    parser = argparse.ArgumentParser(description="scan release files")
    parser.add_argument("--terms")
    parser.add_argument("--target")
    parser.add_argument("--root", default=".")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    raw = args.terms or os.environ.get("FOURNETS_IDENTITY_TERMS", "")
    if not raw or not Path(raw).exists():
        _emit("SKIP maintainer-only\n")
        return 3
    terms = _terms_from(Path(raw), root)
    if terms is None:
        _emit("terms unusable\n")
        return 2
    if args.target:
        candidate = Path(args.target)
        if not candidate.is_absolute():
            candidate = root / candidate
        if not candidate.exists():
            _emit("target missing\n")
            return 2
        files = _files_under(candidate)
    else:
        try:
            files = _iter_targets(root, None)
        except FileNotFoundError:
            _emit("BLOCKED whitelist missing\n")
            return 2
    hits: list[str] = []
    for path in files:
        if not path.is_file():
            relative = path.as_posix()
            hits.append(f"{relative}:0:missing#1")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeError:
            hits.append(f"{path.as_posix()}:1:decode#1")
            continue
        try:
            relative = path.resolve().relative_to(root).as_posix()
        except ValueError:
            relative = path.name
        hits.extend(_scan_text(relative, text, terms))
    if hits:
        _emit("\n".join(hits) + "\n")
        _emit(f"hits {len(hits)}\n")
        return 1
    _emit("PASS\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
