# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""发布文本和源材料的最长公共子串。来源只从参数读。"""

from __future__ import annotations

import argparse
import ast
import os
import sys
import tokenize
from io import BytesIO
from pathlib import Path


DEFINITIONS = (
    "发送者 ≠ 语义作者 ≠ 事实主张 ≠ 写入授权",
    "窗口收到 ≠ 进入训练集 ≠ 得到正确标注 ≠ 推理时真正学会",
    "检索命中 ≠ 语义理解 ≠ 权威裁决 ≠ 施工结论",
    "生成能力 ≠ 生产能力 ≠ 产品价值 ≠ 足以动摇行业的竞争力",
)


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


def _strip(text: str) -> str:
    for line in DEFINITIONS:
        text = text.replace(line, " ")
    return text


def _grams(text: str, size: int) -> set[int]:
    if size <= 0 or len(text) < size:
        return set()
    base = 911382323
    modulus = 1 << 64
    power = pow(base, size, modulus)
    value = 0
    found: set[int] = set()
    for index, char in enumerate(text):
        value = (value * base + ord(char)) % modulus
        if index >= size:
            value = (value - ord(text[index - size]) * power) % modulus
        if index >= size - 1:
            found.add(value)
    return found


def _shares(left: str, right: str, size: int) -> bool:
    if size == 0:
        return True
    return not _grams(left, size).isdisjoint(_grams(right, size))


def _longest(left: str, right: str, limit: int = 120) -> int:
    if not left or not right:
        return 0
    high = min(len(left), len(right), limit)
    best = 0
    upper = high
    while best < upper:
        mid = (best + upper + 1) // 2
        if _shares(left, right, mid):
            best = mid
        else:
            upper = mid - 1
    return best


def _py_surface(text: str) -> str:
    pieces: list[str] = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        tree = None
    if tree is not None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                pieces.append(node.value)
    try:
        for token in tokenize.tokenize(BytesIO(text.encode("utf-8")).readline):
            if token.type == tokenize.COMMENT:
                pieces.append(token.string)
    except tokenize.TokenError:
        pass
    return "\n".join(pieces)


def _source_text(paths: list[str]) -> str:
    chunks: list[str] = []
    for raw in paths:
        path = Path(raw)
        files = [path] if path.is_file() else [item for item in path.rglob("*") if item.is_file()]
        for file in files:
            if file.suffix.lower() not in {".py", ".md", ".json", ".txt"}:
                continue
            if "__pycache__" in file.parts:
                continue
            chunks.append(file.read_text(encoding="utf-8"))
    return _strip("\n".join(chunks))


def _targets(root: Path, single: str | None) -> list[tuple[Path, str]]:
    if single:
        path = Path(single)
        if not path.is_absolute():
            path = root / path
        return [(path, "doc" if path.suffix.lower() == ".md" else "py")]
    found: list[tuple[Path, str]] = []
    docs = root / "docs"
    if docs.is_dir():
        for path in sorted(docs.rglob("*")):
            if path.is_file() and path.suffix.lower() == ".md":
                found.append((path, "doc"))
    readme = root / "README.md"
    if readme.is_file():
        found.append((readme, "doc"))
    whitelist = root / "release_whitelist.txt"
    if whitelist.is_file():
        for line in whitelist.read_text(encoding="utf-8").splitlines():
            item = line.strip()
            if item.endswith(".py"):
                found.append((root / item, "py"))
    return found


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    parser = argparse.ArgumentParser(description="compare public text with source material")
    parser.add_argument("--source", action="append", default=[])
    parser.add_argument("--target")
    parser.add_argument("--root", default=".")
    args = parser.parse_args(argv)
    sources = list(args.source)
    if not sources:
        raw = os.environ.get("FOURNETS_SIMILARITY_SOURCES", "")
        sources = [item for item in raw.split(";") if item]
    if not sources or not any(Path(item).exists() for item in sources):
        _emit("SKIP maintainer-only\n")
        return 3
    sources = [item for item in sources if Path(item).exists()]
    corpus = _source_text(sources)
    root = Path(args.root).resolve()
    failed = False
    lines: list[str] = []
    for path, kind in _targets(root, args.target):
        if not path.is_file():
            lines.append(f"MISSING {path.name}")
            failed = True
            continue
        if path.name == "LICENSE":
            lines.append(f"SKIP_LICENSE {path.as_posix()}")
            continue
        text = _strip(path.read_text(encoding="utf-8"))
        if kind == "py":
            text = _py_surface(text)
            limit = 40
        else:
            limit = 20
        length = _longest(text, corpus)
        try:
            relative = path.resolve().relative_to(root).as_posix()
        except ValueError:
            relative = path.name
        lines.append(f"SIM {relative} length {length}")
        if length >= limit:
            failed = True
    _emit("\n".join(lines) + ("\n" if lines else ""))
    if failed:
        _emit("FAIL\n")
        return 1
    _emit("PASS\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
