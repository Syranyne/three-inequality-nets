# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""核对两份许可证原文、通知行和源文件头。"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

DOCS_LICENSE_SHA = "41003d4a74749c0220e33dd415042164b5a1093ed401f36277234f772d22d3d0"
OFFICIAL_BODY_SHA = "c0ea4a896d2c8c394b29f9427589996db826cd501c512279ff0ed3ef48fabbe5"
NOTICE_LINE = "Required Notice: Copyright 2026 Syranyne"
TITLE = "PolyForm Noncommercial License 1.0.0"
HEADER = (
    "# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0\n"
    "# Copyright 2026 Syranyne\n"
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


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _official_body(text: str) -> bytes:
    head = text[: text.rfind(NOTICE_LINE)] if NOTICE_LINE in text else text
    return (head.rstrip("\n") + "\n").encode("utf-8")


def _py_files(root: Path) -> list[Path]:
    found: list[Path] = []
    whitelist = root / "release_whitelist.txt"
    if whitelist.is_file():
        for line in whitelist.read_text(encoding="utf-8").splitlines():
            item = line.strip()
            if item.endswith(".py"):
                found.append(root / item)
        return found
    for path in root.rglob("*.py"):
        if any(part in {"_备份", "__pycache__", ".pytest_cache"} for part in path.parts):
            continue
        found.append(path)
    return found


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    parser = argparse.ArgumentParser(description="check licenses and file headers")
    parser.add_argument("--root", default=".")
    parser.add_argument("--target")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    if args.target:
        path = Path(args.target)
        if not path.is_absolute():
            path = root / path
        text = path.read_text(encoding="utf-8") if path.is_file() else ""
        if path.suffix == ".py" and not text.startswith(HEADER):
            _emit("FAIL header\n")
            return 1
        if path.name == "LICENSE" and (TITLE not in text or NOTICE_LINE not in text.splitlines()):
            _emit("FAIL license text\n")
            return 1
        _emit("PASS\n")
        return 0
    problems: list[str] = []
    license_path = root / "LICENSE"
    docs_license = root / "docs" / "LICENSE"
    if not license_path.is_file():
        problems.append("root license missing")
    else:
        text = license_path.read_text(encoding="utf-8")
        if TITLE not in text:
            problems.append("title")
        if NOTICE_LINE not in text.splitlines():
            problems.append("notice")
        if hashlib.sha256(_official_body(text)).hexdigest() != OFFICIAL_BODY_SHA:
            problems.append("polyform hash")
    if not docs_license.is_file() or _sha(docs_license) != DOCS_LICENSE_SHA:
        problems.append("docs license hash")
    for path in _py_files(root):
        if not path.is_file() or not path.read_text(encoding="utf-8").startswith(HEADER):
            problems.append(f"header {path.name}")
    if problems:
        _emit("FAIL " + ",".join(problems) + "\n")
        return 1
    _emit("PASS\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
