# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""一条命令跑完发布前检查。"""

from __future__ import annotations

import argparse
import subprocess
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


def _run(root: Path, args: list[str]) -> tuple[int, str]:
    completed = subprocess.run(
        [sys.executable, *args],
        cwd=root,
        capture_output=True,
        check=False,
        env=None,
    )
    text = completed.stdout.decode("utf-8", errors="replace")
    err = completed.stderr.decode("utf-8", errors="replace")
    detail = (text + err).strip().replace("\n", " | ")
    return completed.returncode, detail


def _status(code: int, allow_blocked: bool) -> tuple[str, str]:
    if code == 0:
        return "PASS", ""
    return "FAIL", f"exit {code}"


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    parser = argparse.ArgumentParser(description="run the release checks")
    parser.add_argument("--allow-blocked", action="store_true")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent
    checks: list[tuple[str, list[str], set[int]]] = [
        ("identity", ["dev_tools/identity_scan.py"], {0}),
        ("similarity", ["dev_tools/similarity_check.py"], {0}),
        ("pattern", ["dev_tools/pattern_lint.py"], {0}),
        ("license", ["dev_tools/license_check.py"], {0}),
        ("structure", ["dev_tools/structure_check.py"], {0}),
        ("pytest", ["-m", "pytest", "-q"], {0}),
        ("cases", ["-m", "three_inequality_nets", "run-cases"], {0}),
        ("demo", ["-m", "three_inequality_nets", "demo"], {1}),
        ("determinism", ["dev_tools/determinism_check.py"], {0}),
    ]
    counts = {"PASS": 0, "FAIL": 0, "SKIP": 0, "BLOCKED": 0}
    for name, command, ok_codes in checks:
        script = command[0]
        if script.endswith(".py") and not (root / script).is_file():
            label, reason = "SKIP", "未启用"
            counts["SKIP"] += 1
            _emit(f"SKIP(未启用) {name} {reason}\n")
            continue
        code, detail = _run(root, command)
        if name in {"identity", "similarity"} and code == 3 and detail.startswith("SKIP"):
            counts["SKIP"] += 1
            _emit(f"SKIP {name} maintainer-only\n")
            continue
        if code in ok_codes and not detail.startswith("BLOCKED"):
            counts["PASS"] += 1
            _emit(f"PASS {name}\n")
            continue
        if "BLOCKED" in detail.split(" | ")[0]:
            counts["BLOCKED"] += 1
            reason = detail[:180]
            _emit(f"BLOCKED {name} {reason}\n")
            continue
        counts["FAIL"] += 1
        _emit(f"FAIL {name} {detail[:300]}\n")
    _emit(
        f"PASS_COUNT {counts['PASS']}\n"
        f"FAIL_COUNT {counts['FAIL']}\n"
        f"SKIP_COUNT {counts['SKIP']}\n"
        f"BLOCKED_COUNT {counts['BLOCKED']}\n"
    )
    if counts["FAIL"] == 0 and counts["BLOCKED"] == 0:
        if counts["SKIP"] == 0:
            _emit("ALL GREEN\n")
        return 0
    if counts["FAIL"] == 0 and args.allow_blocked:
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
