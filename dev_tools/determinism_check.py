# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""同一命令在新进程、另一工作目录和不同哈希种子下输出一致。"""

from __future__ import annotations

import hashlib
import os
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


def _run(root: Path, args: list[str], seed: str, cwd: Path) -> tuple[int, bytes]:
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = seed
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONPATH"] = str(root) + os.pathsep + env.get("PYTHONPATH", "")
    completed = subprocess.run(
        [sys.executable, "-m", "three_inequality_nets", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        check=False,
    )
    return completed.returncode, completed.stdout


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def main() -> int:
    _configure_stdio()
    root = Path(__file__).resolve().parents[1]
    other = Path(os.environ.get("TEMP", ".")) / "fournets_code" / "det_cwd"
    other.mkdir(parents=True, exist_ok=True)
    problems: list[str] = []
    lines: list[str] = []
    for name, args, expected in (("run-cases", ["run-cases"], 0), ("demo", ["demo"], 1)):
        code_a, out_a = _run(root, args, "1", root)
        code_b, out_b = _run(root, args, "7", other)
        hash_a = _digest(out_a)
        hash_b = _digest(out_b)
        lines.append(f"{name} {hash_a} {hash_b}")
        if code_a != expected or code_b != expected:
            problems.append(f"{name} exit {code_a} {code_b}")
        if hash_a != hash_b:
            problems.append(f"{name} hash")
    _emit("\n".join(lines) + "\n")
    if problems:
        _emit("FAIL " + ",".join(problems) + "\n")
        return 1
    _emit("PASS\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
