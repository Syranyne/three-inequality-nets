# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""缺失目标时不得把词写进磁盘。"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_missing_target_is_not_created(tmp_path: Path):
    secret = "probe-word-not-real"
    terms = tmp_path / "terms.txt"
    terms.write_text(secret + "\n", encoding="utf-8", newline="\n")
    project = tmp_path / "project"
    project.mkdir()
    target = project / "missing.txt"
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "dev_tools" / "identity_scan.py"),
            "--terms",
            str(terms),
            "--target",
            str(target),
            "--root",
            str(project),
        ],
        capture_output=True,
        check=False,
    )
    assert completed.returncode != 0
    assert not target.exists()
    assert secret.encode("utf-8") not in completed.stdout
    assert secret.encode("utf-8") not in completed.stderr
    assert b"target missing" in completed.stdout
