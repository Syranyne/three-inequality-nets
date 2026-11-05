# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""组合校验的合成输入。"""
import copy
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
def payload():
    return json.loads((ROOT / "templates/composition.json").read_text(encoding="utf-8"))
def change(obj, path, value):
    keys = path.split(".")
    target = obj
    for key in keys[:-1]:
        target = target[int(key)] if isinstance(target, list) else target[key]
    key = int(keys[-1]) if isinstance(target, list) else keys[-1]
    target[key] = copy.deepcopy(value)
