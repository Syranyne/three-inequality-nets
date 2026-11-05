# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
def case(case_id="cp-pass-full"):
    return json.loads((ROOT / "cases/composition" / (case_id+".input.json")).read_text(encoding="utf-8"))
def identities(obj, producer, reviewer):
    for item in obj["stages"]["L4"]["evidence"]:
        item["produced_by"] = producer
        item["reviewed_by"] = reviewer
    for row in obj["observations"]["incidents"]:
        row["recheck"]["verified_by"] = reviewer
    return obj
def attack(label):
    obj = case("cp-forged-stitch" if label == "C" else "cp-break-priority" if label == "H" else "cp-pass-full")
    obs = obj["observations"]
    if label in ("A1","A2"):
        actor = obj["stages"]["L4"]["evidence"][0]["produced_by"]
        identities(obj,actor,actor.upper() if label == "A1" else actor+" ")
    elif label in ("B1","B2"):
        obs["policy"]["policy_id"] += "-changed"
        if label == "B2":
            import hashlib
            body = {k:obs["policy"][k] for k in ("policy_id","declared_at","order","rules")}
            blob = (json.dumps(body,ensure_ascii=False,sort_keys=True,indent=2)+"\n").encode("utf-8")
            obs["policy"]["sha256"] = hashlib.sha256(blob).hexdigest()
    elif label == "C":
        for index, ep in enumerate(obs["joint"]["episodes"]):
            for span in ep["spans"]:
                span["start"] = f"2026-01-15T{10+index:02}:02:00Z"
                span["end"] = f"2026-01-15T{10+index:02}:48:00Z"
    elif label == "D":
        # 与 subject_id 归一后仍不同的发现者
        obs["incidents"][0]["detected_by"] = "external-monitor"
    elif label == "E":
        row = obs["incidents"][0]
        row["hints"] = [{"at":row["consequence_at"],"source":"user"}]
    elif label == "F":
        for row in obs["conflicts"]:
            row["injected"] = False
    elif label == "G":
        obs["thresholds"] = {"min_runs":1,"min_pass_rate":0.01,"max_joint_drop":0.99,"min_conflicts":1}
    elif label == "H":
        obj["outside_model"] = True
        obj["unexplained"] = {"phenomenon":"A failed priority trial was labelled outside the model.","excluded_links":["能同时做→冲突时会正确调权"],"source_ref":"cases/shared/record.txt"}
    return obj
