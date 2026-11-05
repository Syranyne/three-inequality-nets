# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""Compare declared observations with their archived JSON."""
import hashlib
import json
from pathlib import Path
from three_inequality_nets.core.schema import resolve_inside

BLOCKS = {
    "L1": ("solo","solo-observations","L1:solo_observation_digest"),
    "L2": ("joint","joint-observations","L2:joint_observation_digest"),
    "L3": ("conflicts","conflict-observations","L3:conflict_observation_digest"),
    "L4": ("incidents","incident-observations","L4:incident_observation_digest"),
}

def canonical_bytes(value) -> bytes:
    return (json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2,allow_nan=False)+"\n").encode("utf-8")

def binding_checks(payload: dict, root: Path) -> dict:
    findings={}
    claimed=int(payload["claimed_level"][1:])
    for stage,(block,kind,reason) in BLOCKS.items():
        items=payload["stages"][stage]["evidence"]
        if not items and int(stage[1:])>claimed:
            findings[stage]=(True,[])
            continue
        bound=[item for item in items if item["kind"]==kind]
        ok=False
        if len(bound)==1:
            item=bound[0]
            try:
                blob=resolve_inside(root,item["path"]).read_bytes()
                archived=json.loads(blob)
                ok=(hashlib.sha256(blob).hexdigest()==item["sha256"].casefold()
                    and canonical_bytes(archived)==canonical_bytes(payload["observations"][block]))
            except (OSError,UnicodeError,ValueError,OverflowError):
                ok=False
        findings[stage]=(ok,[] if ok else [reason])
    return findings
