# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""Archived exceptions with independently checked exclusions."""
import hashlib
from pathlib import Path
from three_inequality_nets.core.report import make_result
from three_inequality_nets.core.schema import is_sha256, resolve_inside, stable_relative

def record_fields(payload: dict, links: tuple) -> list[str]:
    record=payload.get("unexplained")
    if not isinstance(record,dict):
        return ["unexplained"]
    fields=[]
    phenomenon=record.get("phenomenon")
    if not isinstance(phenomenon,str) or not phenomenon.strip():
        fields.append("phenomenon")
    excluded=record.get("excluded_links")
    if not (isinstance(excluded,list) and excluded
            and all(isinstance(item,str) and item in links for item in excluded)
            and len(set(excluded))==len(excluded)):
        fields.append("excluded_links")
    if not stable_relative(record.get("source_ref")):
        fields.append("source_ref")
    if not is_sha256(record.get("source_sha256")):
        fields.append("source_sha256")
    return fields

def record_reasons(fields: list[str]) -> list[str]:
    if not fields:
        return []
    return ["outside_model:record_missing"]+["outside_model:record_missing:"+field for field in fields]

def evaluate_outside(payload: dict, root: Path, net: str, links: tuple, ordinary):
    claimed=payload.get("claimed_level")
    fields=record_fields(payload,links)
    if fields:
        return make_result(net,"FAIL",None,claimed,"L0",record_reasons(fields))
    record=payload["unexplained"]
    try:
        blob=resolve_inside(root,record["source_ref"]).read_bytes()
    except (OSError,ValueError):
        return make_result(net,"FAIL",None,claimed,"L0",record_reasons(["source_ref"]))
    if hashlib.sha256(blob).hexdigest()!=record["source_sha256"].casefold():
        return make_result(net,"FAIL",None,claimed,"L0",["outside_model:source_digest"])
    normal=dict(payload)
    normal["outside_model"]=False
    assessed=ordinary(normal)
    proven=assessed.get("proven_level")
    rank=int(proven[1:]) if proven in ("L0","L1","L2","L3","L4") else 0
    if any(rank<links.index(link)+2 for link in record["excluded_links"]):
        return make_result(net,"FAIL",assessed["broken_link"],claimed,proven,
                           [*assessed["reasons"],"outside_model:explained_by_net"])
    notes=assessed["reasons"] if assessed["verdict"]=="PASS" else []
    return make_result(net,"UNEXPLAINED",None,claimed,proven,["outside_model",*notes])
