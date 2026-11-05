# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne
import copy
import hashlib
import json
import pytest
from three_inequality_nets.nets.composition.binding import BLOCKS, canonical_bytes
from three_inequality_nets.nets.composition.validator import evaluate, LINKS
from tests.f5r_support import ROOT, case

def sandbox(obj,tmp_path):
    import shutil
    relatives = []
    for slot in obj["stages"].values():
        for item in slot["evidence"]:
            for key in ("path", "output_path", "review_path", "receipt_path"):
                rel = item.get(key)
                if isinstance(rel, str):
                    relatives.append(rel)
    for row in obj.get("observations", {}).get("incidents") or []:
        rel = row.get("detection_log_ref")
        if isinstance(rel, str):
            relatives.append(rel)
    relatives.append("reviewers/roster.json")
    for rel in relatives:
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel, target)
    return tmp_path

def alter(block,value):
    value=copy.deepcopy(value)
    if block=="solo":
        value["code"]["run_ids"][0]="changed-run"
    elif block=="joint":
        value["episodes"][0]["spans"][0]["start"]="2026-01-15T10:00:01Z"
    elif block=="conflicts":
        value[0]["loser_handling"]="reported"
    else:
        value[0]["incident_id"]="changed-incident"
    return value

@pytest.mark.parametrize("stage",list(BLOCKS))
@pytest.mark.parametrize("mode",["observation","file","both","equivalent","missing","duplicate","invalid_json"])
def test_archived_observation_binding(stage,mode,tmp_path):
    obj=case()
    root=sandbox(obj,tmp_path)
    block,kind,reason=BLOCKS[stage]
    items=obj["stages"][stage]["evidence"]
    item=next(entry for entry in items if entry["kind"]==kind)
    path=root/item["path"]
    if mode=="observation":
        obj["observations"][block]=alter(block,obj["observations"][block])
    elif mode in ("file","both"):
        path.write_bytes(canonical_bytes(alter(block,obj["observations"][block])))
        if mode=="both":
            item["sha256"]=hashlib.sha256(path.read_bytes()).hexdigest()
    elif mode=="equivalent":
        path.write_text(json.dumps(obj["observations"][block],ensure_ascii=False,sort_keys=False,indent=1)+chr(10),encoding="utf-8")
        item["sha256"]=hashlib.sha256(path.read_bytes()).hexdigest()
        if item.get("review_path"):
            # 等价改写后复核人重新复核这份新文件；签名在下面 reseal 里补。
            review = {
                "evidence_sha256": item["sha256"],
                "reviewer": item.get("reviewed_by") or "reviewer-b",
                "conclusion": "accept",
            }
            (root / item["review_path"]).write_text(json.dumps(review, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    elif mode=="missing":
        items.remove(item)
    elif mode=="duplicate":
        items.append(copy.deepcopy(item))
    else:
        path.write_text("{",encoding="utf-8")
        item["sha256"]=hashlib.sha256(path.read_bytes()).hexdigest()
    # 按改动后的声明重签回执与复核（模拟独立方重新签字），只看归档绑定本身。
    from three_inequality_nets.core.sealing import reseal
    reseal(obj,root)
    result=evaluate(obj,root)
    if mode=="equivalent":
        assert result["verdict"]=="PASS"
        assert result["proven_level"]=="L4"
    else:
        index=list(BLOCKS).index(stage)
        assert result["verdict"]=="FAIL"
        assert result["proven_level"]=="L"+str(index)
        assert result["broken_link"]==LINKS[max(0,index-1)]
        assert reason in result["reasons"]
        if mode=="file":
            assert stage+":hash_mismatch" in result["reasons"]
