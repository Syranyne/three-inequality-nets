# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

import copy
import hashlib
import json
import pytest
from three_inequality_nets.nets.catalog import LINKS
from three_inequality_nets.nets.production.validator import evaluate
from tests.support import ROOT, load_json

def payload():
    return load_json(ROOT/"cases/production/pd-unexplained.input.json")

def test_full_proof_remains_an_archived_exception():
    obj=payload()
    normal=evaluate(dict(obj,outside_model=False),ROOT)
    assert normal["verdict"]=="PASS" and normal["proven_level"]=="L4"
    result=evaluate(obj,ROOT)
    assert result["verdict"]=="UNEXPLAINED" and result["proven_level"]=="L4"
    assert result["broken_link"] is None
    assert result["reasons"]==["outside_model"]

@pytest.mark.parametrize("stage",["L1","L2","L3","L4"])
def test_archive_cannot_replace_any_missing_stage(stage):
    obj=payload()
    obj["stages"][stage]["evidence"]=[]
    result=evaluate(obj,ROOT)
    assert result["verdict"]=="FAIL"
    assert result["proven_level"]=="L"+str(int(stage[1])-1)
    assert result["broken_link"]==LINKS["production"][max(0,int(stage[1])-2)]
    assert "outside_model:explained_by_net" in result["reasons"]

def test_counterexample_archive_is_hash_locked():
    obj=payload()
    obj["unexplained"]["source_sha256"]="0"*64
    result=evaluate(obj,ROOT)
    assert result["verdict"]=="FAIL" and result["proven_level"]=="L0"
    assert "outside_model:source_digest" in result["reasons"]

def test_synthetic_sources_and_coupled_trace_are_consistent():
    obj=payload()
    record=obj["unexplained"]
    blob=(ROOT/record["source_ref"]).read_bytes()
    assert hashlib.sha256(blob).hexdigest()==record["source_sha256"]
    archive=json.loads(blob)
    blocks={}
    for stage,slot in obj["stages"].items():
        item=slot["evidence"][0]
        raw=(ROOT/item["path"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest()==item["sha256"]
        assert archive["stage_refs"][stage]=={"path":item["path"],"sha256":item["sha256"]}
        blocks[stage]=json.loads(raw)
        assert blocks[stage]["fixture_type"]=="synthetic-test-record"
    assert all(p["artifact_exists"] and p["smoke_passed"] for p in blocks["L1"]["products"])
    assert all(p["runs"]==p["passes"]==len(set(p["run_ids"]))==10 and p["released_version"] for p in blocks["L2"]["products"])
    assert not blocks["L3"]["self_scored"]
    assert all(p["paid_accounts"]>0 and p["repeat_sessions"]>1 and p["retained_accounts"]>0 for p in blocks["L3"]["evaluations"])
    reference=blocks["L4"]["reference"]
    assert all(p["cost_units"]<reference["cost_units"] and p["latency_ms"]<reference["latency_ms"] for p in blocks["L4"]["products"])
    trace=archive["trace"]
    assert all(row["combined_orders"]==row["service_a_orders"]+row["service_b_orders"] for row in trace)
    for prior,current in zip(trace,trace[1:]):
        assert current["service_a_orders"]==100+prior["service_b_orders"]
        assert current["service_b_orders"]==100+prior["service_a_orders"]
    assert trace[-1]["combined_orders"]>trace[-1]["external_demand_total"]==trace[0]["combined_orders"]
