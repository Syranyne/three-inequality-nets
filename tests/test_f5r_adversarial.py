# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

import pytest
from three_inequality_nets.nets.catalog import LINKS
from three_inequality_nets.nets.composition.validator import evaluate
from tests.f5r_support import ROOT, attack
from tests.support import resealed

@pytest.mark.parametrize("label",["A1","A2"])
def test_reviewer_alias_attack(label,tmp_path):
    """A1 返工前会被绕过；A2 已能拦住。"""
    result = evaluate(*resealed(attack(label),tmp_path))
    assert result["verdict"] == "FAIL"
    assert result["broken_link"] == LINKS["composition"][2]
    assert result["proven_level"] == "L3"
    assert "L4:correction_reviewer" in result["reasons"]

def test_threshold_attack_g(tmp_path):
    """G 返工前会被绕过。"""
    result=evaluate(*resealed(attack("G"),tmp_path))
    assert result["verdict"]=="FAIL" and result["broken_link"] is None
    assert result["proven_level"]=="L0"
    for name in ("min_runs","min_pass_rate","max_joint_drop","min_conflicts"):
        assert "schema:observations.thresholds."+name in result["reasons"]

@pytest.mark.parametrize("label,level,link,reason",[
    ("B1","L2",1,"L3:priority_policy_digest"),
    ("B2","L2",1,"L3:priority_policy_digest"),
    ("C","L1",0,"L2:joint_observation_digest"),
])
def test_policy_and_observation_attacks(label,level,link,reason,tmp_path):
    """B1/B2 已能拦住；C 返工前会被绕过。"""
    result=evaluate(*resealed(attack(label),tmp_path))
    assert result["verdict"]=="FAIL"
    assert result["broken_link"]==LINKS["composition"][link]
    assert result["proven_level"]==level
    assert reason in result["reasons"]

def test_outside_label_attack_h(tmp_path):
    """H 返工前会被绕过；完整档案也须验证排除。"""
    import hashlib
    obj=attack("H")
    obj["unexplained"]["source_sha256"]=hashlib.sha256((ROOT/obj["unexplained"]["source_ref"]).read_bytes()).hexdigest()
    result=evaluate(*resealed(obj,tmp_path))
    assert result["verdict"]=="FAIL"
    assert result["broken_link"]==LINKS["composition"][1]
    assert result["proven_level"]=="L2"
    assert "outside_model:explained_by_net" in result["reasons"]
    assert "L3:priority_winner" in result["reasons"]

@pytest.mark.parametrize("label,level,link,reason",[
    ("D","L3",2,"L4:correction_detection"),
    ("E","L3",2,"L4:hinted_not_self"),
    ("F","L2",1,"L3:priority_injected"),
])
def test_previously_blocked_attacks_stay_blocked(label,level,link,reason,tmp_path):
    """D/E/F 返工前已能拦住。"""
    result=evaluate(*resealed(attack(label),tmp_path))
    assert result["verdict"]=="FAIL"
    assert result["broken_link"]==LINKS["composition"][link]
    assert result["proven_level"]==level
    assert reason in result["reasons"]
