# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

import pytest
from three_inequality_nets.nets.composition.schema import DEFAULT_THRESHOLDS
from three_inequality_nets.nets.composition.validator import evaluate
from tests.f5r_support import case
from tests.support import resealed

@pytest.mark.parametrize("name,value",[("min_runs",4),("min_pass_rate",0.79),("max_joint_drop",0.11),("min_conflicts",1)])
def test_looser_threshold_rejected(name,value,tmp_path):
    obj=case()
    obj["observations"]["thresholds"][name]=value
    result=evaluate(*resealed(obj,tmp_path))
    assert result["verdict"]=="FAIL" and result["proven_level"]=="L0"
    assert "schema:observations.thresholds."+name in result["reasons"]
    assert result["thresholds"]==DEFAULT_THRESHOLDS

@pytest.mark.parametrize("name",list(DEFAULT_THRESHOLDS))
@pytest.mark.parametrize("value",[True,float("nan"),float("inf"),"5"])
def test_invalid_threshold_types(name,value,tmp_path):
    obj=case()
    obj["observations"]["thresholds"][name]=value
    result=evaluate(*resealed(obj,tmp_path))
    assert result["proven_level"]=="L0"
    assert "schema:observations.thresholds."+name in result["reasons"]

def test_default_echo_and_omitted_values(tmp_path):
    obj=case()
    explicit=evaluate(*resealed(obj,tmp_path/"explicit"))
    del obj["observations"]["thresholds"]
    assert evaluate(*resealed(obj,tmp_path/"omitted"))==explicit
    assert explicit["thresholds"]==DEFAULT_THRESHOLDS

@pytest.mark.parametrize("name,value",[("min_runs",6),("min_pass_rate",0.9),("max_joint_drop",0.05),("min_conflicts",3)])
def test_stricter_threshold_echo(name,value,tmp_path):
    obj=case()
    obj["observations"]["thresholds"][name]=value
    result=evaluate(*resealed(obj,tmp_path))
    assert result["thresholds"][name]==value
    assert not any(code.startswith("schema:") for code in result["reasons"])
    assert result["verdict"]==("FAIL" if name=="min_conflicts" else "PASS")
    if name=="min_conflicts":
        assert "L3:priority_trials" in result["reasons"]
