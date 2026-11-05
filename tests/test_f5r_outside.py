# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne
import copy
import hashlib
import json
import pytest
from three_inequality_nets.cli import NET_EVALUATORS
from three_inequality_nets.nets.catalog import NETS, LINKS
from tests.f5r_support import ROOT, attack

def full(net):
    if net=="composition":
        path=ROOT/"cases/composition/cp-pass-full.input.json"
        return json.loads(path.read_text(encoding="utf-8"))
    for path in sorted((ROOT/"cases"/net).glob("*.input.json")):
        obj=json.loads(path.read_text(encoding="utf-8"))
        obj["outside_model"]=False
        result=NET_EVALUATORS[net](obj,ROOT)
        if result["verdict"]=="PASS" and result["proven_level"]=="L4":
            return obj
    raise AssertionError("full fixture missing")

def _resign(obj,tmp_path):
    """改了声明正文，旧签名按规则 2 失效；在沙箱里由独立执行方/复核人重签。"""
    import shutil
    from tests.support import resealed
    obj,root=resealed(obj,tmp_path)
    target=root/"cases"/"shared"/"record.txt"
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(ROOT/"cases"/"shared"/"record.txt",target)
    return obj,root

def archived(obj,net,excluded=None):
    obj=copy.deepcopy(obj)
    obj["outside_model"]=True
    ref="cases/shared/record.txt"
    obj["unexplained"]={"phenomenon":"A synthetic observation persists after verified local checks.",
                       "excluded_links":list(LINKS[net]) if excluded is None else excluded,
                       "source_ref":ref,"source_sha256":hashlib.sha256((ROOT/ref).read_bytes()).hexdigest()}
    return obj

@pytest.mark.parametrize("net",NETS)
@pytest.mark.parametrize("mode",["none","phenomenon","excluded_links","source_ref","source_sha256","wrong_link","all","duplicate","missing_file","absolute","parent","digest"])
def test_invalid_archive(net,mode):
    obj=archived(full(net),net)
    expected="outside_model:record_missing"
    if mode=="none":
        del obj["unexplained"]
    elif mode in ("phenomenon","excluded_links","source_ref","source_sha256"):
        del obj["unexplained"][mode]
        expected+=":"+mode
    elif mode in ("wrong_link","all","duplicate"):
        obj["unexplained"]["excluded_links"]={"wrong_link":["unknown"],"all":["all"],"duplicate":[LINKS[net][0]]*2}[mode]
        expected+=":excluded_links"
    elif mode in ("missing_file","absolute","parent"):
        obj["unexplained"]["source_ref"]={"missing_file":"cases/missing.txt","absolute":"/outside.txt","parent":"../outside.txt"}[mode]
        expected+=":source_ref"
    else:
        obj["unexplained"]["source_sha256"]="0"*64
        expected="outside_model:source_digest"
    result=NET_EVALUATORS[net](obj,ROOT)
    assert result["verdict"]=="FAIL"
    assert result["broken_link"] is None and result["proven_level"]=="L0"
    assert expected in result["reasons"]

@pytest.mark.parametrize("net",NETS)
def test_true_archived_exception(net):
    result=NET_EVALUATORS[net](archived(full(net),net),ROOT)
    assert result["verdict"]=="UNEXPLAINED"
    assert result["broken_link"] is None and result["proven_level"]=="L4"

@pytest.mark.parametrize("net",NETS)
def test_claimed_exclusion_is_checked(net,tmp_path):
    obj=full(net)
    obj["stages"]["L2"]["evidence"]=[]
    obj,root=_resign(obj,tmp_path)
    normal=NET_EVALUATORS[net](obj,root)
    result=NET_EVALUATORS[net](archived(obj,net),root)
    assert result["verdict"]=="FAIL"
    assert result["broken_link"]==normal["broken_link"]
    assert result["proven_level"]==normal["proven_level"]=="L1"
    assert result["reasons"] == normal["reasons"] + ["outside_model:explained_by_net"]

@pytest.mark.parametrize("net",NETS)
def test_only_proven_first_link_can_be_excluded(net,tmp_path):
    obj=full(net)
    obj["stages"]["L3"]["evidence"]=[]
    obj["stages"]["L4"]["evidence"]=[]
    obj,root=_resign(obj,tmp_path)
    result=NET_EVALUATORS[net](archived(obj,net,[LINKS[net][0]]),root)
    assert result["verdict"]=="UNEXPLAINED"
    assert result["broken_link"] is None and result["proven_level"]=="L2"
    assert result["reasons"]==["outside_model"]

@pytest.mark.parametrize("net",NETS)
def test_false_marker_ignores_archive(net):
    obj=full(net)
    expected=NET_EVALUATORS[net](obj,ROOT)
    obj["unexplained"]="unused"
    assert NET_EVALUATORS[net](obj,ROOT)==expected

def test_h_without_digest_is_a_missing_record():
    """H 的旧三字段写法返工前会被绕过。"""
    result=NET_EVALUATORS["composition"](attack("H"),ROOT)
    assert result["verdict"]=="FAIL"
    assert result["proven_level"]=="L0" and result["broken_link"] is None
    assert "outside_model:record_missing:source_sha256" in result["reasons"]

def test_h_with_complete_archive_is_explained():
    """H 补齐留档后，返工前会被绕过的排除也会核实。"""
    obj=archived(attack("H"),"composition",[LINKS["composition"][1]])
    result=NET_EVALUATORS["composition"](obj,ROOT)
    assert result["verdict"]=="FAIL"
    assert result["proven_level"]=="L2"
    assert result["broken_link"]==LINKS["composition"][1]
    assert "outside_model:explained_by_net" in result["reasons"]
    assert "L3:priority_winner" in result["reasons"]

def test_archive_digest_is_checked_before_observation_io(monkeypatch):
    from three_inequality_nets.nets.composition import validator
    obj=archived(full("composition"),"composition")
    obj["unexplained"]["source_sha256"]="0"*64
    def forbidden_read(*args):
        raise AssertionError("ordinary evaluation started before archive validation")
    monkeypatch.setattr(validator,"binding_checks",forbidden_read)
    result=validator.evaluate(obj,ROOT)
    assert result["verdict"]=="FAIL" and result["proven_level"]=="L0"
    assert result["reasons"]==["outside_model:source_digest"]
