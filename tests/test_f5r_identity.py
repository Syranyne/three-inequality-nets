# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

import pytest
from three_inequality_nets.nets.composition.identity import identity_key
from three_inequality_nets.nets.composition.validator import evaluate
from tests.f5r_support import ROOT, case, identities
from tests.test_f5r_binding import sandbox
from tests.support import resealed
from three_inequality_nets.core.sealing import reseal

PAIRS = [
    ("runner-a","RUNNER-A"),("runner-a","Runner-A"),
    ("runner-a"," runner-a"),("runner-a","runner-a "),
    ("runner a","runner\ta"),("runner a","runner  a"),
    ("runner-a","ｒｕｎｎｅｒ－ａ"),("runner-a","\u3000runner-a\u3000"),
    *[("runner-a","run"+c+"ner-a") for c in ("\u200b","\u200c","\u200d","\ufeff","\u2060","\u00ad")],
    ("runner-a","𝐫unner-a"),
]
@pytest.mark.parametrize("producer,reviewer",PAIRS)
def test_identity_variants_rejected(producer,reviewer,tmp_path):
    assert identity_key(producer) == identity_key(reviewer)
    result = evaluate(*resealed(identities(case(),producer,reviewer),tmp_path))
    assert result["verdict"] == "FAIL"
    assert result["proven_level"] == "L3"
    assert "L4:correction_reviewer" in result["reasons"]

@pytest.mark.parametrize("field",["produced_by","reviewed_by","verified_by"])
def test_empty_normalised_identifier(field,tmp_path):
    obj=case()
    if field=="verified_by":
        obj["observations"]["incidents"][0]["recheck"][field]="\u200b\ufeff"
    else:
        obj["stages"]["L4"]["evidence"][0][field]="\u200b\ufeff"
    result=evaluate(*resealed(obj,tmp_path))
    assert result["proven_level"]=="L0"
    assert any(code.startswith("schema:") and code.endswith(field) for code in result["reasons"])

@pytest.mark.parametrize("detector",["SELF","ｓｅｌｆ","self\u200b"])
def test_detection_normalizes_to_subject(detector,tmp_path):
    # subject_id 默认 self；归一后相同的 detected_by 应被接受。
    obj=case()
    root=sandbox(obj,tmp_path)
    obj["observations"]["incidents"][0]["detected_by"]=detector
    # 同步 incident 归档，避免 binding 失败掩盖语义。
    from three_inequality_nets.nets.composition.binding import canonical_bytes
    import hashlib
    for item in obj["stages"]["L4"]["evidence"]:
        if item.get("kind") == "incident-observations":
            blob = canonical_bytes(obj["observations"]["incidents"])
            (root / item["path"]).write_bytes(blob)
            item["sha256"] = hashlib.sha256(blob).hexdigest()
    reseal(obj,root)
    result=evaluate(obj,root)
    assert "L4:correction_detection" not in result["reasons"]


@pytest.mark.parametrize("detector",["external-monitor","other-agent"])
def test_detection_rejects_non_subject(detector,tmp_path):
    obj=case()
    root=sandbox(obj,tmp_path)
    obj["observations"]["incidents"][0]["detected_by"]=detector
    from three_inequality_nets.nets.composition.binding import canonical_bytes
    import hashlib
    for item in obj["stages"]["L4"]["evidence"]:
        if item.get("kind") == "incident-observations":
            blob = canonical_bytes(obj["observations"]["incidents"])
            (root / item["path"]).write_bytes(blob)
            item["sha256"] = hashlib.sha256(blob).hexdigest()
    reseal(obj,root)
    result=evaluate(obj,root)
    assert result["verdict"]=="FAIL"
    assert "L4:correction_detection" in result["reasons"]

@pytest.mark.parametrize("left,right",[("runner-a","runner-b"),("reviewer-a","reviewer-a2")])
def test_distinct_identifiers(left,right):
    assert identity_key(left)!=identity_key(right)

def test_legitimate_full_case():
    # 仓库里的原始用例，不重签。
    result=evaluate(case(),ROOT)
    assert result["verdict"]=="PASS" and result["proven_level"]=="L4"
