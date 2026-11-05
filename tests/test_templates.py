# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

import pytest

from three_inequality_nets.cli import check_path
from tests.support import ROOT

TEMPLATES = {
    "contract": "task_contract.json",
    "ledger": "run_ledger.json",
    "receipt": "receipt.json",
    "convergence": "convergence.json",
    "authority": "authority.json",
    "learning_claim": "learning_claim.json",
    "retrieval": "retrieval.json",
    "production": "production.json",
    "composition": "composition.json",
}


@pytest.mark.parametrize("kind", list(TEMPLATES))
def test_template_passes(kind):
    path = ROOT / "templates" / TEMPLATES[kind]
    result = check_path(kind, path, ROOT)
    assert result["verdict"] == "PASS"

@pytest.mark.parametrize("kind",["authority","learning_claim","retrieval","production","composition"])
def test_net_template_can_project_verified_archive(kind,tmp_path):
    import hashlib
    import json
    from three_inequality_nets.nets.catalog import LINKS
    obj=json.loads((ROOT/"templates"/TEMPLATES[kind]).read_text(encoding="utf-8"))
    obj["outside_model"]=True
    ref="cases/shared/record.txt"
    obj["unexplained"]={"phenomenon":"Synthetic archived observation.","excluded_links":[LINKS[kind][0]],"source_ref":ref,"source_sha256":hashlib.sha256((ROOT/ref).read_bytes()).hexdigest()}
    path=tmp_path/"template_archive.json"
    path.write_text(json.dumps(obj,ensure_ascii=False,sort_keys=True,indent=2)+chr(10),encoding="utf-8")
    result=check_path(kind,path,ROOT)
    assert result["verdict"]=="UNEXPLAINED"
    assert result["proven_level"] in ("L2","L3","L4")
