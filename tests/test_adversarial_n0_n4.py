# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""对抗回归：N0–N4、G1–G4，以及由四条规则推出、此前没有单独测过的伪造。

每条探针都按「攻击者能做到的最强写法」构造：证据类型、内容结构、独立输出文件、
执行回执和复核签名都写对，只保留该探针要打的那一处伪造。
对照组 test_control_* 证明探针不是因为别的地方写错才失败。
"""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
from pathlib import Path

import pytest

from three_inequality_nets.core import reviewers
from three_inequality_nets.core.claim import binding
from three_inequality_nets.core.evidence import RECEIPT_SCHEMA, receipt_parts, review_parts
from three_inequality_nets.core.schema import file_sha256
from three_inequality_nets.nets.authority.validator import evaluate as evaluate_authority
from three_inequality_nets.nets.catalog import EVIDENCE_KINDS
from three_inequality_nets.nets.composition.validator import evaluate as evaluate_composition
from three_inequality_nets.nets.production.validator import benchmark_parts, evaluate as evaluate_production
from tests.support import ROOT

SIGNALS = {
    "sender": "a", "author": "a", "treat_sender_as_author": True, "asserted_as_fact": False,
    "injected_authorization": False, "write_attempted": False,
}
RUNNER = "runner-lab-a"


@pytest.fixture
def root(tmp_path: Path) -> Path:
    target = tmp_path / "reviewers" / "roster.json"
    target.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / "reviewers" / "roster.json", target)
    (tmp_path / "cases" / "shared").mkdir(parents=True)
    return tmp_path


def _json(root: Path, rel: str, body) -> str:
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / rel).write_text(json.dumps(body, ensure_ascii=False), encoding="utf-8")
    return rel


def _key(root: Path, name: str) -> bytes:
    row = reviewers.find(root, name)
    return str((row or {}).get("fixture_key", "attacker-guess")).encode("utf-8")


def _add_roster(root: Path, entry: dict) -> None:
    path = root / "reviewers/roster.json"
    roster = json.loads(path.read_text(encoding="utf-8"))
    roster["reviewers"].append(entry)
    path.write_text(json.dumps(roster), encoding="utf-8")


def _item(root, net, stage, tag, *, path=None, prod="worker-a", rev="reviewer-b",
          t0="2026-01-15T00:00:00Z", t1="2026-01-15T00:00:02Z"):
    kind = sorted(EVIDENCE_KINDS[net][stage])[0]
    rel = path or _json(root, f"cases/shared/{tag}-{stage}.json", {"evidence_kind": kind, "stage": stage, "note": tag})
    digest = file_sha256(root / rel)
    item = {"kind": kind, "path": rel, "sha256": digest, "produced_by": prod,
            "reviewed_by": rev if stage == "L4" else "", "timestamp": t0}
    if stage == "L4":
        out = f"cases/shared/{tag}-out.txt"
        (root / out).write_text(f"{tag} ran\n", encoding="utf-8")
        rv = _json(root, f"cases/shared/{tag}-review.json", {"evidence_sha256": digest, "reviewer": rev, "conclusion": "accept"})
        item.update(command=["py", "-3", "-c", "print(1)"], exit_code=0, output_summary="ok",
                    output_path=out, output_sha256=file_sha256(root / out), started_at=t0, finished_at=t1,
                    receipt_path=f"cases/shared/{tag}-receipt.json", receipt_sha256="",
                    review_path=rv, review_sha256=file_sha256(root / rv))
    return item


def _stages(root, net, tag, first=None, **kw):
    return {s: {"evidence": [_item(root, net, s, tag, path=first if s == "L1" else None, **kw)]}
            for s in ("L1", "L2", "L3", "L4")}


def _authority_payload(root, tag, case_id=None, **kw):
    return {"schema_version": "fournets.net_input.v1", "net": "authority", "id": case_id or tag,
            "claim": tag, "claimed_level": "L4", "outside_model": False,
            "stages": _stages(root, "authority", tag, **kw), "signals": dict(SIGNALS)}


def _sign(root, payload, *, runner=RUNNER, runner_key=None, review_key=None, review_signer=None,
          receipt_producer=None, sign_review=True, bound=None):
    """以独立执行方/复核人身份签字。参数用来模拟攻击者能伪造的那一处。"""
    bound = bound or binding(payload)
    for slot in payload["stages"].values():
        for item in slot["evidence"]:
            if item.get("receipt_path"):
                receipt = {"schema_version": RECEIPT_SCHEMA, "case_id": bound[0], "claim_sha256": bound[1],
                           "evidence_sha256": item["sha256"], "command": item["command"],
                           "exit_code": item["exit_code"], "output_sha256": item["output_sha256"],
                           "started_at": item["started_at"], "finished_at": item["finished_at"],
                           "producer": receipt_producer or item["produced_by"], "runner": runner}
                receipt["signature"] = reviewers.sign(runner_key or _key(root, runner), bound[0], bound[1],
                                                      "runner", *receipt_parts(receipt))
                _json(root, item["receipt_path"], receipt)
                item["receipt_sha256"] = file_sha256(root / item["receipt_path"])
            if item.get("review_path") and sign_review:
                rv = root / item["review_path"]
                rec = json.loads(rv.read_text(encoding="utf-8"))
                signer = review_signer or rec["reviewer"]
                rec["signature"] = reviewers.sign(
                    review_key or _key(root, signer), bound[0], bound[1], "reviewer",
                    *review_parts(rec["evidence_sha256"], rec["reviewer"], rec["conclusion"],
                                  receipt_producer or item["produced_by"]))
                rv.write_text(json.dumps(rec), encoding="utf-8")
                item["review_sha256"] = file_sha256(rv)
    return payload


def _authority(root, tag, **kw):
    sign_kw = {k: kw.pop(k) for k in list(kw) if k in ("runner", "runner_key", "review_key", "review_signer",
                                                         "receipt_producer", "sign_review")}
    return evaluate_authority(_sign(root, _authority_payload(root, tag, **kw), **sign_kw), root)


def _fixture_mode(monkeypatch, on: bool):
    if on:
        monkeypatch.setenv(reviewers.FIXTURE_ENV, "1")
    else:
        monkeypatch.delenv(reviewers.FIXTURE_ENV, raising=False)


@pytest.fixture(autouse=True)
def _fixtures_on(monkeypatch):
    _fixture_mode(monkeypatch, True)


def _fails_with(result, reason):
    assert result["verdict"] == "FAIL", result
    assert reason in result["reasons"], result["reasons"]


# ---------- 对照 ----------

def test_control_authority_chain_passes_in_fixture_mode(root):
    result = _authority(root, "ctl")
    assert result["verdict"] == "PASS" and result["proven_level"] == "L4", result["reasons"]


# ---------- N0 全自造证据链 ----------

def test_n0_self_made_chain_rejected_outside_fixture_mode(root, monkeypatch):
    _fixture_mode(monkeypatch, False)
    result = _authority(root, "n0")
    assert result["verdict"] == "FAIL"
    assert any(r.endswith("key_unavailable") for r in result["reasons"]), result["reasons"]


def test_n0_unsigned_self_review_rejected(root):
    _fails_with(_authority(root, "n0u", review_key=b"attacker-guess"), "L4:review_signature")


def test_n0_reviewer_not_in_roster(root):
    _fails_with(_authority(root, "n0r", rev="reviewer-z"), "L4:reviewer_not_in_roster")


# ---------- N1 LICENSE 改名当证据 ----------

def test_n1_license_copy_rejected(root):
    shutil.copyfile(ROOT / "LICENSE", root / "cases/shared/n1_license.txt")
    result = _authority(root, "n1", first="cases/shared/n1_license.txt")
    assert result["proven_level"] == "L0"
    _fails_with(result, "L1:evidence_content")


def test_n1_generic_record_kind_rejected(root):
    payload = _authority_payload(root, "n1k")
    payload["stages"]["L1"]["evidence"][0]["kind"] = "record"
    _fails_with(evaluate_authority(_sign(root, payload), root), "L1:evidence_kind")


# ---------- N2 未来时间 ----------

def test_n2_future_timestamps_rejected(root):
    result = _authority(root, "n2", t0="2099-01-01T00:00:00Z", t1="2099-01-01T00:00:01Z")
    assert result["verdict"] == "FAIL"
    assert any(r.endswith(":future_time") for r in result["reasons"])


# ---------- N3 同形字复核人 ----------

def test_n3_cyrillic_homoglyph_reviewer_is_executor(root):
    _fails_with(_authority(root, "n3", prod="worker-a", rev="worker-\u0430"), "L4:reviewer_is_executor")


def test_n3_homoglyph_of_roster_member_rejected(root):
    _fails_with(_authority(root, "n3b", rev="r\u0435viewer-b"), "L4:reviewer_not_in_roster")


# ---------- N4 生产网自造基线 ----------

def _production(root, tag, *, competitors=True, sample=30, attested=True, baseline_att="bench-lab-a",
                baseline_key=None, thresholds=None, ours_value=0.9, base_value=0.1, prod="worker-a", ours_by="worker-a", reuse=None):
    users = _json(root, f"cases/shared/{tag}-users.json", {"sample_size": sample})
    ours = _json(root, f"cases/shared/{tag}-ours.json", {"value": ours_value, "produced_by": ours_by})

    def source(name, value, att):
        return {"name": name, "value": value, "source_ref": f"cases/shared/{tag}-{name}.json", "source_sha256": "", "_att": att}

    bench = {"metric": "acc", "higher_is_better": True, "ours": ours_value, "ours_source_ref": ours,
             "ours_source_sha256": file_sha256(root / ours), "baseline": source("base", base_value, baseline_att),
             "competitors": [source("rival", 0.2, "bench-lab-b")] if competitors else [], "sample_size": sample}
    payload = {"schema_version": "fournets.net_input.v1", "net": "production", "id": tag, "claim": tag,
               "claimed_level": "L4", "outside_model": False, "stages": _stages(root, "production", tag, prod=prod),
               "signals": {"repeat_stable": True, "release_recorded": True, "real_user_signal": True,
                           "self_scored": False, "user_signal_ref": users, "user_signal_sha256": file_sha256(root / users),
                           "user_sample_size": sample, "benchmark": bench}}
    if thresholds is not None:
        payload["thresholds"] = thresholds
    rows = [bench["baseline"], *bench["competitors"]]
    atts = [row.pop("_att") for row in rows]
    bound = binding(payload)
    for row, att in zip(rows, atts):
        body = {"value": row["value"]}
        if attested:
            origin = f"probe {row['name']}"
            key = baseline_key if (baseline_key and row is bench["baseline"]) else _key(root, att)
            body.update(attested_by=att, origin=origin, case_id=bound[0], claim_sha256=bound[1],
                        signature=reviewers.sign(key, bound[0], bound[1], "attester",
                                                 *benchmark_parts(row["name"], "acc", row["value"], origin)))
        if reuse is not None:
            body = json.loads((root / reuse[row["name"]]).read_text(encoding="utf-8"))
        _json(root, row["source_ref"], body)
        row["source_sha256"] = file_sha256(root / row["source_ref"])
    _sign(root, payload)
    return payload, evaluate_production(payload, root)


def test_control_production_passes(root):
    _payload, result = _production(root, "pctl")
    assert result["verdict"] == "PASS" and result["proven_level"] == "L4", result["reasons"]


def test_n4_self_made_baseline_no_competitor_tiny_sample(root):
    _payload, result = _production(root, "n4", competitors=False, sample=1, attested=False)
    assert result["verdict"] == "FAIL"
    assert result["proven_level"] in ("L2", "L3")


def test_n4_unattested_baseline_rejected(root):
    _fails_with(_production(root, "n4a", attested=False)[1], "L4:benchmark_not_independent")


def test_n4_empty_competitors_rejected(root):
    _fails_with(_production(root, "n4c", competitors=False)[1], "L4:benchmark_no_competitor")


def test_n4_small_sample_rejected(root):
    _fails_with(_production(root, "n4s", sample=1)[1], "L3:user_samples")


def test_n4_baseline_attested_by_claimant_rejected(root):
    _fails_with(_production(root, "n4p", baseline_att="worker-a")[1], "L4:benchmark_not_independent")


# ---------- 补充探针 P1–P5 ----------

def test_p1_output_is_byte_copy_of_evidence(root):
    payload = _authority_payload(root, "p1")
    item = payload["stages"]["L4"]["evidence"][0]
    shutil.copyfile(root / item["path"], root / "cases/shared/p1-copy.txt")
    item["output_path"] = "cases/shared/p1-copy.txt"
    item["output_sha256"] = file_sha256(root / "cases/shared/p1-copy.txt")
    _fails_with(evaluate_authority(_sign(root, payload), root), "L4:output_is_evidence")


def test_p2_review_file_is_the_output(root):
    payload = _authority_payload(root, "p2")
    item = payload["stages"]["L4"]["evidence"][0]
    item["review_path"] = item["output_path"]
    item["review_sha256"] = item["output_sha256"]
    _fails_with(evaluate_authority(_sign(root, payload, sign_review=False), root), "L4:review_is_evidence")


def test_p3_threshold_override_cannot_loosen(root):
    _payload, result = _production(root, "p3", sample=1,
                                   thresholds={"min_samples": 0, "min_user_samples": 0, "min_margin": -1})
    assert result["verdict"] == "FAIL"
    assert result["thresholds"]["min_samples"] == 30 and result["thresholds"]["min_margin"] == 0.0


def test_p4_attacker_roster_entry_without_env_key(root, monkeypatch):
    # 声称方往名册里加一个自己的「真实」复核人：没有校验方环境变量里的密钥就不承认。
    _fixture_mode(monkeypatch, False)
    _add_roster(root, {"id": "mallory", "key_sha256": hashlib.sha256(b"k").hexdigest(), "roles": ["reviewer"]})
    result = _authority(root, "p4", rev="mallory", review_key=b"k")
    assert result["verdict"] == "FAIL"
    assert "L4:reviewer_key_unavailable" in result["reasons"] or "L4:receipt_reviewer_key_unavailable" in result["reasons"]


def test_p4_real_keys_from_env_are_accepted(root, monkeypatch):
    _fixture_mode(monkeypatch, False)
    _add_roster(root, {"id": "auditor-1", "key_sha256": hashlib.sha256(b"env-secret").hexdigest(), "roles": ["reviewer"]})
    _add_roster(root, {"id": "ci-1", "key_sha256": hashlib.sha256(b"ci-secret").hexdigest(), "roles": ["runner"]})
    monkeypatch.setenv("FOURNETS_REVIEWER_KEY_AUDITOR_1", "env-secret")
    monkeypatch.setenv("FOURNETS_REVIEWER_KEY_CI_1", "ci-secret")
    result = _authority(root, "p4ok", rev="auditor-1", review_key=b"env-secret", runner="ci-1", runner_key=b"ci-secret")
    assert result["verdict"] == "PASS", result["reasons"]


def test_p5_review_signature_cannot_be_replayed_onto_other_evidence(root):
    good = _sign(root, _authority_payload(root, "p5a"))
    other = _authority_payload(root, "p5b")
    other["stages"]["L4"]["evidence"][0]["review_path"] = good["stages"]["L4"]["evidence"][0]["review_path"]
    other["stages"]["L4"]["evidence"][0]["review_sha256"] = good["stages"]["L4"]["evidence"][0]["review_sha256"]
    _fails_with(evaluate_authority(_sign(root, other, sign_review=False), root), "L4:review_missing")


# ---------- G1 签名绑定本次声明（规则 2） ----------

def test_g1_signed_chain_reused_under_another_case_id(root):
    payload = _sign(root, _authority_payload(root, "g1"))
    assert evaluate_authority(payload, root)["verdict"] == "PASS"
    reused = copy.deepcopy(payload)
    reused["id"] = "g1-other"
    result = evaluate_authority(reused, root)
    _fails_with(result, "L4:receipt_review_signature")


def test_g1_same_case_id_different_claim_text(root):
    payload = _sign(root, _authority_payload(root, "g1t"))
    payload["claim"] = "g1t but stronger"
    _fails_with(evaluate_authority(payload, root), "L4:receipt_review_signature")


def test_g1_benchmark_source_reused_from_other_case(root):
    first, _ = _production(root, "g1a")
    names = {row["name"]: row["source_ref"] for row in
             [first["signals"]["benchmark"]["baseline"], *first["signals"]["benchmark"]["competitors"]]}
    _payload, result = _production(root, "g1b", reuse=names)
    _fails_with(result, "L4:benchmark_not_independent")


# ---------- G2 执行必须有独立回执（规则 1） ----------

def test_g2_composition_self_filled_output_without_receipt(tmp_path):
    from tests.composition_data import payload
    from tests.support import resealed
    obj, root = resealed(payload(), tmp_path)
    for key in ("receipt_path", "receipt_sha256"):
        obj["stages"]["L1"]["evidence"][0].pop(key, None)
    result = evaluate_composition(obj, root)
    assert result["proven_level"] == "L0"
    _fails_with(result, "L1:execution_unverified")


def test_g2_four_net_execution_without_receipt(root):
    payload = _authority_payload(root, "g2")
    for key in ("receipt_path", "receipt_sha256"):
        payload["stages"]["L4"]["evidence"][0].pop(key)
    _fails_with(evaluate_authority(_sign(root, payload), root), "L4:execution_unverified")


def test_g2_receipt_signed_by_claimant_key(root):
    _fails_with(_authority(root, "g2k", runner_key=b"attacker-guess"), "L4:receipt_review_signature")


# ---------- G3 产出者身份取独立来源（规则 3） ----------

def test_g3_self_reported_producer_renamed_to_dodge_reviewer_check(root):
    # 回执记的产出者是 reviewer-b；声明里自报 worker-a 想让 reviewer-b 复核自己。
    result = _authority(root, "g3", prod="worker-a", receipt_producer="reviewer-b")
    _fails_with(result, "L4:producer_mismatch")


def test_g3_reviewer_equals_receipt_producer(root):
    payload = _authority_payload(root, "g3r", prod="reviewer-b")
    _fails_with(evaluate_authority(_sign(root, payload), root), "L4:reviewer_is_executor")


# ---------- G4 完整同形字表 ----------

@pytest.mark.parametrize("reviewer", ["w\u0585rker-a", "worker-\u0251", "\u13b3orker-a", "ｗｏｒｋｅｒ－ａ", "wo\u200brker-a", "work\u1d07r-a", "worker_a"])
def test_g4_confusable_reviewer_is_executor(root, reviewer):
    from three_inequality_nets.nets.composition.identity import identity_key
    assert identity_key(reviewer) == identity_key("worker-a")
    _fails_with(_authority(root, "g4", prod="worker-a", rev=reviewer), "L4:reviewer_is_executor")


# ---------- 由四条规则推出、此前没有单独测过的伪造 ----------

def test_rule_runner_key_cannot_sign_review(root):
    # 规则 3/4：执行方的钥匙签复核，角色未登记即拒绝。
    _fails_with(_authority(root, "r1", rev=RUNNER), "L4:reviewer_role")


def test_rule_attester_cannot_sign_review(root):
    _fails_with(_authority(root, "r2", rev="bench-lab-a"), "L4:reviewer_role")


def test_rule_alias_with_same_key_is_same_principal(root):
    # 规则 3：两个名册 id 共用一把钥匙就是同一个人，名字再不同也算自审。
    row = reviewers.find(root, "reviewer-b")
    _add_roster(root, {"id": "audit-z", "fixture": True, "fixture_key": row["fixture_key"],
                       "key_sha256": row["key_sha256"], "roles": ["reviewer"]})
    payload = _authority_payload(root, "r3", prod="reviewer-b", rev="audit-z")
    _fails_with(evaluate_authority(_sign(root, payload), root), "L4:reviewer_is_executor")


def test_rule_benchmark_signed_by_claimant_key_under_other_name(root):
    row = reviewers.find(root, "reviewer-b")
    _add_roster(root, {"id": "bench-lab-z", "fixture": True, "fixture_key": row["fixture_key"],
                       "key_sha256": row["key_sha256"], "roles": ["attester"]})
    _payload, result = _production(root, "r4", ours_by="reviewer-b", baseline_att="bench-lab-z")
    _fails_with(result, "L4:benchmark_not_independent")


def test_rule_receipt_reused_as_review(root):
    payload = _sign(root, _authority_payload(root, "r5"))
    item = payload["stages"]["L4"]["evidence"][0]
    item["review_path"], item["review_sha256"] = item["receipt_path"], item["receipt_sha256"]
    _fails_with(evaluate_authority(payload, root), "L4:receipt_is_evidence")


def test_rule_receipt_times_differ_from_claim(root):
    payload = _sign(root, _authority_payload(root, "r6"))
    payload["stages"]["L4"]["evidence"][0]["finished_at"] = "2026-01-15T00:00:01Z"
    _fails_with(evaluate_authority(payload, root), "L4:receipt_mismatch")


def test_rule_unknown_evidence_field_is_forged(root):
    payload = _authority_payload(root, "r7")
    payload["stages"]["L1"]["evidence"][0]["verified_by_ci"] = True
    _fails_with(evaluate_authority(_sign(root, payload), root), "L1:unknown_field")


def test_rule_claim_without_case_id_is_unbound(root):
    payload = _sign(root, _authority_payload(root, "r8"))
    del payload["id"]
    result = evaluate_authority(payload, root)
    assert result["proven_level"] == "L0"
    _fails_with(result, "claim_unbound")


def test_rule_receipt_needs_claim_binding(root):
    # 规则 2：没有声明绑定的调用方（台账、演示）拿不到 executed，哪怕回执按空绑定签过。
    from three_inequality_nets.core.evidence import assess
    payload = _authority_payload(root, "r9")
    item = payload["stages"]["L4"]["evidence"][0]
    _sign(root, payload, bound=("", ""))
    level, reasons, forged = assess(item, root, None)
    assert forged is True and level == "artifact"
    assert "receipt_unbound" in reasons


def test_rule_blank_claimant_is_never_independent(root):
    # 规则 4：认不出身份的声明方一律当成同一方。
    from three_inequality_nets.core.attest import attest
    bound = ("r10", "0" * 64)
    signature = reviewers.sign(_key(root, "reviewer-b"), *bound, "reviewer", "x")
    assert attest(root, bound, "reviewer", "reviewer-b", signature, ("x",), claimants=[]) is None
    assert attest(root, bound, "reviewer", "reviewer-b", signature, ("x",), claimants=["  "]) == "not_independent"


def test_rule_review_without_execution_is_forged(root):
    payload = _authority_payload(root, "r11")
    payload["stages"]["L1"]["evidence"][0]["reviewed_by"] = "reviewer-b"
    _fails_with(evaluate_authority(_sign(root, payload), root), "L1:review_without_execution")
