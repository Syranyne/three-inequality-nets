# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

import copy
import pytest
from three_inequality_nets.nets.composition.schema import DEFAULT_THRESHOLDS, parse_time, validate_observations, validate_payload
from tests.composition_data import change, payload

def test_valid_full_schema_and_default_thresholds():
    obj = payload()
    assert validate_payload(obj) == []
    del obj["observations"]["thresholds"]
    assert validate_payload(obj) == []
    assert DEFAULT_THRESHOLDS == {"min_runs": 5, "min_pass_rate": 0.8, "max_joint_drop": 0.1, "min_conflicts": 2}

@pytest.mark.parametrize("path,value", [
    ("observations.capabilities", ["code", "code"]),
    ("observations.capabilities", ["code"]),
    ("observations.capabilities", ["c"+str(i) for i in range(9)]),
    ("observations.thresholds.min_runs", True),
    ("observations.thresholds.min_runs", 0),
    ("observations.thresholds.min_runs", 1001),
    ("observations.thresholds.min_pass_rate", 0),
    ("observations.thresholds.min_pass_rate", 1.1),
    ("observations.thresholds.max_joint_drop", -0.1),
    ("observations.thresholds.max_joint_drop", 1),
    ("observations.thresholds.min_conflicts", 1001),
    ("observations.solo.code.passes", 11),
    ("observations.solo.code.runs", -1),
    ("observations.solo.code.run_ids", [None]),
    ("observations.joint.episodes.0.spans.0.passed", 1),
    ("observations.joint.episodes.0.spans.0.start", "2026-01-15T10:00:00"),
    ("observations.joint.episodes.0.spans.0.end", "2026-01-15T09:00:00Z"),
    ("observations.joint.episodes.0.actions.0.actor", ""),
    ("observations.policy.sha256", "short"),
    ("observations.policy.rules.0.when", ["code", "code"]),
    ("observations.policy.rules.0.winner", "other"),
    ("observations.conflicts.0.injected", 1),
    ("observations.conflicts.0.loser_handling", "dropped_silently"),
    ("observations.conflicts.0.capabilities", ["code", "other"]),
    ("observations.incidents.0.baseline", float("nan")),
    ("observations.incidents.0.observed", float("inf")),
    ("observations.incidents.0.recheck.tolerance", -1),
    ("observations.incidents.0.recheck.verified_by", ""),
    ("observations.incidents.0.detected_at", "2026-01-15T10:06:00Z"),
    ("stages.L1.evidence.0.produced_by", ""),
    ("stages.L1.evidence.0.exit_code", True),
    ("stages.L1.evidence.0.command", []),
    ("outside_model", "true"),
    ("claimed_level", "L5"),
])
def test_invalid_schema_fields(path, value):
    obj = payload()
    change(obj, path, value)
    issues = validate_payload(obj)
    assert issues and all(code.startswith("schema:") for code in issues)

@pytest.mark.parametrize("field", ["capabilities", "solo", "joint", "policy", "conflicts", "incidents"])
def test_required_observations(field):
    obj = payload()["observations"]
    del obj[field]
    assert "schema:observations." + field in validate_observations(obj)

@pytest.mark.parametrize("missing", ["phenomenon", "excluded_links", "source_ref"])
def test_outside_model_requires_complete_record(missing):
    obj = payload()
    obj["outside_model"] = True
    obj["unexplained"] = {"phenomenon": "Shared resource oscillates.", "excluded_links": ["all"], "source_ref": "cases/shared/record.txt"}
    del obj["unexplained"][missing]
    assert "schema:unexplained." + missing in validate_payload(obj)

@pytest.mark.parametrize("text", ["2026-01-15T10:00:00", "2026-01-15", "2026-02-30T00:00:00Z", "2026-01-15T10:00:00z"])
def test_time_format(text):
    with pytest.raises(ValueError):
        parse_time(text)


def test_parse_time_accepts_offset_and_matches_utc():
    assert parse_time("2026-01-15T10:00:00+08:00") == parse_time("2026-01-15T02:00:00Z")

def test_duplicate_episode_and_action_ids_and_unknown_fields():
    obj = payload()
    obj["observations"]["joint"]["episodes"].append(copy.deepcopy(obj["observations"]["joint"]["episodes"][0]))
    obj["observations"]["extra"] = True
    issues = validate_payload(obj)
    assert "schema:observations.joint.episodes.episode_id" in issues
    assert "schema:observations.joint.episodes.actions.action_id" in issues
    assert "schema:observations.extra" in issues

@pytest.mark.parametrize("path", ["stages.L1.evidence.0.path", "unexplained.source_ref"])
def test_source_paths_are_relative(path):
    obj = payload()
    if path.startswith("unexplained"):
        obj["outside_model"] = True
        obj["unexplained"] = {"phenomenon": "Oscillation", "excluded_links": ["all"], "source_ref": "cases/shared/record.txt"}
    change(obj, path, "../outside.txt")
    assert validate_payload(obj)

def test_oversized_numeric_value_is_input_error():
    obj = payload()
    obj["observations"]["incidents"][0]["observed"] = 10**400
    assert validate_payload(obj)

def _field_paths(value, prefix="observations"):
    found = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = prefix + "." + key
            if path != "observations.policy":
                found.append(path)
            found.extend(_field_paths(child, path))
    elif isinstance(value, list) and value:
        if isinstance(value[0], dict):
            found.extend(_field_paths(value[0], prefix + ".0"))
    return found

@pytest.mark.parametrize("path", _field_paths(payload()["observations"]))
def test_each_observation_field_rejects_null(path):
    obj = payload()
    change(obj, path, None)
    assert validate_payload(obj)
