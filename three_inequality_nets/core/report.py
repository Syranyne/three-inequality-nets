# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""统一判定结果。"""

from __future__ import annotations

from typing import Any

from three_inequality_nets.core.schema import dumps


def make_result(
    net: str,
    verdict: str,
    broken_link: str | None,
    claimed_level: Any,
    proven_level: Any,
    reasons: list[str],
) -> dict[str, Any]:
    return {
        "broken_link": broken_link,
        "claimed_level": claimed_level,
        "net": net,
        "proven_level": proven_level,
        "reasons": list(reasons),
        "verdict": verdict,
    }


def to_text(result: dict[str, Any]) -> str:
    link = result.get("broken_link") or "-"
    lines = [
        f"verdict: {result.get('verdict')}",
        f"broken_link: {link}",
        f"claimed_level: {result.get('claimed_level')}",
        f"proven_level: {result.get('proven_level')}",
    ]
    for reason in result.get("reasons") or []:
        lines.append(f"reason: {reason}")
    return "\n".join(lines) + "\n"


def to_json(result: dict[str, Any]) -> str:
    return dumps(result)
