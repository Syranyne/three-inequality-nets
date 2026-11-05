# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""统一入口：身份与独立出具。

规则 1：声明方自己产出的东西不算证据。凡是「执行过 / 复核过 / 基线竞品数值」这类
        验证器无法自己重算的事实，只认名册里独立方的签名（attest）。
规则 2：一份签名只对一次声明有效。签名报文一律以 (case_id, claim_sha256) 打头（attest 强制）。
规则 3：身份从不自报。比较两个身份一律用 principal：名册登记的按密钥指纹，
        未登记的按同形字折叠后的名字；签名方与任一声明方 principal 相同即拒绝。
规则 4：默认拒绝。缺绑定、缺角色、名册查不到、签名对不上，全部返回原因码。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from three_inequality_nets.core import reviewers as roster
from three_inequality_nets.nets.composition.identity import identity_key


def principal(root: Path, name: Any) -> str:
    if not isinstance(name, str) or not name.strip():
        return ""
    row = roster.find(root, name)
    if row is not None and isinstance(row.get("key_sha256"), str):
        return "key:" + row["key_sha256"].casefold()
    return "name:" + identity_key(name)


def same_principal(root: Path, left: Any, right: Any) -> bool:
    a, b = principal(root, left), principal(root, right)
    if not a or not b:
        return True  # 认不出身份的一律当成同一方（默认拒绝）
    if a == b:
        return True
    return isinstance(left, str) and isinstance(right, str) and identity_key(left) == identity_key(right)


def attest(
    root: Path,
    binding: tuple[str, str] | None,
    role: str,
    signer: Any,
    signature: Any,
    parts: Iterable[Any],
    claimants: Iterable[Any] = (),
) -> str | None:
    """独立出具的唯一校验入口。返回 None 表示通过，否则返回原因码。"""
    if binding is None:
        return "unbound"
    if not isinstance(signer, str) or not signer:
        return "reviewer_not_in_roster"
    for claimant in claimants:
        if same_principal(root, signer, claimant):
            return "not_independent"
    return roster.verify(root, signer, signature, binding[0], binding[1], role, *parts, role=role)
