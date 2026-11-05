# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""五张网的环节名、证据白名单与阈值。"""

from __future__ import annotations

NETS = ("authority", "learning_claim", "retrieval", "production", "composition")

LINKS = {
    "authority": (
        "发送者→语义作者",
        "语义作者→事实主张",
        "事实主张→写入授权",
    ),
    "learning_claim": (
        "窗口收到→进入训练集",
        "进入训练集→得到正确标注",
        "得到正确标注→推理时真正学会",
    ),
    "retrieval": (
        "检索命中→语义理解",
        "语义理解→权威裁决",
        "权威裁决→施工结论",
    ),
    "production": (
        "生成能力→生产能力",
        "生产能力→产品价值",
        "产品价值→足以动摇行业的竞争力",
    ),
    "composition": (
        "会做→能同时做",
        "能同时做→冲突时会正确调权",
        "冲突时会正确调权→造成后果后能自主纠偏",
    ),
}

STAGES = ("L1", "L2", "L3", "L4")

# 前四网 L4 要求已复核：写入授权 / 学会 / 施工 / 竞争力主张都需要独立复核。
# L1–L3 保留 artifact：有绑定证据文件即可推进；执行核实集中在 L4。
MIN_LEVELS = {
    "authority": {"L1": "artifact", "L2": "artifact", "L3": "artifact", "L4": "reviewed"},
    "learning_claim": {"L1": "artifact", "L2": "artifact", "L3": "artifact", "L4": "reviewed"},
    "retrieval": {"L1": "artifact", "L2": "artifact", "L3": "artifact", "L4": "reviewed"},
    "production": {"L1": "artifact", "L2": "artifact", "L3": "artifact", "L4": "reviewed"},
    "composition": {"L1": "executed", "L2": "executed", "L3": "executed", "L4": "reviewed"},
}

# 每网每阶段允许的 evidence.kind。不再有通用的 "record"：每份证据都要落到本网本阶段的专属类型。
EVIDENCE_KINDS = {
    "authority": {
        "L1": frozenset({"sender-record", "message-record"}),
        "L2": frozenset({"author-record", "handoff-record"}),
        "L3": frozenset({"fact-check-record"}),
        "L4": frozenset({"write-approval-record"}),
    },
    "learning_claim": {
        "L1": frozenset({"window-record"}),
        "L2": frozenset({"dataset-record"}),
        "L3": frozenset({"label-record"}),
        "L4": frozenset({"held-out-record"}),
    },
    "retrieval": {
        "L1": frozenset({"hit-record"}),
        "L2": frozenset({"alignment-record"}),
        "L3": frozenset({"authority-record"}),
        "L4": frozenset({"conditions-record"}),
    },
    "production": {
        "L1": frozenset({"sample-record"}),
        "L2": frozenset({"release-record"}),
        "L3": frozenset({"user-evaluation"}),
        "L4": frozenset({"benchmark-record"}),
    },
    "composition": {
        "L1": frozenset({"trial-record", "solo-observations", "solo-run"}),
        "L2": frozenset({"trial-record", "joint-observations", "joint-run"}),
        "L3": frozenset({"priority-policy", "conflict-observations", "conflict-trial"}),
        "L4": frozenset({"trial-record", "incident-observations", "correction-incident"}),
    },
}

# 生产网竞争力阈值。默认值「待校」。输入只能收紧（取较严者），不能放宽；结果回显实际值。
PRODUCTION_THRESHOLDS = {
    "min_margin": {"value": 0.0, "status": "待校"},
    "min_samples": {"value": 30, "status": "待校"},
    "min_user_samples": {"value": 30, "status": "待校"},
}

# 仓库本体路径前缀：证据不得落在这里。
EVIDENCE_BLOCKED_PREFIXES = (
    "LICENSE",
    "NOTICE",
    "README.md",
    "docs/",
    "three_inequality_nets/",
    "tests/",
    "dev_tools/",
    "pyproject.toml",
    "reviewers/",
)

# 前四网证据文件的最小内容结构：JSON 对象，evidence_kind 与 stage 必须与条目一致。
# 组合网证据另有观测归档绑定（composition/binding.py），不走这条。
EVIDENCE_CONTENT_NETS = frozenset({"authority", "learning_claim", "retrieval", "production"})

# 证据允许的相对路径前缀。
EVIDENCE_ALLOWED_PREFIXES = (
    "cases/",
    "evidence/",
    "examples/demo/fixtures/",
)
