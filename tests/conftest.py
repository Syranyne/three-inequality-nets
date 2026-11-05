# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""测试统一在样例复核人模式下跑：名册里的公开测试密钥只在这里被承认。"""

import os

os.environ.setdefault("FOURNETS_FIXTURE_REVIEWERS", "1")
