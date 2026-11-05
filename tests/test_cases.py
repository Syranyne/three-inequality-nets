# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""用例汇总计数（不去重判定；各网 test_net_* 负责判定）。"""

from tests.support import case_paths


def test_case_count_matches_files():
    paths = case_paths()
    assert len(paths) >= 1
    assert len(paths) == len({path.resolve() for path in paths})
