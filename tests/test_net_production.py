# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

import pytest

from tests.support import case_paths, matches


@pytest.mark.parametrize("path", case_paths("production"), ids=lambda path: path.stem)
def test_production_case(path):
    assert matches(path)
