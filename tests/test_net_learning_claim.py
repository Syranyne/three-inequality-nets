# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

import pytest

from tests.support import case_paths, matches


@pytest.mark.parametrize("path", case_paths("learning_claim"), ids=lambda path: path.stem)
def test_learning_case(path):
    assert matches(path)
