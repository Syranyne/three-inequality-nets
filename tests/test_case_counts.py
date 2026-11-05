# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

from collections import Counter

from three_inequality_nets.nets.catalog import LINKS, NETS
from tests.support import case_paths, load_json

MINIMUM = {"pass": 2, "break": 3, "skip_step": 2, "forged": 2, "unexplained": 1}


def test_each_net_has_the_required_mix():
    for net in NETS:
        paths = case_paths(net)
        assert len(paths) >= 10
        counts = Counter()
        break_links = set()
        for path in paths:
            expect = load_json(path.with_name(path.name.replace(".input.json", ".expect.json")))
            counts[expect["category"]] += 1
            if expect["category"] == "break":
                break_links.add(expect["broken_link"])
        for category, minimum in MINIMUM.items():
            assert counts[category] >= minimum
        assert break_links == set(LINKS[net])
