"""通用冒烟测试：加载全部 cases/ 用例，校验结构约定。

后续新增的用例批次不需要新写测试——只要遵守 lib.cases.case() 的约定，
这里的断言会自动覆盖到；如果新增了阶段，把预期数量加进 EXPECTED_COUNTS。
"""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import devtest
from lib.cases import REGISTRY

ID_RE = re.compile(r"^P(\d)-\d\d$")
VALID_NEEDS = {"human", "second_host", "sw2", "can_open", "pam_sudo", "usb_log", "imfw", "ota_keys"}
VALID_MUTATES = {"fp", "slot", "keys", "link", "fw", "paired", "all"}

# 目前已实现的阶段用例数；后续批次往这里加新的 phase: count。
EXPECTED_COUNTS = {0: 6, 1: 6, 2: 21, 3: 12, 4: 8, 5: 6, 6: 5, 7: 3, 8: 7, 9: 11}


class CasesSmokeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        REGISTRY.clear()
        devtest.load_cases()

    def test_all_cases_well_formed(self):
        self.assertTrue(REGISTRY, "REGISTRY 为空，load_cases() 没找到任何用例")
        for cid, c in REGISTRY.items():
            m = ID_RE.match(cid)
            self.assertIsNotNone(m, f"{cid}: id 格式不对")
            self.assertEqual(c.phase, int(m.group(1)), f"{cid}: phase={c.phase} 与 id 不符")
            self.assertLessEqual(set(c.needs), VALID_NEEDS, f"{cid}: needs 非法 {c.needs}")
            self.assertLessEqual(set(c.mutates), VALID_MUTATES, f"{cid}: mutates 非法 {c.mutates}")
            self.assertTrue(c.expect is None or isinstance(c.expect, str),
                             f"{cid}: expect 非法 {c.expect!r}")
            self.assertTrue(callable(c.fn), f"{cid}: fn 不可调用")

    def test_expected_counts_for_phases_present(self):
        counts = {}
        for c in REGISTRY.values():
            counts[c.phase] = counts.get(c.phase, 0) + 1
        for phase, expected in EXPECTED_COUNTS.items():
            self.assertEqual(counts.get(phase, 0), expected,
                              f"phase {phase}: 期望 {expected} 条，实际 {counts.get(phase, 0)}")


if __name__ == "__main__":
    unittest.main()
