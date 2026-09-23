import sys, os, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from lib import cases
from lib.cases import case, Ctx, PASS, FAIL, REGISTRY


class CasesTest(unittest.TestCase):
    def setUp(self):
        REGISTRY.clear()

    def test_register_and_filter(self):
        @case("P1-01", "a", phase=1)
        def a(ctx): return PASS()
        @case("P2-01", "b", phase=2, long=True)
        def b(ctx): return PASS()
        @case("P2-02", "c", phase=2, destructive=True)
        def c(ctx): return PASS()
        ids = [x.id for x in cases.cases_for({2}, None, include_long=False)]
        self.assertEqual(ids, ["P2-02"])
        ids = [x.id for x in cases.cases_for(None, {"P1-01"}, include_long=False)]
        self.assertEqual(ids, ["P1-01"])
        self.assertTrue(REGISTRY["P2-02"].destructive)

    def _ctx(self, record, baseline, expect):
        REGISTRY.pop("PX-01", None)

        @case("PX-01", "x", phase=2, expect=expect)
        def x(ctx): return PASS()
        c = Ctx(hooks=None, bus=None, uart=None, op=None, env={}, args=None,
                record=record, baseline=baseline)
        c.case = REGISTRY["PX-01"]
        return c

    def test_expect_record_mode_writes_baseline(self):
        bl = {}
        r = self._ctx(True, bl, "record").expect("ff")
        self.assertEqual(r.status, "PASS")
        self.assertEqual(bl["PX-01"], "ff")

    def test_expect_compare_against_baseline(self):
        self.assertEqual(self._ctx(False, {"PX-01": "ff"}, "record").expect("ff").status, "PASS")
        r = self._ctx(False, {"PX-01": "ff"}, "record").expect("fe")
        self.assertEqual(r.status, "FAIL")
        self.assertEqual(r.evidence["expected"], "ff")

    def test_expect_without_baseline_is_invalid(self):
        self.assertEqual(self._ctx(False, {}, "record").expect("ff").status, "INVALID")

    def test_expect_literal(self):
        self.assertEqual(self._ctx(False, {}, "ff").expect("ff").status, "PASS")
        self.assertEqual(self._ctx(False, {}, "ff").expect("00").status, "FAIL")


if __name__ == "__main__":
    unittest.main()
