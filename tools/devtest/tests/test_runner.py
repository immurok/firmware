import sys, os, unittest, tempfile, json, io
from unittest import mock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tests.fake_app import FakeApp, reply
from lib.cases import case, REGISTRY, PASS, FAIL
import devtest


STATE = 'OK:{"connected":true,"fw":"1.8.3","fp_bitmap":1,"paired":true,"slot_bitmap":1,"slot_active":1}'


def sub(req, c):
    c.sendall(b"OK:SUBSCRIBED\n")
    import time; time.sleep(5)


class RunnerTest(unittest.TestCase):
    def setUp(self):
        REGISTRY.clear()
        self.app = FakeApp({
            "PING": reply("OK:TEST_HOOKS 1.9.0"),
            "STATE": reply(STATE),
            "CMD": reply("OK:0000"),
            "RX": sub,
            "RAW": reply("OK:ff"),
        })
        self.out = tempfile.mkdtemp()

    def tearDown(self):
        self.app.close()

    def _args(self, *extra):
        return devtest.parse_args(["--socket", self.app.path, "--no-uart", "--yes",
                                   "--reports", self.out, "--skip-p0", *extra])

    def _args_with_p0(self, *extra):
        # 不带 --skip-p0：走 select() 里真正的 P0 注入/resume 逻辑
        return devtest.parse_args(["--socket", self.app.path, "--no-uart", "--yes",
                                   "--reports", self.out, *extra])

    def test_pass_fail_and_exit_code(self):
        @case("P1-01", "ok", phase=1)
        def a(ctx): return PASS("fine")
        @case("P1-02", "bad", phase=1)
        def b(ctx): return FAIL("nope")
        rc = devtest.Runner(self._args("--phase", "p1")).run()
        self.assertEqual(rc, 1)
        js = [f for f in os.listdir(self.out) if f.endswith(".json")][0]
        recs = json.load(open(os.path.join(self.out, js)))["records"]
        self.assertEqual([r["status"] for r in recs], ["PASS", "FAIL"])

    def test_health_diff_fails_case(self):
        # 用例声称不改 fp，却让 STATE 的 fp_bitmap 变了 → runner 判 FAIL
        calls = {"n": 0}
        def state(req, c):
            calls["n"] += 1
            bm = 1 if calls["n"] <= 1 else 3
            c.sendall(f'OK:{{"connected":true,"fw":"1.8.3","fp_bitmap":{bm},"paired":true,"slot_bitmap":1,"slot_active":1}}\n'.encode())
        self.app.handlers["STATE"] = state
        @case("P2-01", "raw", phase=2, expect="ff")
        def a(ctx): return ctx.expect(ctx.raw("0500").hex())
        devtest.Runner(self._args("--phase", "p2")).run()
        js = [f for f in os.listdir(self.out) if f.endswith(".json")][0]
        rec = json.load(open(os.path.join(self.out, js)))["records"][0]
        self.assertEqual(rec["status"], "FAIL")
        self.assertIn("fp", rec["health_diff"][0])

    def test_record_writes_baseline(self):
        @case("P2-01", "raw", phase=2, expect="record")
        def a(ctx): return ctx.expect(ctx.raw("0500").hex())
        bl = os.path.join(self.out, "baseline.json")
        rc = devtest.Runner(self._args("--phase", "p2", "--record", "--baseline", bl)).run()
        self.assertEqual(rc, 0)
        self.assertEqual(json.load(open(bl))["P2-01"], "ff")

    def test_needs_skip(self):
        @case("P6-01", "two hosts", phase=6, needs=("second_host",))
        def a(ctx): return PASS()
        r = devtest.Runner(self._args("--phase", "p6"))
        r.env["second_host"] = False
        r.run()
        js = [f for f in os.listdir(self.out) if f.endswith(".json")][0]
        self.assertEqual(json.load(open(os.path.join(self.out, js)))["records"][0]["status"], "SKIP")

    def test_resume_skips_done(self):
        # 两条用例都跑到 PASS：PASS 算「做完」，resume 应该只挑出没做完的那条
        @case("P1-01", "a", phase=1)
        def a(ctx): return PASS()
        @case("P1-02", "b", phase=1)
        def b(ctx): return PASS()
        devtest.Runner(self._args("--only", "P1-01")).run()
        r = devtest.Runner(self._args("--phase", "p1", "--resume"))
        r.run()
        self.assertEqual([x["id"] for x in r.records], ["P1-02"])

    def test_resume_reruns_phase0_and_keeps_skipped_pending(self):
        # P0 永远重跑（它是重建 env 的地方）；因缺条件 SKIP 的用例不算「做完」，
        # 条件满足后 resume 要能把它捡回来重跑
        calls = {"p0": 0}
        @case("P0-01", "ping", phase=0)
        def z(ctx):
            calls["p0"] += 1
            return PASS()
        @case("P1-01", "needs cond", phase=1, needs=("cond",))
        def a(ctx): return PASS()
        @case("P1-02", "ok", phase=1)
        def b(ctx): return PASS()

        r1 = devtest.Runner(self._args_with_p0("--phase", "p1"))
        r1.run()
        self.assertEqual([x["id"] for x in r1.records], ["P0-01", "P1-01", "P1-02"])
        self.assertEqual(r1.records[1]["status"], "SKIP")   # cond 缺失
        self.assertEqual(calls["p0"], 1)

        state = json.load(open(os.path.join(self.out, ".state.json")))
        self.assertNotIn("P1-01", state["done"])   # SKIP 不算 done
        self.assertIn("P0-01", state["done"])
        self.assertIn("P1-02", state["done"])

        r2 = devtest.Runner(self._args_with_p0("--phase", "p1", "--resume"))
        r2.env["cond"] = True
        r2.run()
        self.assertEqual([x["id"] for x in r2.records], ["P0-01", "P1-01"])  # P0 重跑 + 之前 SKIP 的重跑
        self.assertEqual(r2.records[1]["status"], "PASS")
        self.assertEqual(calls["p0"], 2)

    def test_p9_confirm_eof_does_not_crash_and_skips_destructive_phase(self):
        # 非交互 stdin（无人值守）下 input() 会抛 EOFError；必须当成「拒绝」处理，
        # 不能让整轮崩掉、也不能误入破坏性阶段
        @case("P9-01", "factory reset", phase=9)
        def a(ctx): return PASS()
        r = devtest.Runner(self._args("--phase", "p9"))
        with mock.patch.object(sys, "stdin", io.StringIO("")):
            rc = r.run()
        self.assertEqual(r.records, [])   # P9 用例被跳过，压根没跑
        self.assertEqual(rc, 0)
        js = [f for f in os.listdir(self.out) if f.endswith(".json")]
        self.assertEqual(len(js), 1)      # 报告仍然写出来了

    def test_all_mutates_covers_link_disconnect_check(self):
        # mutates=("all",) 该覆盖 "link" 分组：老实现里 run_case 的三处判断都精确匹配
        # 字符串 "link"，没认 "all"，会把这种用例的一次断链事件误判成 FAIL。
        def sub_with_disconnect(req, c):
            c.sendall(b"OK:SUBSCRIBED\n")
            import time
            time.sleep(0.3)
            try:
                c.sendall(b"LINK:DISCONNECTED:test\n")
            except OSError:
                pass
            time.sleep(5)
        self.app.handlers["RX"] = sub_with_disconnect

        @case("P2-01", "all mutates", phase=2, mutates=("all",))
        def a(ctx):
            import time
            time.sleep(0.6)   # 留够时间让上面那条 LINK:DISCONNECTED 落进这条用例的 bus 窗口
            return PASS()

        rc = devtest.Runner(self._args("--phase", "p2")).run()
        js = [f for f in os.listdir(self.out) if f.endswith(".json")][0]
        rec = json.load(open(os.path.join(self.out, js)))["records"][0]
        self.assertEqual(rec["status"], "PASS")

    def test_link_lost_stops_run(self):
        # 用例没声明 link/all，跑完之后设备真的连不上了（wait_reconnect 15s 判定失败，
        # 不是短暂抖动）：runner 不能把剩下的用例硬跑到底，必须整轮中止，但已完成的
        # 记录和报告都要正常写出来。
        calls = {"n": 0}
        def state(req, c):
            calls["n"] += 1
            if calls["n"] == 1:
                c.sendall(STATE.encode() + b"\n")
            else:
                c.sendall(b'OK:{"connected":false}\n')
        self.app.handlers["STATE"] = state
        @case("P2-01", "a", phase=2)
        def a(ctx): return PASS()
        @case("P2-02", "b", phase=2)
        def b(ctx): return PASS()
        with mock.patch.object(devtest.Runner, "wait_reconnect", return_value=False):
            rc = devtest.Runner(self._args("--phase", "p2")).run()
        self.assertEqual(rc, 1)
        js = [f for f in os.listdir(self.out) if f.endswith(".json")][0]
        recs = json.load(open(os.path.join(self.out, js)))["records"]
        self.assertEqual([r["id"] for r in recs], ["P2-01"])   # P2-02 没跑，整轮中止
        self.assertEqual(recs[0]["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
