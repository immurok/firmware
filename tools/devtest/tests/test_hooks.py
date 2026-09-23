import sys, os, time, threading, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tests.fake_app import FakeApp, reply
from lib.hooks import Hooks, EventBus, HooksError


class HooksTest(unittest.TestCase):
    def setUp(self):
        self.abandon_closed = []

        def abandon_handler(req, c):
            c.sendall(b"A\nB\nC\nOK:done\n")
            time.sleep(0.2)
            try:
                data = c.recv(1024)
            except OSError:
                data = b""
            self.abandon_closed.append(data)

        self.app = FakeApp({
            "PING": reply("OK:TEST_HOOKS 1.9.0"),
            "GATE": reply("FP:FAIL:2", "FP:OK", "OK:PASS"),
            "RAW": reply("OK:ff"),
            "CMD": reply("OK:0001"),
            "STATE": reply('OK:{"connected":true,"fw":"1.8.3"}'),
            "BAD": reply("ERR:BAD_ARGS"),
            "ABANDON": abandon_handler,
        })
        self.h = Hooks(self.app.path)

    def tearDown(self):
        self.app.close()

    def test_ping(self):
        self.assertEqual(self.h.ping(), "TEST_HOOKS 1.9.0")

    def test_call_collects_events_and_final(self):
        r = self.h.call("TEST:GATE:5")
        self.assertEqual(r.events, ["FP:FAIL:2", "FP:OK"])
        self.assertEqual(r.final, "OK:PASS")
        self.assertTrue(r.ok)
        self.assertEqual(r.value, "PASS")

    def test_err(self):
        r = self.h.call("TEST:BAD")
        self.assertFalse(r.ok)
        self.assertEqual(r.value, "BAD_ARGS")

    def test_raw_and_cmd(self):
        self.assertEqual(self.h.raw("0500"), b"\xff")
        self.assertEqual(self.h.cmd("01"), b"\x00\x01")

    def test_state_json(self):
        self.assertEqual(self.h.state()["fw"], "1.8.3")

    def test_unreachable(self):
        with self.assertRaises(HooksError):
            Hooks("/nonexistent/cli.sock").ping()

    def test_line_split_across_recv(self):
        def h(req, c):
            c.sendall(b"OK:AB")
            time.sleep(0.2)
            c.sendall(b"CD\n")
        app = FakeApp({"SPLIT": h})
        try:
            r = Hooks(app.path).call("TEST:SPLIT")
            self.assertEqual(r.value, "ABCD")
        finally:
            app.close()

    def test_no_terminal_line_raises(self):
        def h(req, c):
            c.sendall(b"EV:1\n")
        app = FakeApp({"NOTERM": h})
        try:
            with self.assertRaises(HooksError):
                Hooks(app.path).call("TEST:NOTERM")
        finally:
            app.close()

    def test_stream_abandoned_closes_socket(self):
        gen = self.h.stream("TEST:ABANDON")
        first = next(gen)
        self.assertEqual(first, "A")
        gen.close()
        time.sleep(0.3)
        self.assertEqual(self.abandon_closed, [b""])
        r = self.h.call("TEST:PING")
        self.assertEqual(r.value, "TEST_HOOKS 1.9.0")

    def test_call_wraps_oserror(self):
        def h(req, c):
            pass
        app = FakeApp({"CLOSE": h})
        try:
            with self.assertRaises(HooksError):
                Hooks(app.path).call("TEST:CLOSE")
        finally:
            app.close()


class EventBusTest(unittest.TestCase):
    def test_wait_and_since(self):
        def sub(req, c):
            c.sendall(b"OK:SUBSCRIBED\n")
            time.sleep(0.1)
            c.sendall(b"RX:2100\nFPMATCH:3\n")
            time.sleep(0.5)
            c.sendall(b"LINK:DISCONNECTED:clean\n")
            time.sleep(2)
        app = FakeApp({"RX": sub})
        bus = EventBus(Hooks(app.path))
        bus.start()
        try:
            m = bus.mark()
            self.assertEqual(bus.wait("FPMATCH:", 2.0), "FPMATCH:3")
            self.assertEqual(bus.wait("LINK:DISCONNECTED", 2.0), "LINK:DISCONNECTED:clean")
            self.assertIsNone(bus.wait("NEVER", 0.2))
            self.assertIn("RX:2100", bus.since(m))
        finally:
            bus.stop()
            app.close()

    def test_wait_returns_first_match_not_newest(self):
        def sub(req, c):
            c.sendall(b"OK:SUBSCRIBED\nRX:01\nRX:02\nRX:03\n")
            time.sleep(2)
        app = FakeApp({"RX": sub})
        bus = EventBus(Hooks(app.path))
        bus.start()
        try:
            time.sleep(0.2)
            self.assertEqual(bus.wait("RX:", 1.0, since_mark=0), "RX:01")
        finally:
            bus.stop()
            app.close()


if __name__ == "__main__":
    unittest.main()
