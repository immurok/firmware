import sys, os, unittest, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from lib.uart import Uart


class UartTest(unittest.TestCase):
    def test_detect_reset(self):
        self.assertEqual(Uart.detect_reset("FP matched score=80\n"), None)
        self.assertEqual(Uart.detect_reset("xx\nReset status: 0x04\n"), "Reset status: 0x")
        self.assertEqual(Uart.detect_reset("V6 [fw:1.8.3.0012 build:...]"), "[fw:")
        # release-debug 固件每次 OTP 门都打一行 "STACK probe: entry depth N"（正常噪音，
        # 不是复位）；只有真的溢出才打 OVERFLOW-AT-ENTRY。
        self.assertEqual(Uart.detect_reset("STACK probe: entry depth 120\n"), None)
        self.assertEqual(
            Uart.detect_reset("STACK[gate]: OVERFLOW-AT-ENTRY (sp already below probe window)\n"),
            "OVERFLOW-AT-ENTRY")

    def test_slice_from_file(self):
        u = Uart.__new__(Uart)
        u.path = os.path.join(tempfile.mkdtemp(), "dev.log")
        with open(u.path, "wb") as f:
            f.write(b"aaa\n")
        m = u.mark("t")
        with open(u.path, "ab") as f:
            f.write(b"bbb\nccc\n")
        self.assertEqual(u.slice(m), "bbb\nccc\n")


if __name__ == "__main__":
    unittest.main()
