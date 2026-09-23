"""设备 release-debug 日志（USB CDC）抓取。

走 /dev/cu.usbmodem*（不是 wchusbserial，那个读 0 字节）。macOS 没有 timeout(1)，
用 select 轮询。抄到文件，用例前后各打一个偏移 mark，切片查复位字样。
"""
import glob
import os
import select
import termios
import threading

RESET_PATTERNS = ("Reset status: 0x", "[fw:", "Watchdog enabled", "OVERFLOW-AT-ENTRY")


class Uart:
    def __init__(self, port=None, out_path=None):
        self.port = port or self.find_port()
        self.path = out_path or os.path.join(os.getcwd(), "device.log")
        self.available = self.port is not None
        self._fd = None
        self._stop = False
        self._t = None

    @staticmethod
    def find_port():
        found = sorted(glob.glob("/dev/cu.usbmodem*"))
        return found[0] if found else None

    @staticmethod
    def detect_reset(text):
        for p in RESET_PATTERNS:
            if p in text:
                return p
        return None

    def start(self):
        if not self.available:
            return
        fd = os.open(self.port, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY)
        a = termios.tcgetattr(fd)
        a[0] = termios.IGNBRK
        a[1] = 0
        a[3] = 0
        a[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
        a[4] = a[5] = termios.B115200
        termios.tcsetattr(fd, termios.TCSANOW, a)
        self._fd = fd
        open(self.path, "wb").close()
        self._t = threading.Thread(target=self._loop, daemon=True)
        self._t.start()

    def _loop(self):
        with open(self.path, "ab", buffering=0) as out:
            while not self._stop:
                try:
                    ready = select.select([self._fd], [], [], 0.5)[0]
                except OSError:
                    return
                if ready:
                    try:
                        data = os.read(self._fd, 4096)
                    except OSError:
                        return
                    if data:
                        out.write(data)

    def stop(self):
        self._stop = True
        if self._fd is not None:
            os.close(self._fd)

    def mark(self, label):
        return os.path.getsize(self.path) if os.path.exists(self.path) else 0

    def slice(self, start):
        with open(self.path, "rb") as f:
            f.seek(start)
            return f.read().decode("utf-8", "replace")
