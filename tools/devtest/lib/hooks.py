"""~/.immurok/cli.sock 上 TEST:* 控制面的客户端。

协议：发一行请求；App 逐行回事件，最后一行 OK:/ERR: 开头后关连接。
TEST:RX:SUB 例外：一直推到我们关连接，EventBus 用它当事件总线。
"""
import json
import os
import socket
import threading
import time


class HooksError(Exception):
    pass


class Reply:
    def __init__(self, events, final):
        self.events = events
        self.final = final

    @property
    def ok(self):
        return self.final.startswith("OK")

    @property
    def value(self):
        for p in ("OK:", "ERR:"):
            if self.final.startswith(p):
                return self.final[len(p):]
        return self.final

    def __repr__(self):
        return f"Reply(events={self.events!r}, final={self.final!r})"


def _default_path():
    return os.path.expanduser("~/.immurok/cli.sock")


class Hooks:
    def __init__(self, path=None):
        self.path = path or _default_path()

    def _connect(self, timeout):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(self.path)
        except OSError as e:
            s.close()
            raise HooksError(f"cli.sock 不可达 ({self.path}): {e}")
        return s

    def stream(self, cmd, timeout=180.0):
        """逐行产出，直到 OK:/ERR: 收尾行（也产出）或对端关闭。"""
        s = self._connect(timeout)
        try:
            s.sendall((cmd + "\n").encode())
            buf = b""
            while True:
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    raise HooksError(f"{cmd}: {timeout}s 没等到收尾行")
                except OSError as e:
                    raise HooksError(f"{cmd}: 连接异常: {e}")
                if not chunk:
                    return
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    text = line.decode("utf-8", "replace")
                    yield text
                    if text.startswith("OK") or text.startswith("ERR"):
                        return
        finally:
            s.close()

    def call(self, cmd, timeout=10.0):
        events = []
        final = None
        for line in self.stream(cmd, timeout):
            if line.startswith("OK") or line.startswith("ERR"):
                final = line
            else:
                events.append(line)
        if final is None:
            raise HooksError(f"{cmd}: 对端关闭前没有收尾行")
        return Reply(events, final)

    def ping(self):
        r = self.call("TEST:PING", timeout=5)
        if not r.ok:
            raise HooksError(f"PING 失败: {r.final}")
        return r.value

    def state(self):
        r = self.call("TEST:STATE", timeout=25)
        if not r.ok:
            raise HooksError(f"STATE 失败: {r.final}")
        return json.loads(r.value)

    def raw(self, hexstr, timeout_ms=1500):
        """原样写字节；返回第一帧 bytes，超时无帧返回 None。"""
        r = self.call(f"TEST:RAW:{hexstr}:{timeout_ms}", timeout=timeout_ms / 1000 + 5)
        if not r.ok:
            raise HooksError(f"RAW {hexstr}: {r.final}")
        return None if r.value == "NORX" else bytes.fromhex(r.value)

    def cmd(self, hexstr, timeout_ms=5000):
        """走 App 队列发已知命令；超时返回 None。"""
        r = self.call(f"TEST:CMD:{hexstr}:{timeout_ms}", timeout=timeout_ms / 1000 + 5)
        if r.final == "ERR:TIMEOUT":
            return None
        if not r.ok:
            raise HooksError(f"CMD {hexstr}: {r.final}")
        return bytes.fromhex(r.value)


class EventBus:
    """常驻一条 TEST:RX:SUB 连接，把事件行攒进列表供 wait/since 查。"""

    def __init__(self, hooks):
        self.hooks = hooks
        self.lines = []
        self._cv = threading.Condition()
        self._sock = None
        self._t = None
        self._stop = False

    def start(self):
        self._sock = self.hooks._connect(None)
        self._sock.sendall(b"TEST:RX:SUB\n")
        self._t = threading.Thread(target=self._loop, daemon=True)
        self._t.start()

    def _loop(self):
        buf = b""
        while not self._stop:
            try:
                chunk = self._sock.recv(4096)
            except OSError:
                return
            if not chunk:
                return
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                with self._cv:
                    self.lines.append((time.time(), line.decode("utf-8", "replace")))
                    self._cv.notify_all()

    def stop(self):
        self._stop = True
        if self._sock:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._sock.close()

    def mark(self):
        with self._cv:
            return len(self.lines)

    def since(self, mark):
        with self._cv:
            return [ln for _, ln in self.lines[mark:]]

    def drain(self):
        return self.mark()

    def wait(self, prefix, timeout, since_mark=None):
        deadline = time.time() + timeout
        idx = self.mark() if since_mark is None else since_mark
        with self._cv:
            while True:
                for i in range(idx, len(self.lines)):
                    if self.lines[i][1].startswith(prefix):
                        return self.lines[i][1]
                idx = len(self.lines)
                remaining = deadline - time.time()
                if remaining <= 0:
                    return None
                self._cv.wait(remaining)
