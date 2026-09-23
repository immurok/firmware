"""假 immurok.app：在临时 Unix socket 上按脚本应答 TEST:* 请求，测试共用。"""
import os
import socket
import tempfile
import threading


class FakeApp:
    def __init__(self, handlers=None):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "cli.sock")
        self.handlers = handlers or {}
        self.requests = []
        self._srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._srv.bind(self.path)
        self._srv.listen(8)
        self._stop = False
        self._t = threading.Thread(target=self._loop, daemon=True)
        self._t.start()

    def _loop(self):
        while not self._stop:
            try:
                c, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        req = c.recv(1024).decode().strip()
        self.requests.append(req)
        name = req.split(":")[1] if ":" in req else req
        h = self.handlers.get(name) or self.handlers.get("*")
        try:
            if h is None:
                c.sendall(b"ERR:UNKNOWN_TEST_COMMAND\n")
            else:
                h(req, c)
        finally:
            c.close()

    def close(self):
        self._stop = True
        self._srv.close()


def reply(*lines):
    """handler 工厂：逐行发出后关连接。"""
    def h(req, c):
        for ln in lines:
            c.sendall((ln + "\n").encode())
    return h
