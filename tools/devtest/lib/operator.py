"""操作员提示。所有交互进 transcript，写进报告。"""
import select
import sys
import termios
import time

C_HI = "\033[36m"
C_WARN = "\033[33m"
C_0 = "\033[0m"


class Operator:
    def __init__(self, transcript, yes=False):
        self.transcript = transcript
        self.yes = yes

    def _record(self, prompt, answer):
        self.transcript.append((time.strftime("%H:%M:%S"), prompt, answer))

    def _readline(self, timeout):
        if select.select([sys.stdin], [], [], timeout)[0]:
            line = sys.stdin.readline()
            if line == "":
                return None  # EOF / 非交互 stdin，按超时处理
            return line.rstrip("\n")
        return None

    def ask(self, text, timeout=90):
        # 上一条用例的等待窗口/操作动作可能往 stdin 里溅了残留字节（提前敲的键、
        # 终端粘贴），先冲掉再问，不然会被当成这条提示的答案。
        if sys.stdin.isatty():
            try:
                termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
            except OSError:
                pass
        print(f"\n{C_HI}▶ {text}{C_0}  [{timeout}s] ", end="", flush=True)
        ans = self._readline(timeout)
        print()
        self._record(text, ans if ans is not None else "<timeout>")
        return ans

    def wait_enter(self, text, timeout=90):
        return self.ask(f"{text}（回车继续）", timeout) is not None

    def confirm(self, text, default=False):
        if self.yes:
            self._record(text, "<--yes>")
            return True
        ans = self.ask(f"{text} [{'Y/n' if default else 'y/N'}]", timeout=300)
        if ans is None or ans.strip() == "":
            return default
        return ans.strip().lower() in ("y", "yes")

    def touch(self, text="请触摸指纹传感器"):
        print(f"\n{C_WARN}✋ {text}{C_0}", flush=True)
        self._record(text, "<prompt>")
