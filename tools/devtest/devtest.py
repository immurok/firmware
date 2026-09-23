#!/usr/bin/env python3
"""真机自动化测试 runner。设计：docs/superpowers/specs/2026-09-20-device-e2e-test-design.md

用法：
  devtest.py                     全跑，破坏性用例逐项 y/n
  devtest.py --phase p2 p3       只跑指定阶段
  devtest.py --only P2-07        只跑指定用例
  devtest.py --record --phase p2 首跑定基线（expect="record" 的用例）
  devtest.py --resume            从 reports/.state.json 断点继续
  devtest.py --list              列用例
"""
import argparse
import importlib
import json
import os
import pkgutil
import sys
import termios
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from lib import cases as C, oracle, report                 # noqa: E402
from lib.hooks import Hooks, EventBus, HooksError         # noqa: E402
from lib.operator import Operator                         # noqa: E402
from lib.uart import Uart                                 # noqa: E402

C_OK, C_NG, C_HI, C_DIM, C_0 = "\033[32m", "\033[31m", "\033[36m", "\033[2m", "\033[0m"


class StopRun(Exception):
    """设备链路真丢了（未声明 link/all 的用例跑完 wait_reconnect 仍连不上），
    整轮中止但已跑完的记录要保留、报告照常写出来。"""
    def __init__(self, rec):
        super().__init__(f"{rec['id']}: 设备 15s 没回来")
        self.rec = rec


def _mutates(case, group):
    """`case.mutates` 里的 "all" 覆盖所有分组（health diff 已经这么处理，这里给
    run_case 里另外三处 "link"/"fw" 判断补齐同样的语义，别再各写各的漏掉 all）。"""
    return "all" in case.mutates or group in case.mutates


def _flush_stdin():
    """破坏性/等待类提示前把残留在 stdin 缓冲区里的输入（例如上一条用例期间
    误触键盘、或终端粘贴的多余内容）冲掉，避免它们被当成这条提示的回答。只有
    真终端才冲；非 tty（管道/重定向）冲不了也没有意义。"""
    if not sys.stdin.isatty():
        return
    try:
        termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
    except OSError:
        pass


def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--phase", nargs="*", help="p0..p9")
    p.add_argument("--only", nargs="*", help="用例 ID")
    p.add_argument("--list", action="store_true")
    p.add_argument("--record", action="store_true")
    p.add_argument("--resume", action="store_true")
    p.add_argument("--long", action="store_true", help="包含耗时用例")
    p.add_argument("--yes", action="store_true", help="破坏性用例不逐项确认")
    p.add_argument("--imfw", help="当前版本的合法 .imfw（P8 用）")
    p.add_argument("--socket", help="cli.sock 路径")
    p.add_argument("--no-uart", action="store_true")
    p.add_argument("--reports", default=os.path.join(HERE, "reports"))
    p.add_argument("--baseline", default=os.path.join(HERE, "baseline.json"))
    p.add_argument("--skip-p0", action="store_true", help="（测试用）不强制先跑 P0")
    return p.parse_args(argv)


def load_cases():
    import cases as pkg
    for m in pkgutil.iter_modules(pkg.__path__):
        importlib.import_module(f"cases.{m.name}")


class Runner:
    def __init__(self, args):
        self.args = args
        self.hooks = Hooks(args.socket)
        self.bus = None
        self.uart = None
        self.transcript = []
        self.op = Operator(self.transcript, yes=args.yes)
        self.env = {}
        self.records = []
        self.started = time.strftime("%Y%m%d-%H%M%S")
        self.state_path = os.path.join(args.reports, ".state.json")
        self.baseline = {}
        if os.path.exists(args.baseline):
            self.baseline = json.load(open(args.baseline))

    # ── 选用例 ──
    def select(self):
        phases = None
        if self.args.phase:
            phases = {int(p.lstrip("pP")) for p in self.args.phase}
        only = set(self.args.only) if self.args.only else None
        sel = C.cases_for(phases, only, self.args.long)
        if not self.args.skip_p0:
            p0 = C.cases_for({0}, None, True)
            sel = p0 + [c for c in sel if c.phase != 0]
        if self.args.resume and os.path.exists(self.state_path):
            done = json.load(open(self.state_path)).get("done", {})
            # P0 永远重跑（它是重建 env 的地方），resume 只跳过其它阶段已完成的用例
            sel = [c for c in sel if c.phase == 0 or c.id not in done]
        return sel

    # ── 体检 ──
    def health(self):
        try:
            return oracle.snapshot(self.hooks)
        except HooksError as e:
            return {"connected": False, "error": str(e)}

    def wait_reconnect(self, seconds=15):
        deadline = time.time() + seconds
        while time.time() < deadline:
            try:
                if self.hooks.state().get("connected"):
                    return True
            except HooksError:
                pass
            time.sleep(1)
        return False

    # ── 跑一条 ──
    def run_case(self, case):
        rec = {"id": case.id, "title": case.title, "phase": case.phase, "status": "SKIP",
               "note": "", "seconds": 0.0, "evidence": {}, "health_before": None,
               "health_after": None, "health_diff": [], "bus": [], "uart": "",
               "uart_reset": None, "log": []}
        missing = [n for n in case.needs if not self.env.get(n)]
        if missing:
            rec["note"] = f"缺条件: {', '.join(missing)}"
            return rec
        if case.destructive and not self.args.yes:
            if not self.op.confirm(f"{case.id} {case.title} 是破坏性用例，跑吗？"):
                rec["note"] = "操作员跳过"
                return rec
        ctx = C.Ctx(self.hooks, self.bus, self.uart, self.op, self.env, self.args,
                    self.args.record, self.baseline)
        ctx.case = case
        before = self.health() if case.phase > 0 else None
        bus_mark = self.bus.mark() if self.bus else 0
        uart_mark = self.uart.mark(case.id) if self.uart and self.uart.available else 0
        t0 = time.time()
        try:
            res = case.fn(ctx)
        except HooksError as e:
            res = C.FAIL(f"钩子异常: {e}")
        except KeyboardInterrupt:
            raise
        except Exception as e:  # 用例自己的 bug 也要进报告，不能把整轮带崩
            res = C.INVALID(f"用例异常: {type(e).__name__}: {e}")
        rec["seconds"] = time.time() - t0
        rec["status"], rec["note"], rec["evidence"] = res.status, res.note, res.evidence
        rec["log"] = ctx.lines
        if self.bus:
            rec["bus"] = self.bus.since(bus_mark)
        stop = False
        if before is not None:
            if not self.hooks_connected() and not _mutates(case, "link"):
                if not self.wait_reconnect():
                    stop = True
            self.quiesce()
            after = self.health()
            rec["health_before"], rec["health_after"] = before, after
            rec["health_diff"] = oracle.diff(before, after, case.mutates)
            if rec["health_diff"] and rec["status"] == "PASS":
                rec["status"] = "FAIL"
                rec["note"] = ("体检漂移: " + "; ".join(rec["health_diff"]) + " | " + rec["note"]).strip(" |")
            if not _mutates(case, "link") and self.bus:
                if any(l.startswith("LINK:DISCONNECTED") for l in rec["bus"]) and rec["status"] == "PASS":
                    rec["status"] = "FAIL"
                    rec["note"] = "用例期间断链 | " + rec["note"]
        if self.uart and self.uart.available:
            rec["uart"] = self.uart.slice(uart_mark)
            rec["uart_reset"] = Uart.detect_reset(rec["uart"])
            if rec["uart_reset"] and not _mutates(case, "fw") and not _mutates(case, "link") \
                    and rec["status"] == "PASS":
                rec["status"] = "FAIL"
                rec["note"] = f"设备复位({rec['uart_reset']}) | " + rec["note"]
        if stop:
            # phase>0 才会走到这里（before is not None 才会设 stop）：P0 还没建立 env，
            # 断线在那个阶段不该是致命的，本来就不会进这个分支。
            raise StopRun(rec)
        return rec

    def quiesce(self, silence=1.5, limit=8.0):
        """体检前等总线静默：RAW 打出去的帧若超时未回，迟到的应答会被 App 下一条命令
        认领，整条队列错位一格（真机首跑 P2-20 实测）。等 silence 秒没有 RX 再拍快照，
        让错位的应答在没有在飞命令时落地被丢弃。"""
        if not self.bus:
            return
        deadline = time.time() + limit
        while time.time() < deadline:
            m = self.bus.mark()
            if self.bus.wait("RX:", silence, since_mark=m) is None:
                return

    def hooks_connected(self):
        try:
            return bool(self.hooks.state().get("connected"))
        except HooksError:
            return False

    def save_state(self):
        os.makedirs(self.args.reports, exist_ok=True)
        done = {}
        if self.args.resume and os.path.exists(self.state_path):
            done = json.load(open(self.state_path)).get("done", {})
        # SKIP 不算「做完」——因缺条件被跳过的用例，条件满足后 resume 要能重新捡起来
        done.update({r["id"]: r["status"] for r in self.records if r["status"] != "SKIP"})
        with open(self.state_path, "w") as f:
            json.dump({"started": self.started, "done": done,
                       "device": {"fw": self.env.get("fw"), "slot_active": self.env.get("slot_active")}},
                      f, indent=1)

    def _record(self, rec):
        self.records.append(rec)
        color = {"PASS": C_OK, "FAIL": C_NG}.get(rec["status"], C_DIM)
        print(f"  {color}{rec['status']}{C_0} {rec['note']} ({rec['seconds']:.1f}s)")
        self.save_state()

    def finish(self):
        if self.args.record:
            with open(self.args.baseline, "w") as f:
                json.dump(self.baseline, f, indent=1, sort_keys=True)
        md, js = report.write(self.args.reports, self.started, self.records, self.env, self.transcript)
        print(f"\n报告: {md}")
        return 1 if any(r["status"] == "FAIL" for r in self.records) else 0

    def run(self):
        sel = self.select()
        if self.args.list:
            for c in sel:
                flags = "".join(f for f, on in (("D", c.destructive), ("L", c.long), ("R", c.expect == "record")) if on)
                print(f"{c.id}  {c.title}  {C_DIM}{','.join(c.needs)} {flags}{C_0}")
            return 0
        try:
            v = self.hooks.ping()
            if "TEST_HOOKS" not in v:
                print(f"{C_NG}App 不是 TEST_HOOKS 构建（PING → {v}），拒跑。部署：app-macos/build-deploy.sh -a -s -t{C_0}")
                return 2
        except HooksError as e:
            print(f"{C_NG}{e}{C_0}")
            return 2
        self.env["human"] = sys.stdin.isatty()      # 有终端才能要求操作员配合
        self.bus = EventBus(self.hooks)
        self.bus.start()
        if not self.args.no_uart:
            self.uart = Uart(out_path=os.path.join(self.args.reports, f"{self.started}-device.log"))
            os.makedirs(self.args.reports, exist_ok=True)
            self.uart.start()
            self.env["usb_log"] = self.uart.available
        phase_seen = set()
        try:
            for c in sel:
                if c.phase not in phase_seen:
                    phase_seen.add(c.phase)
                    print(f"\n{C_HI}══ P{c.phase} ══{C_0}")
                    if c.phase == 9 and self.args.yes:
                        _flush_stdin()  # 冲掉前面阶段可能残留的按键/粘贴，别误当这里的答案
                        try:
                            ans = input("即将进入破坏性阶段 P9（出厂重置/开盖），继续？[y/N] ")
                        except EOFError:
                            ans = ""  # 无人值守（非 tty stdin）：当作拒绝，绝不误入破坏性阶段
                        if ans.strip().lower() not in ("y", "yes"):
                            break
                print(f"{C_HI}▸ {c.id} {c.title}{C_0}")
                try:
                    rec = self.run_case(c)
                except StopRun as e:
                    self._record(e.rec)
                    print(f"{C_NG}设备 15s 没回来，中止本轮（--resume 可续）{C_0}")
                    break
                self._record(rec)
        except KeyboardInterrupt:
            print(f"\n{C_DIM}Ctrl+C，写出已完成部分{C_0}")
        finally:
            if self.bus:
                self.bus.stop()
            if self.uart:
                self.uart.stop()
        return self.finish()


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    load_cases()
    return Runner(args).run()


if __name__ == "__main__":
    sys.exit(main())
