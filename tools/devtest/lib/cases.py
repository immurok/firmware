"""用例注册表、结果类型、用例上下文。"""
import time

STATUSES = ("PASS", "FAIL", "SKIP", "INVALID")


class Result:
    def __init__(self, status, note="", evidence=None):
        assert status in STATUSES
        self.status = status
        self.note = note
        self.evidence = evidence or {}

    def __repr__(self):
        return f"Result({self.status}, {self.note!r})"


def PASS(note="", **ev):
    return Result("PASS", note, ev)


def FAIL(note, **ev):
    return Result("FAIL", note, ev)


def SKIP(note):
    return Result("SKIP", note)


def INVALID(note, **ev):
    return Result("INVALID", note, ev)


class Case:
    def __init__(self, id, title, phase, needs, destructive, expect, mutates, long, fn):
        self.id = id
        self.title = title
        self.phase = phase
        self.needs = tuple(needs)
        self.destructive = destructive
        self.expect = expect
        self.mutates = tuple(mutates)
        self.long = long
        self.fn = fn


REGISTRY = {}


def case(id, title, *, phase, needs=(), destructive=False, expect=None, mutates=(), long=False):
    def deco(fn):
        if id in REGISTRY:
            raise ValueError(f"用例 id 重复: {id}")
        REGISTRY[id] = Case(id, title, phase, needs, destructive, expect, mutates, long, fn)
        return fn
    return deco


def cases_for(phases, only, include_long):
    out = []
    for c in REGISTRY.values():
        if only is not None and c.id not in only:
            continue
        if only is None and phases is not None and c.phase not in phases:
            continue
        if c.long and not include_long and only is None:
            continue
        out.append(c)
    return sorted(out, key=lambda c: c.id)


class Ctx:
    def __init__(self, hooks, bus, uart, op, env, args, record, baseline):
        self.hooks = hooks
        self.bus = bus
        self.uart = uart
        self.op = op
        self.env = env
        self.args = args
        self.record = record
        self.baseline = baseline
        self.case = None
        self.lines = []          # 用例内 log，进报告

    def log(self, msg):
        self.lines.append(f"{time.strftime('%H:%M:%S')} {msg}")
        print(f"    · {msg}")

    def raw(self, hexstr, timeout_ms=1500):
        r = self.hooks.raw(hexstr, timeout_ms)
        self.log(f"RAW {hexstr} → {r.hex() if r is not None else 'NORX'}")
        return r

    def cmd(self, hexstr, timeout_ms=5000):
        r = self.hooks.cmd(hexstr, timeout_ms)
        self.log(f"CMD {hexstr} → {r.hex() if r is not None else 'TIMEOUT'}")
        return r

    def expect(self, actual, note=""):
        exp = self.case.expect
        if exp == "record":
            if self.record:
                self.baseline[self.case.id] = actual
                return PASS(f"recorded: {actual} {note}".strip(), actual=actual)
            if self.case.id not in self.baseline:
                return INVALID("no baseline, run --record", actual=actual)
            exp = self.baseline[self.case.id]
        if actual == exp:
            return PASS(note, actual=actual)
        return FAIL(f"expected {exp}, got {actual} {note}".strip(), expected=exp, actual=actual)


def hexs(b):
    """bytes|None → 稳定的可比对字符串（NORX 表示无帧）"""
    return "NORX" if b is None else b.hex()
