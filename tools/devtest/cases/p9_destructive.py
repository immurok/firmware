"""P9 破坏性收尾：解绑=出厂重置、配对边界、FACTORY_RESET、长按重置、防拆。逐项确认。
每条跑完设备状态都要明确：_ensure_paired 负责把设备重新配回来。

fix round 1（对照 controller 裁决 + firmware hidkbd.c 复核，见 task-16-17-report.md）：
- `_pair` 的 socket 超时改成 100（App 侧 handlePair 内部最长等 90s 才收尾），原来两个
  数字贴得太近，会在钩子快收尾那一刻被 socket 超时抢先打断；流提前断线收不到终止行时
  天然返回 (stages, None)，调用方一律把 final is None 当 FAIL 处理。
- P9-03：对照固件确认 PAIR_INIT 的回包格式是 `[0x30][status]`——0xF0=等按键、
  0xF1=需要先出厂重置，第一版误把 `r[0] == 0xF0` 当判据（第一字节其实永远是操作码
  回显 0x30），改成 `r[0] == 0x30 and r[1] == 0xF0`；等按键态用短按 1-3 秒取消
  （≥3 秒是长按出厂重置，不能提示"长按"）。固件对 PAIR_INIT 一律先回
  `[0x30][0xF0]` 等按键，不管有没有指纹残留——ECDH 要按键后才在 BUTTON_SCAN_EVT
  里起（第一版误以为"无指纹时 PAIR_INIT 会直接起 ECDH"，对照 hidkbd.c 确认不成立）；
  一律只记协议头两字节进基线，完整回包进日志（防御性兜底，正常不会命中）。
- P9-06：`ctx.raw()` 在配对线程占着门的窗口内并发探测，命中 App 侧
  `testCommandInFlight` 会直接抛 `HooksError`（ERR:BUSY）；原来没接住会让整条用例
  异常退出，还把后台配对线程晾在等按键态没人 join。现在包 try/except HooksError，
  记 `second=ERR:...`，无论探测成不成功都照常提示按键、join 配对线程。
- 出厂重置类用例（P9-02/08/09/11）和 `_ensure_paired`：擦 bond 后设备换新地址广播，
  macOS 侧旧配对记录可能连不上——90s 常规等待落空后再提示操作员去系统设置手动忘记/
  重新连接，额外给 60s 兜底，不再一次性判死。
- P9-08：RAW FACTORY_RESET 在设备上有登记指纹时走门控（回 0x11 WAIT_FP），需要真的
  摸一下指纹才会继续擦；如果操作员没有在窗口内触摸（不断链），主动 GATE_CANCEL 收尾
  并记 `reset=no`，不把门悬在那。
"""
import threading
import time
from lib.cases import case, PASS, FAIL, INVALID, SKIP
from lib.hooks import HooksError


def _wait(ctx, pred, seconds, step=2):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            st = ctx.hooks.state()
            if pred(st):
                return st
        except Exception:
            pass
        time.sleep(step)
    return None


def _pair(ctx, prompt="设备等按键：请短按设备按键", timeout=100):
    """timeout 是 socket 每次 recv 的超时；App 侧 handlePair 内部最长等 90s（含按钮超时
    重试）才收尾，这里要留出比 90s 更宽的余量，否则会在钩子快收尾时被 socket 超时抢先
    打断。流提前断线收不到终止行时返回 (stages, None)，调用方一律把 final is None 当 FAIL。"""
    ctx.op.touch(prompt)
    stages = []
    final = None
    for line in ctx.hooks.stream("TEST:PAIR", timeout=timeout):
        if line.startswith("STAGE:"):
            stages.append(line)
        elif line.startswith(("OK", "ERR")):
            final = line
    ctx.log(f"PAIR {stages} → {final}")
    return stages, final


def _wait_after_erase(ctx, seconds=90):
    """擦 bond 之后设备用新地址广播，macOS 侧的旧配对记录可能连不上——先按 90s 常规
    等待，不行就提示操作员去系统设置手动忘记/重新连接，再给 60s 兜底。"""
    st = _wait(ctx, lambda s: s.get("connected"), seconds)
    if st is not None:
        return st
    ctx.op.wait_enter(
        "设备擦了 bond 后 macOS 侧旧配对可能连不上：请到 系统设置→蓝牙 忘记 immurok 并重新连接，然后回车",
        timeout=300,
    )
    return _wait(ctx, lambda s: s.get("connected"), 60)


def _ensure_paired(ctx):
    """收口：设备没配对就配一次；返回是否已配对。"""
    st = _wait_after_erase(ctx)
    if st is None:
        return False
    if st.get("paired"):
        return True
    _, final = _pair(ctx)
    st = _wait(ctx, lambda s: s.get("connected") and s.get("paired"), 30)
    return st is not None


@case("P9-02", "解绑唯一主机 = 出厂重置：未配对、指纹清空", phase=9, destructive=True, mutates=("all",))
def unpair_last(ctx):
    bm = int(ctx.hooks.call("TEST:SLOT_STATUS").value.split(":")[0])
    if bm == 0b11:
        return SKIP("两槽都占，解绑本槽不是出厂重置（先跑 P6-05 清另一槽）")
    r = ctx.hooks.call("TEST:UNPAIR", timeout=30)
    ctx.log(f"UNPAIR → {r.final}")
    st = _wait_after_erase(ctx)
    if st is None:
        return FAIL("解绑后设备没回来（90s + 提示 + 60s 兜底都没等到）")
    if st.get("paired"):
        return FAIL("解绑后 STATE 仍 paired")
    if st.get("fp_bitmap", 0) != 0:
        return FAIL(f"解绑后指纹没清空: 0x{st['fp_bitmap']:02x}")
    return PASS("未配对，指纹 0")


@case("P9-03", "未配对态 PAIR_INIT：指纹残留 0 → 不应回 0xF1", phase=9, destructive=True, mutates=("all",), expect="record")
def pair_init_clean(ctx):
    st = ctx.hooks.state()
    if st.get("paired"):
        return SKIP("设备已配对，此用例要在 P9-02 之后")
    r = ctx.raw("3000", 3000)
    if r is None:
        res = "NORX"
    else:
        if r[0] == 0x30 and len(r) >= 34:
            # 正常情况下 PAIR_INIT 恒回 2 字节 [0x30][0xF0/0xF1] 等按键，不会带
            # pubkey（ECDH 要按键后才在 BUTTON_SCAN_EVT 里起）；这里只是防御性
            # 兜底，万一命中就不逐字节记基线（不稳定），日志留全量。
            ctx.log(f"回包异常地带了 pubkey，完整回包 {r.hex()}")
        res = r[:2].hex()
    # 回包格式是 [0x30][status]：0xF0=等按键，0xF1=需要先出厂重置。别把设备留在等按键
    # 态：短按 1-3 秒取消（≥3 秒是长按出厂重置，别按太久）。
    if r and len(r) >= 2 and r[0] == 0x30 and r[1] == 0xF0:
        ctx.op.touch("按住按键 1–3 秒后松开取消（别超过 3 秒，≥3 秒是出厂重置）")
        ctx.bus.wait("PAIRBTN:", 40)
    return ctx.expect(res)


@case("P9-04", "PAIR_INIT 后 30s 不按键 → 超时", phase=9, needs=("human",), destructive=True, mutates=("all",), long=True)
def button_timeout(ctx):
    if ctx.hooks.state().get("paired"):
        return SKIP("设备已配对")
    m = ctx.bus.mark()
    _, final = _pair(ctx, prompt="接下来【不要】按键，等它超时", timeout=120)
    evt = ctx.bus.wait("PAIRBTN:00", 5, since_mark=m)
    return PASS(f"{final} {evt}") if "buttonTimeout" in (final or "") else FAIL(f"{final} {evt}")


@case("P9-05", "PAIR_INIT 后长按 → 取消", phase=9, needs=("human",), destructive=True, mutates=("all",))
def button_cancel(ctx):
    if ctx.hooks.state().get("paired"):
        return SKIP("设备已配对")
    m = ctx.bus.mark()
    _, final = _pair(ctx, prompt="按住按键 1–3 秒后松开取消（别超过 3 秒，≥3 秒是出厂重置）")
    evt = ctx.bus.wait("PAIRBTN:02", 5, since_mark=m)
    return PASS(f"{final} {evt}") if "buttonCancelled" in (final or "") else FAIL(f"{final} {evt}")


@case("P9-06", "配对窗口抢先（N1）：等按键期间再发 PAIR_INIT", phase=9, needs=("human",), destructive=True, mutates=("all",), expect="record")
def pair_preempt(ctx):
    if ctx.hooks.state().get("paired"):
        return SKIP("设备已配对")
    out = {}

    def go():
        try:
            out["r"] = _pair(ctx, prompt="先别按键，3 秒后再短按")
        except Exception as e:
            out["err"] = str(e)

    t = threading.Thread(target=go)
    t.start()
    time.sleep(3)
    second_err = None
    try:
        second = ctx.raw("3000", 3000)
    except HooksError as e:
        # 配对线程正占着门，这次探测很可能撞上 App 侧 testCommandInFlight 被拒
        # (ERR:BUSY)；接住异常，不管探测结果如何都要照常提示按键、join 线程。
        second = None
        second_err = str(e)
    ctx.op.touch("现在短按按键")
    t.join(120)
    if out.get("err") is not None:
        return FAIL(f"配对线程异常: {out['err']}")
    _, final = out.get("r", ([], None))
    st = _wait(ctx, lambda s: s.get("connected"), 30) or {}
    second_note = f"ERR:{second_err}" if second_err is not None else (second.hex() if second else "NORX")
    return ctx.expect(f"second={second_note};pair={final};paired={st.get('paired')}")


@case("P9-07", "正常重配对成功", phase=9, needs=("human",), destructive=True, mutates=("all",))
def repair(ctx):
    if ctx.hooks.state().get("paired"):
        return PASS("已配对")
    _, final = _pair(ctx)
    if final != "OK":
        return FAIL(f"{final}")
    st = _wait(ctx, lambda s: s.get("connected") and s.get("paired"), 30)
    return PASS() if st else FAIL("配对 OK 但 STATE 不 paired")


@case("P9-08", "RAW FACTORY_RESET(0x36) → 全擦 → 重配", phase=9, needs=("human",), destructive=True, mutates=("all",), expect="record")
def factory_reset_cmd(ctx):
    if not ctx.hooks.state().get("paired"):
        return SKIP("设备未配对，先 P9-07")
    r = ctx.raw("3600", 3000)
    if r == b"\x11":
        # 有登记指纹时 FACTORY_RESET 走门控（WAIT_FP），要真的摸一下才会继续擦；
        # 操作员没在窗口内触摸就别把门悬在那，主动 GATE_CANCEL 收尾。
        m = ctx.bus.mark()
        ctx.op.touch("出厂重置需要门：触摸")
        if ctx.bus.wait("LINK:DISCONNECTED", 40, since_mark=m) is None:
            ctx.hooks.call("TEST:GATE_CANCEL")
            return ctx.expect("rsp=11;reset=no")
    res = r.hex() if r else "NORX"
    st = _wait_after_erase(ctx) or {}
    ok = _ensure_paired(ctx)
    return ctx.expect(f"rsp={res};after_paired={st.get('paired')};fp={st.get('fp_bitmap')};repaired={ok}")


@case("P9-09", "长按按键 3s 出厂重置 → 全擦 → 重配", phase=9, needs=("human",), destructive=True, mutates=("all",))
def factory_reset_button(ctx):
    if not ctx.hooks.state().get("paired"):
        return SKIP("设备未配对")
    m = ctx.bus.mark()
    ctx.op.touch("【长按】设备按键 3 秒以上直到 LED 提示重置")
    if ctx.bus.wait("LINK:DISCONNECTED", 30, since_mark=m) is None:
        return FAIL("30s 没断链，重置没发生？")
    st = _wait_after_erase(ctx)
    if st is None:
        return FAIL("重置后设备没回来（90s + 提示 + 60s 兜底都没等到）")
    if st.get("paired") or st.get("fp_bitmap"):
        return FAIL(f"重置后 paired={st.get('paired')} fp=0x{st.get('fp_bitmap', 0):02x}")
    return PASS("已清空") if _ensure_paired(ctx) else FAIL("清空了但重配失败")


@case("P9-10", "防拆（未配对）：开盖不广播红慢闪，合盖恢复", phase=9, needs=("human", "can_open"), destructive=True, mutates=("all",))
def tamper_unpaired(ctx):
    ctx.op.wait_enter("准备：这条要设备处于【未配对】。若已配对，先跑 P9-02。回车继续", timeout=120)
    if ctx.hooks.state().get("paired"):
        return SKIP("设备已配对")
    ctx.op.wait_enter("开盖，观察：设备应停止广播、红灯 1s/1s 慢闪。确认后回车", timeout=300)
    a = ctx.op.ask("红灯慢闪且蓝牙列表里消失了吗？(y/n)")
    ctx.op.wait_enter("合盖，观察设备恢复广播。回车", timeout=300)
    st = _wait(ctx, lambda s: s.get("connected"), 60)
    return PASS() if (a or "").lower().startswith("y") and st else FAIL(f"开盖表现={a}, 合盖后连上={st is not None}")


@case("P9-11", "防拆（已配对）：开盖 → 全擦红灯停机 → 重启未配对", phase=9, needs=("human", "can_open"), destructive=True, mutates=("all",))
def tamper_paired(ctx):
    if not _ensure_paired(ctx):
        return INVALID("配不上，没法测已配对开盖")
    m = ctx.bus.mark()
    ctx.op.wait_enter("开盖。设备应立刻断链、红灯常亮停机。回车", timeout=300)
    disc = ctx.bus.wait("LINK:DISCONNECTED", 10, since_mark=m)
    ctx.op.wait_enter("合盖，拨 SW2 断电再上电。回车", timeout=300)
    st = _wait_after_erase(ctx)
    if st is None:
        return FAIL(f"重启后没回来 (disc={disc})（90s + 提示 + 60s 兜底都没等到）")
    if st.get("paired") or st.get("fp_bitmap"):
        return FAIL(f"开盖后没擦干净: paired={st.get('paired')} fp={st.get('fp_bitmap')}")
    return PASS(f"断链={disc is not None}，重启后未配对指纹 0")


@case("P9-12", "收尾：重配对 + 提示恢复登记/密钥", phase=9, needs=("human",), destructive=True, mutates=("all",))
def wrap_up(ctx):
    ok = _ensure_paired(ctx)
    ctx.op.wait_enter("设备已重配。指纹和密钥已被前面的重置清空，回车结束（指纹与密钥可稍后在 App 里恢复）", timeout=300)
    return PASS() if ok else FAIL("重配失败")


# P9-01 只是"记录状态"，已被 runner 的体检快照覆盖，不单列。
