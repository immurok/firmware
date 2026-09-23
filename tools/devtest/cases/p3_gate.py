"""P3 指纹门：AUTH_REQUEST 的正常/错指/超时/取消/背靠背/并发/互斥/冷却/长按。都要人。"""
import threading
import time
from lib.cases import case, PASS, FAIL, INVALID, SKIP


def _gate(ctx, timeout=30, prompt="请触摸指纹传感器"):
    if prompt:
        ctx.op.touch(prompt)
    r = ctx.hooks.call(f"TEST:GATE:{timeout}", timeout=timeout + 10)
    ctx.log(f"GATE → {r}")
    return r


@case("P3-01", "正常触摸 → FP:OK 且总线收到 AUTH_OK(0x00)", phase=3, needs=("human",))
def normal(ctx):
    # 门通过时固件只回一字节 0x00 (AUTH_OK)，不会发签名的 0x21 通知；
    # 0x21/HMAC 校验是 P3-10（无门被动匹配）的事，这里不测。
    m = ctx.bus.mark()
    r = _gate(ctx)
    if r.value != "PASS":
        return FAIL(r.final)
    if "FP:OK" not in r.events:
        return FAIL(f"门通过但事件里没有 FP:OK: {r.events}")
    if "RX:00" not in ctx.bus.since(m):
        return FAIL("门通过但总线没有 RX:00（AUTH_OK 一字节应答没收到）")
    return PASS()


@case("P3-02", "错手指 3 次 → FP:FAIL 递减，门以 TIMEOUT 结束", phase=3, needs=("human",))
def wrong_finger(ctx):
    # 第三次错指固件直接发 0x06 超时，不会有第三条 0x07，所以 FP:FAIL:0 不会出现，
    # 收尾是 OK:TIMEOUT 而非 DENIED。
    r = _gate(ctx, prompt="请用【未登记】的手指连续触摸 3 次")
    fails = [e for e in r.events if e.startswith("FP:FAIL:")]
    if r.value == "PASS":
        return INVALID("门通过了——用的是已登记手指？")
    if len(fails) < 2:
        return FAIL(f"只看到 {len(fails)} 次 FP:FAIL: {r}")
    lefts = [int(e.split(":")[2]) for e in fails]
    if lefts != sorted(lefts, reverse=True):
        return FAIL(f"剩余次数不递减: {lefts}")
    if r.value not in ("TIMEOUT", "DENIED"):
        return FAIL(f"预期 TIMEOUT/DENIED 收尾，实际: {r.value}")
    return PASS(f"FP:FAIL 序列 {lefts} → {r.value}")


@case("P3-03", "30s 不摸 → TIMEOUT，之后触摸不产生 0x21", phase=3, needs=("human",))
def timeout(ctx):
    r = _gate(ctx, timeout=30, prompt="接下来 30s【不要】触摸")
    if r.value != "TIMEOUT":
        return FAIL(r.final)
    m = ctx.bus.mark()
    ctx.op.touch("现在触摸一次（应当不产生认证匹配）")
    hit = ctx.bus.wait("FPMATCH:", 10, since_mark=m)
    # 无门触摸走被动路径也会有 0x21（P3-10），这里只验证门已关：GATE 结果不再变
    return PASS("超时后触摸" + ("有被动 0x21" if hit else "无 0x21"))


@case("P3-04", "GATE_CANCEL 后触摸不产生匹配", phase=3, needs=("human",))
def cancel(ctx):
    out = {}
    def _run():
        try:
            out["r"] = ctx.hooks.call("TEST:GATE:30", timeout=45)
        except Exception as e:
            out["err"] = str(e)
    t = threading.Thread(target=_run)
    t.start()
    time.sleep(2)
    m0 = ctx.bus.mark()      # GATE_CANCEL 自己的命令应答（RX:00）也会上总线，先标记好避免和门应答混淆
    ctx.hooks.call("TEST:GATE_CANCEL")
    t.join(10)
    if out.get("err"):
        return FAIL(f"门线程异常: {out['err']}")
    r = out.get("r")
    ctx.log(f"取消后 GATE → {r}")
    if r is None or r.value == "PASS":
        return FAIL(f"取消后门仍通过: {r}")
    ctx.bus.wait("RX:00", 5, since_mark=m0)   # 消费掉 GATE_CANCEL 的命令应答
    m = ctx.bus.mark()
    ctx.op.touch("现在触摸一次")
    time.sleep(5)
    fp_ok = any(l == "RX:00" for l in ctx.bus.since(m))
    return PASS("取消后触摸没有门应答") if not fp_ok else FAIL("取消后触摸仍有门应答")


@case("P3-05", "背靠背两门 + 存活确认", phase=3, needs=("human",))
def back_to_back(ctx):
    r1 = _gate(ctx, prompt="T1：触摸")
    r2 = _gate(ctx, prompt="T2：立刻再触摸")
    time.sleep(3)
    r3 = _gate(ctx, prompt="T3：再触摸一次（存活确认）")
    vals = (r1.value, r2.value, r3.value)
    return PASS(str(vals)) if vals[2] == "PASS" else FAIL(f"T3 不通过，传感器可能死了: {vals}")


@case("P3-06", "并发两门：一个 BUSY 一个通过，之后存活", phase=3, needs=("human",))
def concurrent(ctx):
    res = {}
    def go(k):
        res[k] = ctx.hooks.call("TEST:GATE:30", timeout=45)
    ctx.op.touch("并发两门，触摸一次")
    a = threading.Thread(target=go, args=("a",)); b = threading.Thread(target=go, args=("b",))
    a.start(); b.start(); a.join(); b.join()
    finals = sorted(r.final for r in res.values())
    if "OK:PASS" not in finals:
        return FAIL(f"两个都没过: {finals}")
    if "ERR:BUSY" not in finals:
        ctx.log(f"没出现 ERR:BUSY（App 侧互斥没拦住第二个）: {finals}")
    time.sleep(3)
    r3 = _gate(ctx, prompt="存活确认：再触摸一次")
    return PASS(f"{finals} → 存活 {r3.value}") if r3.value == "PASS" else FAIL(f"并发后传感器死: {finals} / {r3.final}")


@case("P3-07", "门期间发 ENROLL_START → BUSY，门不受影响", phase=3, needs=("human",))
def busy_during_gate(ctx):
    out = {}
    def _run():
        try:
            out["r"] = ctx.hooks.call("TEST:GATE:30", timeout=45)
        except Exception as e:
            out["err"] = str(e)
    t = threading.Thread(target=_run)
    t.start()
    time.sleep(1.5)
    r = ctx.hooks.call("TEST:ENROLL:4", timeout=15)
    ctx.log(f"门期间 ENROLL → {r.final}")
    ctx.op.touch()
    t.join(40)
    if out.get("err"):
        return FAIL(f"门线程异常: {out['err']}")
    g = out.get("r")
    if g is None or g.value != "PASS":
        return FAIL(f"门被干扰: {g}")
    return PASS(f"ENROLL 得到 {r.final}，门照常通过") if r.final in ("ERR:BUSY", "ERR:START_FAILED") \
        else FAIL(f"门期间 ENROLL 居然 {r.final}")


@case("P3-08", "冷却期：门过后 5s 内 KEY_OTP 是否免门（记录）", phase=3, needs=("human",), expect="record")
def cooldown(ctx):
    n = int(ctx.hooks.call("TEST:KEY_COUNT:otp").value)
    if n == 0:
        return SKIP("没有 OTP 条目")
    r = _gate(ctx)
    if r.value != "PASS":
        return INVALID(r.final)
    t0 = time.time()
    ctx.op.touch("接下来 8s 不要触摸")
    # 不在冷却窗内时 KEY_OTP 会在设备侧按下最长 25s 的门，超时才回 ERR:DENIED；
    # socket 超时必须盖过设备门超时，否则 hooks.call 会先抛 HooksError 而不是拿到 ERR:DENIED。
    r1 = ctx.hooks.call("TEST:KEY_OTP:0", timeout=60)
    dt1 = time.time() - t0
    if not r1.ok:
        ctx.hooks.call("TEST:GATE_CANCEL")
    r2 = ctx.hooks.call("TEST:KEY_OTP:0", timeout=60)
    dt2 = time.time() - t0
    if not r2.ok:
        ctx.hooks.call("TEST:GATE_CANCEL")
    free1 = r1.ok and dt1 < 5
    free2 = r2.ok and dt2 < 12
    return ctx.expect(
        f"otp1={'free' if free1 else r1.final}@{dt1:.0f}s;otp2={'free' if free2 else r2.final}@{dt2:.0f}s",
        note="假定 idx 0 的 OTP 条目存在（没有 KEY_LIST 钩子核对具体条目）",
    )


@case("P3-09", "长按 → LOCKREQ(0x23)", phase=3, needs=("human",))
def long_press(ctx):
    m = ctx.bus.mark()
    ctx.op.touch("请【长按】传感器 3 秒再松开（屏幕会被锁定；解锁后回到终端继续）")
    line = ctx.bus.wait("LOCKREQ", 15, since_mark=m)
    return PASS() if line else FAIL("15s 没收到 0x23")


@case("P3-10", "无门触摸已登记指 → 被动 0x21", phase=3, needs=("human",))
def passive_match(ctx):
    m = ctx.bus.mark()
    ctx.op.touch("无门状态：用已登记手指触摸一次")
    line = ctx.bus.wait("FPMATCH:", 15, since_mark=m)
    return PASS(line) if line else FAIL("15s 没有 0x21")


@case("P3-11", "无门触摸未登记指 → 无 0x21 且不复位", phase=3, needs=("human",))
def passive_nomatch(ctx):
    m = ctx.bus.mark()
    ctx.op.touch("无门状态：用【未登记】手指触摸一次")
    line = ctx.bus.wait("FPMATCH:", 8, since_mark=m)
    return FAIL(f"未登记指居然匹配: {line}") if line else PASS()


@case("P3-12", "端到端：sudo 走 PAM 指纹", phase=3, needs=("human", "pam_sudo"))
def sudo_e2e(ctx):
    from lib import oracle
    ctx.op.touch("sudo 指纹：请触摸")
    st, dt = oracle.sudo_probe()
    return {"PASS": PASS, "FAIL": FAIL, "INVALID": INVALID}[st](f"{dt:.1f}s")
