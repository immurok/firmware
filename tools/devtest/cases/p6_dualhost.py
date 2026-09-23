"""P6 双机切换。需要第二台电脑在场（env.second_host），否则整段 SKIP。
第二台电脑上的操作由操作员在那台机器的 App 里做，本机只观察。"""
import time
from lib.cases import case, PASS, FAIL, SKIP


def _slots(ctx):
    bm, ac = ctx.hooks.call("TEST:SLOT_STATUS").value.split(":")
    return int(bm), int(ac)


@case("P6-01", "第二主机登记槽 2 → 本机 SLOT_STATUS bitmap=11", phase=6, needs=("human", "second_host"), mutates=("slot", "link"))
def enroll_host2(ctx):
    bm, ac = _slots(ctx)
    if bm == 0b11:
        return PASS("两槽已占，跳过登记")
    m = ctx.bus.mark()
    ctx.op.wait_enter(
        "① 触摸【切换指纹】让设备跳到空槽（本机会断链）；"
        "② 在第二台电脑的 immurok App 里完成配对（触摸+按键）；"
        "③ 再触摸【切换指纹】切回本机；"
        "④ 回车",
        timeout=600,
    )
    if ctx.bus.wait("LINK:CONNECTED", 40, since_mark=m) is None:
        return FAIL("切回本机后 40s 没重连")
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            bm, ac = _slots(ctx)
            if bm == 0b11:
                return PASS(f"bitmap={bm:02b} active={ac}")
        except Exception:
            pass
        time.sleep(2)
    return FAIL(f"bitmap={bm:02b}")


@case("P6-02", "触摸切换指纹 → 本机断链，第二机连上（计时）", phase=6, needs=("human", "second_host"), mutates=("link", "slot"))
def switch_away(ctx):
    m = ctx.bus.mark()
    t0 = time.time()
    ctx.op.touch("触摸【切换指纹】")
    if ctx.bus.wait("LINK:DISCONNECTED", 20, since_mark=m) is None:
        return FAIL("20s 本机没断链")
    dt = time.time() - t0
    ans = ctx.op.ask("第二台电脑连上了吗？连上用了大约几秒？（输入秒数，或 n）", timeout=120)
    if ans is None or ans.strip().lower().startswith("n"):
        return FAIL(f"本机 {dt:.1f}s 断链，第二机未连上")
    return PASS(f"本机 {dt:.1f}s 断链，第二机 ~{ans.strip()}s 连上")


@case("P6-03", "第二机触摸切换指纹 → 本机重连（计时）", phase=6, needs=("human", "second_host"), mutates=("link", "slot"))
def switch_back(ctx):
    m = ctx.bus.mark()
    t0 = time.time()
    ctx.op.touch("再触摸【切换指纹】切回本机")
    if ctx.bus.wait("LINK:CONNECTED", 40, since_mark=m) is None:
        return FAIL("40s 本机没重连")
    return PASS(f"{time.time() - t0:.1f}s 重连")


@case("P6-04", "两槽占满时再 PAIR_INIT（记录：有指纹时预期 30f1）", phase=6, needs=("second_host",), expect="record")
def slot_full(ctx):
    # 这个探针的前提是设备当前至少已登记一根指纹；如果没有任何指纹，PAIR_INIT 不会被
    # SLOT_FULL 拦截，而是正常启动 ECDH 交换，回包就不是这里记录的基线。
    bm, _ = _slots(ctx)
    if bm != 0b11:
        return SKIP("两槽没占满")
    r = ctx.raw("3000")
    return ctx.expect(r.hex() if r else "NORX")


@case("P6-05", "本机 SLOT_CLEAR 另一槽 → bitmap 回单槽", phase=6, needs=("human", "second_host"), mutates=("slot",), destructive=True)
def clear_other(ctx):
    bm, ac = _slots(ctx)
    other = 2 if ac == 1 else 1
    if not (bm >> (other - 1)) & 1:
        return SKIP("另一槽本来就空")
    ctx.op.touch("清另一槽需要门：触摸")
    r = ctx.hooks.call(f"TEST:SLOT_CLEAR:{other}", timeout=45)
    if not r.ok:
        return FAIL(r.final)
    bm2, _ = _slots(ctx)
    ans = ctx.op.ask("不要触摸切换指纹；第二台电脑现在还能连上/验证吗？(y/n)", timeout=120)
    if bm2 != (1 << (ac - 1)):
        return FAIL(f"bitmap={bm2:02b}")
    return PASS(f"bitmap={bm2:02b}，第二机已连不上/验证不了") if (ans or "").lower().startswith("n") \
        else FAIL("另一槽清了第二机仍能连上/验证")

# P6-06（解绑后地址轮换）与 P9-02/P9-07 是同一动作（UNPAIR + 重配），不再单列，P9 覆盖。
