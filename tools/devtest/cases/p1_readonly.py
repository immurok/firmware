"""P1 只读：状态类命令的格式与合理性。"""
from lib.cases import case, PASS, FAIL
from lib import oracle


@case("P1-01", "GET_STATUS 格式、版本与 STATE 一致", phase=1)
def get_status(ctx):
    r = ctx.cmd("01")
    if r is None or r[0] != 0x00 or len(r) < 9:
        return FAIL(f"应答异常: {r.hex() if r else None}")
    ver = f"{r[4]}.{r[5]}.{r[6]}.{((r[7] << 8) | r[8]):x}"
    st = ctx.hooks.state()
    if ver != st["fw"]:
        return FAIL(f"GET_STATUS 版本 {ver} ≠ STATE {st['fw']}")
    if bool(r[2]) != st["paired"]:
        return FAIL("paired 位不一致")
    return PASS(ver)


@case("P1-02", "GET_BATT_RAW 合理", phase=1)
def batt(ctx):
    r = ctx.cmd("0201", timeout_ms=8000)   # payload 0x01 = 用缓存值
    if r is None or r[0] != 0x00 or len(r) < 6:
        return FAIL(f"应答异常: {r.hex() if r else None}")
    mv = r[1] | (r[2] << 8)
    pct = r[3]
    if not 3000 <= mv <= 4400:
        return FAIL(f"mv={mv} 超出 3.0–4.4V")
    if not 0 <= pct <= 100:
        return FAIL(f"pct={pct}")
    return PASS(f"{mv}mV {pct}%")


@case("P1-03", "连接参数满足 Apple 公式", phase=1)
def conn_params(ctx):
    r = ctx.cmd("03")
    if r is None or len(r) < 8 or r[0] != 0x03 or r[1] != 0x00:
        return FAIL(f"应答异常: {r.hex() if r else None}")
    interval = (r[2] << 8) | r[3]
    latency = (r[4] << 8) | r[5]
    timeout = (r[6] << 8) | r[7]
    ok = oracle.apple_params_ok(interval, latency, timeout)
    note = f"interval={interval * 1.25:.1f}ms latency={latency} timeout={timeout * 10}ms"
    return PASS(note) if ok else FAIL("不满足 timeout > interval×(latency+1)×3: " + note)


@case("P1-04", "SLOT_STATUS 活动槽在 bitmap 内", phase=1)
def slot(ctx):
    r = ctx.cmd("39")
    if r is None or len(r) < 4 or r[1] != 0x00:
        return FAIL(f"应答异常: {r.hex() if r else None}")
    bitmap, active = r[2], r[3]
    if active not in (1, 2) or not (bitmap >> (active - 1)) & 1:
        return FAIL(f"bitmap={bitmap:02b} active={active}")
    return PASS(f"bitmap={bitmap:02b} active={active}")


@case("P1-05", "FP_LIST 与 STATE 一致", phase=1)
def fp_list(ctx):
    r = ctx.cmd("13")
    if r is None or len(r) < 2 or r[0] != 0x00:
        return FAIL(f"应答异常: {r.hex() if r else None}")
    st = ctx.hooks.state()
    if r[1] != st["fp_bitmap"]:
        return FAIL(f"FP_LIST 0x{r[1]:02x} ≠ STATE 0x{st['fp_bitmap']:02x}")
    return PASS(f"0x{r[1]:02x}")


@case("P1-06", "三类 KEY_COUNT 可读", phase=1)
def key_count(ctx):
    out = {}
    for cat, code in (("ssh", 0), ("otp", 1), ("api", 2)):
        r = ctx.cmd(f"60{code:02x}")
        if r is None or r[0] != 0x00 or len(r) < 2:
            return FAIL(f"{cat}: {r.hex() if r else None}")
        out[cat] = r[1]
    return PASS(str(out))
