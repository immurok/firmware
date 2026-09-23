"""P7 连接：断链重连、广播两段式→深睡→触摸唤醒、锁屏长稳。"""
import time
from lib.cases import case, PASS, FAIL, SKIP


@case("P7-01", "DISCONNECT → 自动重连 ≤ 15s", phase=7, mutates=("link",))
def reconnect(ctx):
    m = ctx.bus.mark()
    t0 = time.time()
    ctx.hooks.call("TEST:DISCONNECT")
    if ctx.bus.wait("LINK:DISCONNECTED", 10, since_mark=m) is None:
        return FAIL("没断")
    if ctx.bus.wait("LINK:CONNECTED", 15, since_mark=m) is None:
        return FAIL("15s 没重连")
    return PASS(f"{time.time() - t0:.1f}s")


@case("P7-02", "断链后 60s FAST 广播 → 深睡 → 触摸唤醒重连", phase=7, needs=("human",), mutates=("link",), long=True)
def deep_sleep_wake(ctx):
    ctx.op.wait_enter("请在 macOS 蓝牙菜单关闭蓝牙，然后回车（让设备进入无主机广播）", timeout=120)
    ctx.op.wait_enter("等 90 秒让设备过完 60s FAST 广播进深睡（LED 应熄灭），然后回车", timeout=200)
    m = ctx.bus.mark()
    ctx.op.wait_enter("重新打开蓝牙，然后回车", timeout=120)
    if ctx.bus.wait("LINK:CONNECTED", 20, since_mark=m):
        return FAIL("深睡态不触摸就重连了（说明没进深睡，或 60s 没到）")
    t0 = time.time()
    ctx.op.touch("触摸传感器唤醒设备")
    if ctx.bus.wait("LINK:CONNECTED", 30, since_mark=m) is None:
        return FAIL("触摸后 30s 没重连")
    return PASS(f"触摸后 {time.time() - t0:.1f}s 重连")


@case("P7-03", "锁屏 30 分钟不断链", phase=7, needs=("human",), long=True)
def locked_stable(ctx):
    m = ctx.bus.mark()
    ctx.op.wait_enter("锁屏（Ctrl+Cmd+Q），30 分钟后回来解锁并回车", timeout=2400)
    discs = [l for l in ctx.bus.since(m) if l.startswith("LINK:DISCONNECTED")]
    return PASS() if not discs else FAIL(f"期间断链 {len(discs)} 次: {discs[:3]}")
