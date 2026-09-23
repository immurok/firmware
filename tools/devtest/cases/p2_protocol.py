"""P2 协议边界：畸形包、错参、状态机外命令。无人值守，全部先 --record 定基线。

表驱动：每条 = (id, 标题, [帧 hex, ...], [收尾帧 hex, ...])。收尾帧列表可省略。
actual = 表里各帧应答 hex 以逗号连接；收尾帧发送后不并入 actual，只用来把设备复位回
干净状态（例如某条命令会按下指纹门/进入登记态，不清掉会污染后面用例的结果）。
应答码参考 firmware/Profile/include/immurokservice.h：
  00 OK / 11 WAIT_FP / fd BUSY / fe INVALID_PARAM / ff UNKNOWN_CMD / f0 QC_REFUSED
"""
import random
from lib.cases import case, PASS, FAIL, hexs
from lib.hooks import HooksError


def _table(ctx, frames, timeout_ms=1500):
    return ",".join(hexs(ctx.raw(f, timeout_ms)) for f in frames)


TABLE = [
    ("P2-01", "未知 cmd 0x05/0x7F/0xA0/0xFF", ["0500", "7f00", "a000", "ff00"]),
    ("P2-02", "len 大于实际字节（GET_STATUS 声称 4 字节只给 0）", ["0104"]),
    ("P2-03", "len 小于实际字节（DELETE_FP 声称 0 字节带 1 字节）", ["120004"]),
    ("P2-04", "len=0 的需参命令 ENROLL/DELETE/KEY_READ", ["1000", "1200", "6100"]),
    ("P2-05", "64 字节整帧（GET_STATUS + 62 字节垃圾）", ["013e" + "aa" * 62]),
    ("P2-06", "65 字节超长写", ["013f" + "aa" * 63]),
    ("P2-07", "空写（0 字节）", [""]),
    ("P2-08", "单字节帧（只有 cmd）", ["01", "13", "39"]),
    ("P2-09", "错参：DELETE 槽 28/255、KEY_READ cat 9、SLOT_CLEAR 槽 7、ENROLL 已占槽",
     ["12011c", "1201ff", "6103090000", "3c0107"],   # ENROLL 已占槽在函数里补
     ["1100", "3700"]),   # ENROLL_CANCEL 只清登记标志，GATE_CANCEL 清掉可能挂起的门
    ("P2-10", "已配对态发 QC 0x40–0x44", ["4000", "4100", "4200", "4300", "4400"]),
    ("P2-11", "已配对态发 PAIR_INIT/PAIR_CONFIRM/SLOT_PIN_ISSUE/SLOT_PAIR",
     ["3000", "3100", "3a00", "3b00"]),
    ("P2-12", "无登记时 ENROLL_CANCEL", ["1100"]),
    ("P2-13", "无门时 GATE_CANCEL", ["3700"]),
    ("P2-14", "无 WRITE 直接 KEY_COMMIT（otp idx 200）", ["640201c8"], ["3700"]),
    # 固件在查 cat/idx 前先检查 fp_gate_needed，会回 0x11 并按下 25s 指纹门；
    # 不清掉的话之后超时通知（0x06）会串进 P2-16/17/19 的结果里。
    ("P2-15", "KEY_WRITE 偏移越界（api idx 49 off 250）+ len 大于实际", ["62040231fa" + "aa", "620302ff"]),
    ("P2-17", "乱发 FP_MATCH_ACK（无待确认匹配）", ["2200", "22020000"]),
    ("P2-19", "CHALLENGE 带错长 nonce（4 字节 / 0 字节）", ["380400000000", "3800"]),
]


def _make(cid, title, frames, cleanup=None):
    cleanup = cleanup or []

    @case(cid, title, phase=2, expect="record")
    def fn(ctx):
        f = list(frames)
        if cid == "P2-09":
            # 追加「已占槽 ENROLL_START」：取当前 fp_bitmap 里第一个占用的认证槽
            bm = ctx.hooks.state()["fp_bitmap"]
            used = next((i for i in range(5) if (bm >> i) & 1), None)
            if used is not None:
                f.append(f"1001{used:02x}")
        try:
            res = _table(ctx, f)
        finally:
            # 表本身若中途抛 HooksError（钩子异常），清理帧也必须照发——不然某条命令
            # 按下的指纹门/登记态会悬在那，污染后面用例的结果。每条清理帧各自兜底，
            # 一条失败不能连累其它清理帧不发。
            for c in cleanup:
                try:
                    ctx.raw(c)
                except HooksError as e:
                    ctx.log(f"cleanup {c} 失败: {e}")
        return ctx.expect(res)
    fn.__name__ = cid.replace("-", "_")
    return fn


for _row in TABLE:
    _make(*_row)


@case("P2-16", "未 COMMIT 就 KEY_READ：写 otp idx 100 不提交再读", phase=2, expect="record", mutates=("keys",))
def uncommitted_read(ctx):
    entry = (b"devtest-uncommit".ljust(30, b"\0") + b"svc".ljust(30, b"\0") + b"\x01" * 32).hex()
    w = ctx.hooks.call(f"TEST:KEY_WRITE_NOCOMMIT:otp:100:{entry}", timeout=30)
    rd = ctx.hooks.call("TEST:KEY_READ:otp:100", timeout=20)
    # 没 COMMIT 的 KEY_WRITE 只是暂存在 RAM，idx 100 在 flash 上本来就不存在，
    # 不需要（也不该）为了「清残留」再等一次 40s 的 KEY_DELETE 门；
    # 只用 GATE_CANCEL 清掉 write/read 过程中可能挂起的指纹门。
    ctx.raw("3700")
    return ctx.expect(f"write={w.final};read={rd.final[:40]}")


@case("P2-18", "重放上次真实 0x21 的 ACK", phase=2, expect="record", needs=("human",))
def replay_ack(ctx):
    ctx.op.touch("请触摸指纹传感器一次（产生一条真实匹配通知）")
    m = ctx.bus.mark()
    line = ctx.bus.wait("RX:21", 30, since_mark=m)
    if line is None:
        return FAIL("30s 没等到 0x21")
    frame = line[3:]
    ctx.log(f"真实匹配帧 {frame}")
    # App 已经 ACK 过一次；再原样发 ACK 两次，看固件回什么
    return ctx.expect(_table(ctx, ["2200", "2200"]))


@case("P2-20", "100 条随机字节帧（固定种子）后设备仍正常", phase=2)
def fuzz(ctx):
    rnd = random.Random(20260920)
    norx = 0
    for i in range(100):
        n = rnd.randint(1, 64)
        frame = bytes(rnd.randint(0, 255) for _ in range(n))
        # 避开会真正改状态/挂起指纹门的 opcode：登记/删除/配对/槽清/AUTH/密钥读写删/
        # 签名/OTP/出厂重置/QC/OTA。改种子要重新核对避让列表。
        if frame[0] in (0x10, 0x12, 0x30, 0x31, 0x33, 0x36, 0x3a, 0x3b, 0x3c,
                        0x40, 0x41, 0x42, 0x43, 0x44,
                        0x62, 0x63, 0x64, 0x65, 0x67, 0x69):
            frame = bytes([0x05]) + frame[1:]
        r = ctx.hooks.raw(frame.hex(), 2500)   # GET_BATT_RAW 强制新测 ~500ms + BLE 延迟，800ms 会误判 NORX 并让应答错位
        if r is None:
            norx += 1
    st = ctx.hooks.state()
    if not st.get("connected"):
        return FAIL("乱包后断链")
    r = ctx.cmd("01")
    if r is None or r[0] != 0x00:
        return FAIL("乱包后 GET_STATUS 异常")
    return PASS(f"100 帧，{norx} 帧无应答，GET_STATUS 正常")


@case("P2-21", "命令风暴：GET_STATUS 连发 50 条不等应答", phase=2)
def storm(ctx):
    m = ctx.bus.mark()
    for _ in range(50):
        ctx.hooks.call("TEST:RAW:0100:0", timeout=5)
    import time
    time.sleep(3)
    replies = [l for l in ctx.bus.since(m) if l.startswith("RX:00")]
    r = ctx.cmd("01")
    if r is None or r[0] != 0x00:
        return FAIL(f"风暴后 GET_STATUS 异常，风暴期收到 {len(replies)} 条应答")
    return PASS(f"风暴期收到 {len(replies)}/50 条应答，之后 GET_STATUS 正常")
