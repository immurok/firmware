"""P4 登记：完整登记、取消、断链、超时、重复、越界、删后不匹配、切换指纹。"""
import threading
import time
from lib.cases import case, PASS, FAIL, INVALID, SKIP
from lib.hooks import HooksError

AUTH_SLOTS = range(5)
SWITCH_SLOT = 5


def _free_slot(ctx):
    bm = ctx.hooks.state()["fp_bitmap"]
    return next((i for i in AUTH_SLOTS if not (bm >> i) & 1), None)


def _enroll(ctx, slot, prompt, timeout=150):
    # timeout 是底层 socket 每次 recv 的超时，不是登记总时长——钩子会持续推 STEP:waiting
    # 之类的保活行，只要还在收行就不会触发这个超时，登记本身可以比 timeout 更久。
    ctx.op.touch(prompt)
    steps = []
    final = None
    for line in ctx.hooks.stream(f"TEST:ENROLL:{slot}", timeout=timeout):
        if line.startswith("STEP:"):
            steps.append(line)
            print(f"      {line}")
        elif line.startswith(("OK", "ERR")):
            final = line
    ctx.log(f"ENROLL slot {slot}: {len(steps)} 步 → {final}")
    return steps, final


@case("P4-01", "完整登记新槽", phase=4, needs=("human",), mutates=("fp",))
def full_enroll(ctx):
    slot = _free_slot(ctx)
    if slot is None:
        return SKIP("认证槽已满")
    before = ctx.hooks.state()["fp_bitmap"]
    steps, final = _enroll(ctx, slot, f"先用已登记的手指触摸过门，再登记到槽 {slot}：用要登记的手指按提示反复按压/抬起，直到完成")
    if final != "OK:COMPLETE":
        return FAIL(f"{final}")
    after = ctx.hooks.state()["fp_bitmap"]
    if not (after >> slot) & 1 or after != before | (1 << slot):
        return FAIL(f"FP_LIST 不对: {before:02x} → {after:02x}")
    ctx.env["enrolled_slot"] = slot
    return PASS(f"槽 {slot}，{len(steps)} 步事件")


@case("P4-02", "登记中途 ENROLL_CANCEL → FP_LIST 不变", phase=4, needs=("human",))
def cancel_mid(ctx):
    slot = _free_slot(ctx)
    if slot is None:
        return SKIP("认证槽已满")
    before = ctx.hooks.state()["fp_bitmap"]
    out = {}
    def _run():
        try:
            out["r"] = _enroll(ctx, slot, "先用已登记的手指触摸过门，再用要登记的手指按压 2 次，然后等待")
        except Exception as e:
            out["err"] = str(e)
    t = threading.Thread(target=_run)
    t.start()
    time.sleep(12)
    ctx.hooks.call("TEST:ENROLL_CANCEL")
    t.join(30)
    if out.get("err"):
        return FAIL(f"登记线程异常: {out['err']}")
    _, final = out.get("r", ([], None))
    after = ctx.hooks.state()["fp_bitmap"]
    if after != before:
        return FAIL(f"取消后 FP_LIST 变了: {before:02x} → {after:02x}")
    return PASS(f"final={final}")


@case("P4-03", "登记中途断链 → 重连后无半成品", phase=4, needs=("human",), mutates=("link",))
def disconnect_mid(ctx):
    slot = _free_slot(ctx)
    if slot is None:
        return SKIP("认证槽已满")
    before = ctx.hooks.state()["fp_bitmap"]
    out = {}
    def _run():
        try:
            out["r"] = _enroll(ctx, slot, "先用已登记的手指触摸过门，再用要登记的手指按压 2 次，然后等待")
        except Exception as e:
            out["err"] = str(e)
    t = threading.Thread(target=_run)
    t.start()
    time.sleep(12)
    ctx.hooks.call("TEST:DISCONNECT")
    t.join(30)
    try:
        deadline = time.time() + 20
        while time.time() < deadline and not ctx.hooks.state().get("connected"):
            time.sleep(1)
        connected = ctx.hooks.state().get("connected")
    finally:
        # App 的 handleEnroll 在断链期间收不到设备收尾事件，.auth 锁最长会占用 120s；
        # 不管重连有没有成功都要主动 ENROLL_CANCEL 释放锁，否则会撞 P4-05/P4-07 的
        # BUSY——重连失败提前 return 也不能漏掉这一步。
        try:
            ctx.hooks.call("TEST:ENROLL_CANCEL")
        except HooksError as e:
            ctx.log(f"ENROLL_CANCEL 清理失败: {e}")
        t.join(5)
    if not connected:
        return FAIL("20s 没重连")
    st = ctx.hooks.state()   # 释放锁之后重新取一次快照，避免用释放前的旧 fp_bitmap 比对
    if out.get("err"):
        return FAIL(f"登记线程异常: {out['err']}")
    if st["fp_bitmap"] != before:
        return FAIL(f"断链后 FP_LIST 变了: {before:02x} → {st['fp_bitmap']:02x}")
    return PASS()


@case("P4-04", "登记中 30s 不按 → FAILED/TIMEOUT，FP_LIST 不变", phase=4, needs=("human",), long=True)
def enroll_timeout(ctx):
    slot = _free_slot(ctx)
    if slot is None:
        return SKIP("认证槽已满")
    before = ctx.hooks.state()["fp_bitmap"]
    _, final = _enroll(ctx, slot, "先用已登记的手指触摸过门，再开始登记但【不要】按压，等它自己超时", timeout=200)
    after = ctx.hooks.state()["fp_bitmap"]
    if after != before:
        return FAIL(f"FP_LIST 变了: {before:02x} → {after:02x}")
    return PASS(f"final={final}")


@case("P4-05", "同一手指重复登记到另一槽（记录固件是否拒）", phase=4, needs=("human",), expect="record", mutates=("fp",))
def duplicate(ctx):
    if "enrolled_slot" not in ctx.env:
        return SKIP("P4-01 没登记成功")
    slot = _free_slot(ctx)
    if slot is None:
        return SKIP("认证槽已满")
    _, final = _enroll(ctx, slot, f"先用已登记的手指触摸过门，再用 P4-01 同一根手指登记到槽 {slot}")
    if final is None:
        return INVALID("登记流没有收尾行")
    if final == "OK:COMPLETE":
        ctx.op.touch("删除重复登记：触摸")
        ctx.hooks.call(f"TEST:FP_DELETE:{slot}", timeout=45)   # 收尾，会要求触摸
    return ctx.expect(final)


@case("P4-06", "越界槽 ENROLL_START：6/28/255 → 拒", phase=4, expect="record")
def out_of_range(ctx):
    res = []
    for s in (6, 28, 255):
        r = ctx.raw(f"1001{s:02x}")
        res.append(r.hex() if r else "NORX")
        if r and r[0] in (0x00, 0x11):
            ctx.raw("1100")      # 万一开始了，取消
    return ctx.expect(",".join(res))


@case("P4-07", "删除 P4-01 的槽 → 该指不再通过", phase=4, needs=("human",), mutates=("fp",))
def delete_then_nomatch(ctx):
    slot = ctx.env.get("enrolled_slot")
    if slot is None:
        return SKIP("P4-01 没登记成功")
    ctx.op.touch("删除指纹需要门：触摸（任意已登记指）")
    r = ctx.hooks.call(f"TEST:FP_DELETE:{slot}", timeout=45)
    if not r.ok:
        return FAIL(f"删除失败: {r.final}")
    if (ctx.hooks.state()["fp_bitmap"] >> slot) & 1:
        return FAIL("删除后 FP_LIST 仍有该槽")
    ctx.op.touch("用刚删掉的那根手指触摸（应当不通过）")
    # 设备侧门 25s 才关；App 20s 就撤的话不会发 GATE_CANCEL，会留 ~5s 敞口，
    # 所以这里用 30s 让设备自己按超时关（OK:TIMEOUT），不通过再补一次 GATE_CANCEL 保险。
    g = ctx.hooks.call("TEST:GATE:30", timeout=40)
    if g.value != "PASS":
        ctx.hooks.call("TEST:GATE_CANCEL")
        return PASS(g.value)
    return FAIL("删掉的手指仍能通过")


@case("P4-08", "登记切换指纹（槽 5），触摸它不产生认证 0x21", phase=4, needs=("human",), mutates=("fp",))
def switch_fp(ctx):
    st = ctx.hooks.state()
    bm = st["fp_bitmap"]
    if (bm >> SWITCH_SLOT) & 1:
        ctx.log("槽 5 已有切换指纹，跳过登记只测触摸")
    else:
        _, final = _enroll(ctx, SWITCH_SLOT, "登记切换指纹到槽 5：用一根【不同】的手指")
        if final != "OK:COMPLETE":
            return FAIL(final)
    slot_bitmap = ctx.hooks.state().get("slot_bitmap", 0)
    if bin(slot_bitmap).count("1") >= 2:
        return SKIP("已绑双机，触摸切换指纹会切主机")
    m = ctx.bus.mark()
    ctx.op.touch("无门状态触摸切换指纹（单主机时应无认证匹配）")
    line = ctx.bus.wait("FPMATCH:", 8, since_mark=m)
    return FAIL(f"切换指纹产生认证匹配: {line}") if line else PASS()
