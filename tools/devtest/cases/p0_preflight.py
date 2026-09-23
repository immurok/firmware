"""P0 前置：每次必跑，收集现场条件进 ctx.env。"""
import os
from lib.cases import case, PASS, FAIL
from lib.imfw import load_private_pem


@case("P0-01", "immurok.app 在跑且是 TEST_HOOKS 构建", phase=0)
def app_running(ctx):
    v = ctx.hooks.ping()
    return PASS(v) if "TEST_HOOKS" in v else FAIL(f"PING → {v}")


@case("P0-02", "设备已连接已配对", phase=0)
def device_paired(ctx):
    st = ctx.hooks.state()
    if not st.get("connected"):
        return FAIL("设备未连接")
    if not st.get("paired"):
        return FAIL("设备未配对")
    ctx.env["fw"] = st.get("fw")
    ctx.env["slot_active"] = st.get("slot_active")
    if st.get("fp_bitmap", 0) & 0x1F == 0:
        ctx.log("设备没有认证指纹，KEY_* / PAIR_INIT 等命令行为会不同")
    return PASS(f"fw={st.get('fw')} slot={st.get('slot_active')} fp=0x{st.get('fp_bitmap', 0):02x}")


@case("P0-03", "USB 设备日志口", phase=0)
def usb_log(ctx):
    if ctx.env.get("usb_log"):
        return PASS(f"抓取中: {ctx.uart.port}")
    return PASS("没有 /dev/cu.usbmodem*，体检不查复位（release 固件本来没日志；要查复位刷 release-debug + 接 USB）")


@case("P0-04", "电池电压", phase=0)
def battery(ctx):
    st = ctx.hooks.state()
    mv = st.get("batt_mv")
    if mv is None:
        return PASS("读不到 batt_mv，跳过")
    if mv < 3500:
        ctx.log(f"电池 {mv}mV 偏低，长用例可能半路断电")
    return PASS(f"{mv}mV {st.get('batt_pct')}%")


@case("P0-05", "现场条件", phase=0, needs=())
def site(ctx):
    # 现场条件用 ask 不用 confirm：--yes 只该放行破坏性确认，不该替操作员回答「有没有第二台电脑」
    def yes(text):
        ans = ctx.op.ask(text + " [y/N]", timeout=120)
        return bool(ans) and ans.strip().lower() in ("y", "yes")
    ctx.env["second_host"] = yes("现场有第二台已装 immurok 的电脑吗？（测双机切换）")
    ctx.env["sw2"] = yes("能拨设备电源开关 SW2 断电吗？（测 OTA 中途断电）")
    ctx.env["can_open"] = yes("能开盖触发防拆簧片吗？（P9 防拆用例）")
    ctx.env["imfw"] = bool(getattr(ctx.args, "imfw", None) and os.path.exists(ctx.args.imfw))
    ctx.env["ota_keys"] = load_private_pem() is not None
    return PASS(str({k: ctx.env[k] for k in ("second_host", "sw2", "can_open", "imfw", "ota_keys")}))


@case("P0-06", "sudo_local 挂了 pam_immurok.so", phase=0)
def pam(ctx):
    ok = False
    try:
        ok = "pam_immurok.so" in open("/etc/pam.d/sudo_local").read()
    except OSError:
        pass
    ctx.env["pam_sudo"] = ok
    return PASS("端到端 sudo 用例可跑") if ok else PASS("未挂 PAM，端到端 sudo 用例 SKIP")
