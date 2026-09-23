"""P8 OTA：正常/坏签名/低 SVN/中途断链/中途断电/IAP 边界。需要 --imfw 指向当前版本合法包。

fix round 1（对照 controller 裁决，见 task-16-17-report.md）：
- `_push` 返回 (终止行, 最后一条 PROGRESS)，方便调用方在失败时报告推到了多远。
- `--imfw` 是用户传入的路径，每条用例开头用一次 `os.path.abspath` 定下来，避免相对路径
  在线程/子调用里因为 cwd 语义不明确而对不上。
- P8-02/P8-03（坏签名/低 SVN 被拒）：对照 hidkbd.c 确认签名校验和 SVN 反降级都是 END
  之后的 deferred verify 判定，不是 HEADER——P8-02 标题/docstring 改为反映"整段推完
  才知道结果"，不再说"header 拒"。`_reboot_fw_suffix` 不论 final 是什么都跑一遍：判断
  有没有重启、核实/等回版本号，统一拼出 `;rebooted=yes|no;fw=<ver>` 记进基线；
  `final != OK` 但版本确实变了才判 FAIL，`final is None` 用 `!s` 转换成 "None" 兜底，
  不会因为 `None + str` 直接崩成用例异常。
- P8-04/P8-07：推送线程包 try/except 存 `out["err"]`；P8-04/P8-07 只在没进入
  abort/dropped 分支时才把异常算 FAIL——OTA_ABORT 会让底层连接被动收尾，那属于预期的
  中断路径本身。P8-07 标题改为"PROM 第一块后断链"（第一条 PROGRESS 出现时 HEADER 早
  已通过、PROM 已经在发，不是"HEADER 后不发数据"）。
- P8-05：断电本身就会打断 `ctx.hooks.stream()`，线程异常同样存下来但只记日志不算 FAIL；
  拨回 SW2 后需要操作员显式回车确认，再进 `_wait_link`。
- P8-06：加 `mutates=("link", "fw")`（裸发 END 万一真落盘会让设备重启）；只有 END 的
  回包进 record 基线，INFO/ERASE/HEADER 三条只进日志——ERASE 走固定 5s 钩子超时，真机
  擦 54 块偶发压线超时，混进基线会让 record 不稳定。
- `_tmp` 写临时包前补 `os.makedirs(ctx.args.reports, exist_ok=True)`，避免 `--no-uart`
  等场景下 reports/ 目录还没被创建过就直接写文件失败。

fix round 2（全量复审）：
- record 基线不能带具体固件版本号/SVN——换固件版本后基线不该跟着变。
  `_reboot_fw_suffix` 改拼 `;rebooted=yes|no;fw_unchanged=<bool>`（跟 fw0 比对的结果，
  不是绝对版本号），P8-06 的 `;fw={fw}` 同理改成 `;fw_unchanged=<bool>`；P8-03 的
  `svn{svn}->{svn-1}:` 改成不带数字的 `svn_down:`。具体版本号/SVN 数字都改记
  `ctx.log`，排查时看日志，不看基线。
"""
import os
import threading
import time
from lib.cases import case, PASS, FAIL, INVALID, SKIP
from lib import imfw


def _tmp(ctx, name, data):
    os.makedirs(ctx.args.reports, exist_ok=True)
    p = os.path.join(ctx.args.reports, name)
    with open(p, "wb") as f:
        f.write(data)
    return p


def _wait_link(ctx, seconds=60):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            if ctx.hooks.state().get("connected"):
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def _still_connected(ctx, seconds=5):
    """几秒内一直读到 connected=true，认为设备没有重启（拒绝路径的正常表现）。"""
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            if not ctx.hooks.state().get("connected"):
                return False
        except Exception:
            return False
        time.sleep(1)
    return True


def _reboot_fw_suffix(ctx, fw0):
    """不论 final 是什么都跑一遍：判断设备有没有重启，顺手核实/等回版本号，统一拼出
    `;rebooted=yes|no;fw_unchanged=<bool>` 后缀——后缀会进 record 基线，换固件版本后
    基线不该跟着绝对版本号变，具体版本只写 ctx.log。重启了（不管 final 是 OK 还是
    ERR）先等它连回来，不然下一条用例会在断链状态里起步。返回 (后缀字符串, fw1 或
    None)。"""
    if _still_connected(ctx):
        fw1 = ctx.hooks.state()["fw"]
        ctx.log(f"包被拒后仍连接，fw0={fw0} fw1={fw1}")
        return f";rebooted=no;fw_unchanged={fw1 == fw0}", fw1
    if not _wait_link(ctx, 90):
        ctx.log(f"重启后 90s 没重连，fw0={fw0}")
        return ";rebooted=yes;fw_unchanged=<90s 没重连>", None
    fw1 = ctx.hooks.state().get("fw")
    ctx.log(f"重启后重连，fw0={fw0} fw1={fw1}")
    return f";rebooted=yes;fw_unchanged={fw1 == fw0}", fw1


def _push(ctx, path, timeout=600):
    """推一个包；返回 (终止行, 最后一条 PROGRESS)。"""
    last = None
    final = None
    for line in ctx.hooks.stream(f"TEST:OTA:{path}", timeout=timeout):
        if line.startswith("PROGRESS:"):
            last = line
        elif line.startswith(("OK", "ERR")):
            final = line
    ctx.log(f"OTA {os.path.basename(path)} → {final} (last {last})")
    return final, last


@case("P8-01", "同版本重刷成功，重连后版本/指纹/密钥/槽不变", phase=8, needs=("imfw",), mutates=("link", "fw"))
def same_version(ctx):
    path = os.path.abspath(ctx.args.imfw)
    fw0 = ctx.hooks.state()["fw"]
    final, last = _push(ctx, path)
    if final != "OK":
        return FAIL(f"{final} (last {last})")
    if not _wait_link(ctx, 90):
        return FAIL("OTA 后 90s 没重连")
    fw1 = ctx.hooks.state()["fw"]
    return PASS(f"{fw0} → {fw1}") if fw1.split(".")[:3] == fw0.split(".")[:3] else FAIL(f"版本变了 {fw0} → {fw1}")


@case("P8-02", "坏签名包 → END 验签拒，版本不变（全量推送约 1 分钟）", phase=8, needs=("imfw",), expect="record")
def bad_signature(ctx):
    """firmware 把签名校验和 SVN 反降级检查都放在 END 之后的 deferred verify 里
    （hidkbd.c 的 s_ota_verify_pending 流程：先落盘再校验）；HEADER 阶段只查
    magic/格式版本/hw_id/fw_size，不碰签名。所以坏签名包会被整段推完（~216KB，
    约 1 分钟）才在 END 拿到拒绝，不是"HEADER 拒"。"""
    path = os.path.abspath(ctx.args.imfw)
    fw0 = ctx.hooks.state()["fw"]
    data = imfw.corrupt_signature(imfw.load(path))
    final, last = _push(ctx, _tmp(ctx, "bad-sig.imfw", data), timeout=120)
    suffix, fw1 = _reboot_fw_suffix(ctx, fw0)
    if final != "OK" and fw1 is not None and fw1 != fw0:
        return FAIL(f"包被拒但版本变了 {fw0} → {fw1}")
    return ctx.expect(f"{final!s}{suffix}", note=f"last={last}")


@case("P8-03", "低 SVN 重签包 → 拒，版本不变", phase=8, needs=("imfw", "ota_keys"), expect="record")
def svn_downgrade(ctx):
    """SVN 反降级检查和签名校验同一个 deferred verify 阶段判定（END 之后），同样要
    整段推完才知道结果，见 P8-02 docstring。"""
    path = os.path.abspath(ctx.args.imfw)
    data = imfw.load(path)
    svn = imfw.info(data)["svn"]
    if svn is None or svn == 0:
        return SKIP(f"当前包 SVN={svn}，没法再降")
    fw0 = ctx.hooks.state()["fw"]
    low = imfw.with_svn(data, svn - 1, imfw.load_private_pem())
    ctx.log(f"svn {svn} -> {svn - 1}")
    final, last = _push(ctx, _tmp(ctx, "low-svn.imfw", low), timeout=120)
    suffix, fw1 = _reboot_fw_suffix(ctx, fw0)
    if final != "OK" and fw1 is not None and fw1 != fw0:
        return FAIL(f"包被拒但版本变了 {fw0} → {fw1}")
    return ctx.expect(f"svn_down:{final!s}{suffix}", note=f"last={last}")


@case("P8-04", "推到 ~50% OTA_ABORT 断链 → 重连版本不变 → 可再推", phase=8, needs=("imfw",), mutates=("link", "fw"))
def abort_midway(ctx):
    path = os.path.abspath(ctx.args.imfw)
    fw0 = ctx.hooks.state()["fw"]
    out = {}

    def go():
        try:
            seen = []
            for line in ctx.hooks.stream(f"TEST:OTA:{path}", timeout=600):
                seen.append(line)
                if line.startswith("PROGRESS:") and int(line.split(":")[1]) >= 50 and "aborted" not in out:
                    out["aborted"] = True
                    ctx.hooks.call("TEST:OTA_ABORT")
            out["final"] = seen[-1] if seen else None
        except Exception as e:
            out["err"] = str(e)

    t = threading.Thread(target=go)
    t.start()
    t.join(300)
    # OTA_ABORT 本身会让 TEST:OTA 这条流以 ERR:writeFailed/noResponse 收尾（或让底层连接
    # 提前收尾），这是预期的中断路径；只有在没进 abort 分支的情况下线程异常才算真的坏了。
    if out.get("err") is not None and not out.get("aborted"):
        return FAIL(f"OTA 推送线程异常: {out['err']}")
    if not out.get("aborted"):
        return INVALID(f"没到 50% 就结束了: {out.get('final')}")
    if not _wait_link(ctx, 60):
        return FAIL("中断后 60s 没重连")
    fw1 = ctx.hooks.state()["fw"]
    if fw1 != fw0:
        return FAIL(f"中断后版本变了 {fw0} → {fw1}")
    final, last = _push(ctx, path)
    if final != "OK" or not _wait_link(ctx, 90):
        return FAIL(f"中断后再推失败: {final} (last {last})")
    return PASS(f"中断于 ~50%，再推成功，{ctx.hooks.state()['fw']}")


@case("P8-05", "推到 ~50% 拨 SW2 断电 → 重启版本不变", phase=8, needs=("imfw", "sw2", "human"), mutates=("link", "fw"), destructive=True)
def power_cut_midway(ctx):
    path = os.path.abspath(ctx.args.imfw)
    fw0 = ctx.hooks.state()["fw"]
    ctx.op.touch("看到进度到 50% 时立刻拨 SW2 断电，3 秒后再拨回来")
    out = {}

    def go():
        try:
            for line in ctx.hooks.stream(f"TEST:OTA:{path}", timeout=600):
                if line.startswith("PROGRESS:"):
                    pct = int(line.split(":")[1])
                    if pct >= 50 and "told" not in out:
                        out["told"] = True
                        print("\a      >>> 现在拨 SW2 <<<")
                out["final"] = line
        except Exception as e:
            # 断电本身就会打断这条流（recv 超时或连接异常），这是测试要制造的情况，
            # 不算用例线程的 bug，只记下来供排查用。
            out["err"] = str(e)

    t = threading.Thread(target=go)
    t.start()
    t.join(300)
    ctx.log(f"final={out.get('final')} err={out.get('err')}")
    ctx.op.wait_enter("拨回 SW2 上电后回车")
    if not _wait_link(ctx, 120):
        return FAIL("断电重启后 120s 没重连（可能变砖，走 wchisp 串口救）")
    fw1 = ctx.hooks.state()["fw"]
    return PASS(f"{fw1}") if fw1 == fw0 else FAIL(f"版本变了 {fw0} → {fw1}")


@case("P8-06", "IAP：HEADER 后直接 END 不经 PROM → 拒或无动作，不变砖", phase=8, needs=("imfw",), expect="record", mutates=("link", "fw"))
def iap_end_only(ctx):
    path = os.path.abspath(ctx.args.imfw)
    data = imfw.load(path)
    fw0 = ctx.hooks.state()["fw"]
    header = data[:0x80]
    frames = (
        ("INFO", "84020000"),
        ("ERASE", "81040000" + "3600"),                             # 54 blocks
        ("HEADER", "85" + f"{len(header):02x}" + header.hex()),
    )
    for name, frame in frames:
        # ERASE 读走的是固定 5s 的钩子超时，真机擦 54 块 Image B 有时候压线，偶发
        # ERR:TIMEOUT 不代表协议层拒绝——这三条只进日志，不进 record 基线。
        r = ctx.hooks.call(f"TEST:OTA_RAW:{frame}", timeout=30)
        ctx.log(f"{name} {frame} → {r.value}")
    # END 帧带 :15000 —— 真机在没发任何 PROM 数据时判定拒绝，落盘/解析路径比正常
    # END 慢，默认 5000ms 有时候压线超时误报 NORX。
    end = ctx.hooks.call("TEST:OTA_RAW:83020000:15000", timeout=30)
    _wait_link(ctx, 90)
    fw1 = ctx.hooks.state().get("fw")
    ctx.log(f"fw0={fw0} fw1={fw1}")
    # record 基线不含具体版本号（换固件版本后不该跟着变），只记「变没变」。
    return ctx.expect(f"{end.value};fw_unchanged={fw1 == fw0}")


@case("P8-07", "PROM 第一块后断链 → 重连正常", phase=8, needs=("imfw",), mutates=("link",))
def header_then_drop(ctx):
    path = os.path.abspath(ctx.args.imfw)
    fw0 = ctx.hooks.state()["fw"]
    out = {}

    def go():
        try:
            for line in ctx.hooks.stream(f"TEST:OTA:{path}", timeout=600):
                if line.startswith("PROGRESS:") and "dropped" not in out:
                    out["dropped"] = True
                    ctx.hooks.call("TEST:OTA_ABORT")
                out["final"] = line
        except Exception as e:
            out["err"] = str(e)

    t = threading.Thread(target=go)
    t.start()
    t.join(120)
    if out.get("err") is not None and not out.get("dropped"):
        return FAIL(f"OTA 推送线程异常: {out['err']}")
    if not _wait_link(ctx, 60):
        return FAIL("60s 没重连")
    return PASS() if ctx.hooks.state()["fw"] == fw0 else FAIL("版本变了")
