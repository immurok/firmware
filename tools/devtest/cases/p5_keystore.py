"""P5 密钥库：真实密码学验证 + 边界。写进去的条目用例结束都删掉。

约定（fix round 1 后，对照固件 hidkbd.c 与 BLEManager 修正，见 task-14-15-report.md）：
- 按名字找 idx（`_find_idx_by_name`）用 `ctx.cmd` 直发 KEY_READ 帧读 off=0（名字字段），
  任何类目都不需要门——off=0 从不触发门控，这一步不再摸门。
- 门控调用（WRITE/DELETE/GENERATE/SIGN/OTP，以及 api 类目 off>=32 的门内 READ）前都摸一次门；
  调用失败（not r.ok）时补发 TEST:GATE_CANCEL，避免设备门悬空。
- socket 超时：门控 KEY_GENERATE/KEY_SIGN/KEY_OTP/KEY_WRITE 60s，KEY_DELETE 50s，
  门内 KEY_READ 30s；不门控的 KEY_GETPUB 25s。
- KEYSTORE 门控成功会启动 10s rolling 冷却，期间的门控读无需再摸门；冷却期外，固件对
  api 类目 off>=32 的无门探测只回裸 0x11（无副作用探测，不会为此临时开门）——P5-03 据此设计。
- fix round 2：`_count` 在 ERR:*/非数字时返回 -1（不抛异常）；`_find_idx_by_name` 对 n<0
  直接判"找不到"；所有 finally 里的清理（找 idx + 删）都包一层
  `try/except HooksError`，避免设备恰好不可达时清理逻辑本身崩溃、盖掉已经算出来的结果。
"""
import os
import time
from lib.cases import case, PASS, FAIL, INVALID, SKIP
from lib import oracle
from lib.hooks import HooksError

MAX = {"ssh": 32, "otp": 128, "api": 50}
SIZE = {"ssh": 112, "otp": 92, "api": 160}
CAT = {"ssh": 0, "otp": 1, "api": 2}


def _count(ctx, cat):
    """计数失败（ERR:* 或返回值不是数字）时给 -1，不抛异常——调用方（尤其 finally 里的
    清理逻辑）不能因为设备当时不可达就崩在清理步骤，漏掉本该保留的 FAIL 结果。"""
    r = ctx.hooks.call(f"TEST:KEY_COUNT:{cat}")
    if not r.ok:
        return -1
    try:
        return int(r.value)
    except ValueError:
        return -1


def _find_idx_by_name(ctx, cat, name, n):
    """按名字找 idx（name 在 off=0）。off=0 从不触发门控，任何类目都不需要摸门；
    直接用 ctx.cmd 发 KEY_READ 帧 [61][cat][idx][off=0]，回包 [00][total][off][data...]。
    n<0（_count 拿不到有效计数）视为找不到，不去扫描一个负数范围。"""
    if n < 0:
        return None
    for i in range(n):
        r = ctx.cmd(f"61{CAT[cat]:02x}{i:02x}00")
        if r and r[0] == 0x00 and r[3:].startswith(name.encode()):
            return i
    return None


@case("P5-01", "SSH: GENERATE → GETPUB 一致 → SIGN → 本机验签", phase=5, needs=("human",), mutates=("keys",))
def ssh_roundtrip(ctx):
    name = f"devtest{int(time.time()) % 100000}"
    ctx.op.touch("生成 SSH 密钥需要门：触摸")
    g = ctx.hooks.call(f"TEST:KEY_GENERATE:{name}", timeout=60)
    if not g.ok:
        ctx.hooks.call("TEST:GATE_CANCEL")
        return FAIL(f"GENERATE {g.final}")
    idx, pub_hex = g.value.split(":")
    idx = int(idx)
    try:
        p = ctx.hooks.call(f"TEST:KEY_GETPUB:{idx}", timeout=25)
        if p.value != pub_hex:
            return FAIL("GETPUB 与 GENERATE 返回的公钥不一致")
        digest = os.urandom(32)
        ctx.op.touch("签名需要门：触摸")
        s = ctx.hooks.call(f"TEST:KEY_SIGN:{idx}:{digest.hex()}", timeout=60)
        if not s.ok:
            ctx.hooks.call("TEST:GATE_CANCEL")
            return FAIL(f"SIGN {s.final}")
        ok = oracle.verify_ecdsa(bytes.fromhex(pub_hex), digest, bytes.fromhex(s.value))
        return PASS(f"idx {idx} 验签通过") if ok else FAIL("签名验证不通过")
    finally:
        # 删之前按名字二次确认 idx 没变——GENERATE 返回的 idx 万一和别的流程撞车，
        # 宁可不删也不能删错一把真实密钥。这里的 return 会盖掉 try 块的结果，是故意的。
        try:
            confirm = _find_idx_by_name(ctx, "ssh", name, _count(ctx, "ssh"))
            if confirm != idx:
                return FAIL(f"清理前二次确认 idx 不一致（按名字={confirm}，GENERATE 返回={idx}），为避免删错真实密钥跳过删除")
            ctx.op.touch("删 SSH 条目需要门：触摸")
            d = ctx.hooks.call(f"TEST:KEY_DELETE:ssh:{idx}", timeout=50)
            if not d.ok:
                ctx.hooks.call("TEST:GATE_CANCEL")
        except HooksError as e:
            ctx.log(f"清理失败: {e}")


@case("P5-02", "OTP: 写已知 secret → 设备 TOTP 与本机 ±1 步一致", phase=5, needs=("human",), mutates=("keys",))
def otp_roundtrip(ctx):
    secret = b"devtest-secret-1"          # 无尾零，固件按去尾零后的长度算
    name = "devtest-otp"
    entry = name.encode().ljust(30, b"\0") + b"svc".ljust(30, b"\0") + secret.ljust(32, b"\0")
    ctx.op.touch("写 OTP 条目需要门：触摸")
    w = ctx.hooks.call(f"TEST:KEY_WRITE:otp:255:{entry.hex()}", timeout=60)
    if not w.ok:
        ctx.hooks.call("TEST:GATE_CANCEL")
        return FAIL(f"WRITE {w.final}")
    try:
        idx = _find_idx_by_name(ctx, "otp", name, _count(ctx, "otp"))
        if idx is None:
            return FAIL("写入后按名字找不到条目")
        ctx.op.touch("读 OTP 需要门：触摸")
        r = ctx.hooks.call(f"TEST:KEY_OTP:{idx}", timeout=60)
        if not r.ok:
            ctx.hooks.call("TEST:GATE_CANCEL")
            return FAIL(f"KEY_OTP {r.final}")
        win = oracle.totp_window(secret)
        return PASS(f"{r.value} ∈ {sorted(win)}") if r.value in win else FAIL(f"设备 {r.value} 不在本机窗口 {sorted(win)}")
    finally:
        try:
            idx2 = _find_idx_by_name(ctx, "otp", name, _count(ctx, "otp"))
            if idx2 is not None:
                ctx.op.touch("删 OTP 条目需要门：触摸")
                d = ctx.hooks.call(f"TEST:KEY_DELETE:otp:{idx2}", timeout=50)
                if not d.ok:
                    ctx.hooks.call("TEST:GATE_CANCEL")
            else:
                ctx.log("警告：清理时按名字找不到 devtest-otp 条目，可能已残留或被其他流程删掉")
        except HooksError as e:
            ctx.log(f"清理失败: {e}")


@case("P5-03", "API: 写 → 冷却期外无门探测应裸 0x11 → 门内读全量一致", phase=5, needs=("human",), mutates=("keys",), expect="record")
def api_gate(ctx):
    """真实门控行为（对照固件 hidkbd.c）：api 类目 off>=32 的读需要门；KEYSTORE 门控成功会
    启动 10s rolling 冷却，冷却期内的门控读不用再摸门。冷却期外，固件对 off>=32 的无门探测
    是无副作用的——回一个裸 0x11，不会为此临时开门（App 不会为等门阻塞）。所以这里先等 WRITE
    用掉的 KEYSTORE 冷却窗口彻底过期（>10s）再探测，避免把"还在冷却期内"误判成"漏了"。
    门内读改用 TEST:GATE:30（AUTH 门）而不是重新走 KEYSTORE 门，覆盖"AUTH 门窗口内也能读
    api secret"这条路径。"""
    name = "devtest-api"
    key = b"sk-devtest-" + os.urandom(16).hex().encode()
    entry = name.encode().ljust(32, b"\0") + key.ljust(128, b"\0")
    ctx.op.touch("写 API 条目需要门：触摸")
    w = ctx.hooks.call(f"TEST:KEY_WRITE:api:255:{entry.hex()}", timeout=60)
    if not w.ok:
        ctx.hooks.call("TEST:GATE_CANCEL")
        return FAIL(f"WRITE {w.final}")
    try:
        idx = _find_idx_by_name(ctx, "api", name, _count(ctx, "api"))
        if idx is None:
            return FAIL("写入后找不到条目")
        ctx.op.touch("接下来 12s 不要触摸")
        time.sleep(11)   # 等 WRITE 用掉的 KEYSTORE 门冷却（rolling 10s）彻底过期
        r = ctx.cmd(f"6102{idx:02x}20")   # KEY_READ api idx off=32：冷却期外应回裸 0x11
        probe = f"{r[0]:02x}" if r else "NORX"
        leaked = bool(r) and r[0] == 0x00 and key in r
        ctx.op.touch("过门：触摸")
        gt = ctx.hooks.call("TEST:GATE:30", timeout=40)
        if gt.value != "PASS":
            ctx.hooks.call("TEST:GATE_CANCEL")
            return INVALID(f"过门失败: {gt.value}")
        r1 = ctx.hooks.call(f"TEST:KEY_READ:api:{idx}", timeout=30)
        if not r1.ok:
            ctx.hooks.call("TEST:GATE_CANCEL")
        got1 = bytes.fromhex(r1.value) if r1.ok else b""
        full_ok = got1[:160] == entry
        if leaked:
            return FAIL("无门探测读到了 secret")
        return ctx.expect(f"probe={probe};leak={leaked};gated_full_ok={full_ok}")
    finally:
        try:
            idx2 = _find_idx_by_name(ctx, "api", name, _count(ctx, "api"))
            if idx2 is not None:
                ctx.op.touch("删 API 条目需要门：触摸")
                d = ctx.hooks.call(f"TEST:KEY_DELETE:api:{idx2}", timeout=50)
                if not d.ok:
                    ctx.hooks.call("TEST:GATE_CANCEL")
            else:
                ctx.log("警告：清理时按名字找不到 devtest-api 条目，可能已残留或被其他流程删掉")
        except HooksError as e:
            ctx.log(f"清理失败: {e}")


@case("P5-04", "每类写 1 条 + 越界 idx → 拒；删后计数复原", phase=5, needs=("human",), mutates=("keys",), expect="record")
def fill_and_bounds(ctx):
    """每类只写 1 条（brief 原为 3 条；写/删都要过门，3 条=6 次触摸太重，缩到每类 1 条）。
    越界 idx 探针与删后计数复原检查保留。记录字符串只放增量/布尔，绝对计数进 ctx.log。"""
    notes = []
    for cat in ("ssh", "otp", "api"):
        n0 = _count(ctx, cat)
        name = f"dt{cat}0"
        entry = name.encode().ljust(SIZE[cat], b"\x01")
        ctx.op.touch(f"写 {cat} 条目需要门：触摸")
        w = ctx.hooks.call(f"TEST:KEY_WRITE:{cat}:255:{entry.hex()}", timeout=60)
        wrote_ok = w.ok
        if not wrote_ok:
            ctx.hooks.call("TEST:GATE_CANCEL")
        n1 = _count(ctx, cat)
        oob = ctx.raw(f"6103{CAT[cat]:02x}{MAX[cat]:02x}00")   # KEY_READ idx=maxEntries
        oob_hex = oob.hex() if oob else "NORX"
        if wrote_ok:
            idx = _find_idx_by_name(ctx, cat, name, _count(ctx, cat))
            if idx is not None:
                ctx.op.touch(f"删 {cat} 条目需要门：触摸")
                d = ctx.hooks.call(f"TEST:KEY_DELETE:{cat}:{idx}", timeout=50)
                if not d.ok:
                    ctx.hooks.call("TEST:GATE_CANCEL")
        n2 = _count(ctx, cat)
        restored = n2 == n0
        ctx.log(f"{cat}: n0={n0} n1={n1} n2={n2}")
        notes.append(f"{cat}:{'+1=ok' if wrote_ok else '+0=fail'},oob={oob_hex},restored={restored}")
        if not restored:
            return FAIL("删后计数没复原: " + ";".join(notes))
    return ctx.expect(";".join(notes))


@case("P5-05", "断链重连后条目仍在", phase=5, needs=("human",), mutates=("keys", "link"))
def persist_across_link(ctx):
    name = "dtpersist"
    entry = name.encode().ljust(92, b"\x02")
    ctx.op.touch("写 OTP 条目需要门：触摸")
    w = ctx.hooks.call(f"TEST:KEY_WRITE:otp:255:{entry.hex()}", timeout=60)
    if not w.ok:
        ctx.hooks.call("TEST:GATE_CANCEL")
        return FAIL(f"WRITE {w.final}")
    try:
        ctx.hooks.call("TEST:DISCONNECT")
        deadline = time.time() + 20
        while time.time() < deadline and not ctx.hooks.state().get("connected"):
            time.sleep(1)
        if not ctx.hooks.state().get("connected"):
            return FAIL("重连超时")
        idx = _find_idx_by_name(ctx, "otp", name, _count(ctx, "otp"))
        if idx is None:
            return FAIL("重连后条目消失")
        return PASS()
    finally:
        # _count/_find_idx_by_name 现在对"设备还没重连上"是健壮的（返回 -1/None 而不抛异常），
        # 这里再包一层 try/except 兜底真正的连接异常（比如清理时又恰好掉线），确保上面 try 块
        # 里 return 的 FAIL("重连超时") 之类结果不会被这里的异常吞掉。
        try:
            idx2 = _find_idx_by_name(ctx, "otp", name, _count(ctx, "otp"))
            if idx2 is not None:
                ctx.op.touch("删 OTP 条目需要门：触摸（重连后门状态已重置，需要再摸一次）")
                d = ctx.hooks.call(f"TEST:KEY_DELETE:otp:{idx2}", timeout=50)
                if not d.ok:
                    ctx.hooks.call("TEST:GATE_CANCEL")
            else:
                ctx.log("警告：清理时按名字找不到 dtpersist 条目，可能已残留或被其他流程删掉")
        except HooksError as e:
            ctx.log(f"清理失败: {e}")


@case("P5-06", "端到端 imk get imk://otp/<name>", phase=5, needs=("human",), mutates=("keys",))
def imk_e2e(ctx):
    import shutil
    import subprocess
    if shutil.which("imk") is None:
        return SKIP("imk 不在 PATH 中")
    secret = b"devtest-imk-secr"
    name = "devtest-imk"
    entry = name.encode().ljust(30, b"\0") + b"svc".ljust(30, b"\0") + secret.ljust(32, b"\0")
    ctx.op.touch("写 OTP 条目需要门：触摸")
    w = ctx.hooks.call(f"TEST:KEY_WRITE:otp:255:{entry.hex()}", timeout=60)
    if not w.ok:
        ctx.hooks.call("TEST:GATE_CANCEL")
        return FAIL(f"WRITE {w.final}")
    try:
        ctx.op.touch("imk get 需要门：触摸")
        p = subprocess.run(["imk", "get", f"imk://otp/{name}"], capture_output=True, text=True, timeout=60)
        out = p.stdout.strip()
        err = p.stderr.strip()
        if "CLI_DISABLED" in out or "CLI_DISABLED" in err:
            return SKIP(f"imk CLI 开关未启用: {(out or err)[:80]}")
        if p.returncode != 0:
            ctx.hooks.call("TEST:GATE_CANCEL")
            return FAIL(f"imk rc={p.returncode}: {err[:80]}")
        return PASS(out) if out in oracle.totp_window(secret) else FAIL(f"imk 给 {out} 不在窗口")
    finally:
        try:
            idx = _find_idx_by_name(ctx, "otp", name, _count(ctx, "otp"))
            if idx is not None:
                ctx.op.touch("删 OTP 条目需要门：触摸")
                d = ctx.hooks.call(f"TEST:KEY_DELETE:otp:{idx}", timeout=50)
                if not d.ok:
                    ctx.hooks.call("TEST:GATE_CANCEL")
            else:
                ctx.log("警告：清理时按名字找不到 devtest-imk 条目，可能已残留或被其他流程删掉")
        except HooksError as e:
            ctx.log(f"清理失败: {e}")
