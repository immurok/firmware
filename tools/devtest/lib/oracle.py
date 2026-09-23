"""判据：体检快照/diff、sudo 指纹布尔、ECDSA/TOTP 校验、Apple 连接参数公式。"""
import hashlib
import hmac
import struct
import subprocess
import time

_FIELD_GROUP = {
    "connected": "link", "fw": "fw", "fp": "fp", "slot_bitmap": "slot",
    "slot_active": "slot", "paired": "paired",
}


def snapshot(hooks):
    st = hooks.state()
    if not st.get("connected"):
        return {"connected": False}
    keys = {}
    # 走裸命令 0x60（KEY_COUNT）而不是 TEST:KEY_COUNT：后者是走 App 的类别名分派，
    # 设备真的拒绝这个请求（例如没有任何认证指纹）时也想拿到 -1（体检 diff 会忽略
    # -1），不能把"设备拒绝"和"读到 0"混为一谈。
    for code, cat in enumerate(("ssh", "otp", "api")):
        r = hooks.cmd(f"60{code:02x}")
        keys[cat] = r[1] if (r is not None and r[0] == 0) else -1
    return {
        "connected": True,
        "fw": st.get("fw", ""),
        "fp": st.get("fp_bitmap", 0),
        "slot_bitmap": st.get("slot_bitmap", 0),
        "slot_active": st.get("slot_active", 0),
        "paired": st.get("paired", False),
        "keys": keys,
    }


def diff(before, after, mutates):
    if "all" in mutates:
        return []
    out = []
    if not after.get("connected", False) or not before.get("connected", False):
        if before.get("connected") != after.get("connected") and "link" not in mutates:
            out.append(f"connected: {before.get('connected')} → {after.get('connected')}")
        return out
    for f, grp in _FIELD_GROUP.items():
        if f == "connected":
            continue
        if before.get(f) != after.get(f) and grp not in mutates:
            out.append(f"{f}: {before.get(f)} → {after.get(f)}")
    for cat in ("ssh", "otp", "api"):
        b = before.get("keys", {}).get(cat)
        a = after.get("keys", {}).get(cat)
        if b == -1 or a == -1:
            continue  # KEY_COUNT 读失败，无法判断，跳过
        if b != a and "keys" not in mutates:
            out.append(f"keys.{cat}: {b} → {a}")
    return out


def sudo_probe(timeout=40):
    """沿用 firmware/tools/test-dual-auth.sh：sudo 成败 = 指纹是否工作。"""
    subprocess.run(["sudo", "-k"], check=False)
    t0 = time.time()
    try:
        rc = subprocess.run(["sudo", "-S", "-p", "", "true"], stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        return "FAIL", time.time() - t0
    dt = time.time() - t0
    if rc == 0 and dt < 0.3:
        return "INVALID", dt
    return ("PASS" if rc == 0 else "FAIL"), dt


def verify_ecdsa(pub_xy, digest, sig_rs):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature
    x = int.from_bytes(pub_xy[:32], "big")
    y = int.from_bytes(pub_xy[32:], "big")
    r = int.from_bytes(sig_rs[:32], "big")
    s = int.from_bytes(sig_rs[32:], "big")
    try:
        pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        pub.verify(encode_dss_signature(r, s), digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except (InvalidSignature, ValueError):
        return False


def totp(secret, t=None, step=30, digits=6):
    t = int(time.time()) if t is None else int(t)
    msg = struct.pack(">Q", t // step)
    h = hmac.new(secret, msg, hashlib.sha1).digest()
    off = h[-1] & 0x0F
    code = (struct.unpack(">I", h[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_window(secret, t=None, step=30):
    t = int(time.time()) if t is None else t
    return {totp(secret, t + d * step, step) for d in (-1, 0, 1)}


def apple_params_ok(interval_units, latency, timeout_units):
    return timeout_units * 10 > interval_units * 1.25 * (latency + 1) * 3
