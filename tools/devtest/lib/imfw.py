"""造 OTA 测试包：坏签名 / 低 SVN 重签 / 截断。布局见 ota/ota-package.py 注释。"""
import hashlib
import importlib.util
import os
import struct

HEADER_V2 = 0x80
SIG_OFF = 0x40
SVN_OFF = 0x0C
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))


def load(path):
    with open(path, "rb") as f:
        return f.read()


def info(data):
    magic, ver = struct.unpack_from("<IB", data, 0)
    if magic != 0x494D4657:
        raise ValueError("不是 IMFW 包")
    return {
        "version": ver,
        "svn": struct.unpack_from("<H", data, SVN_OFF)[0] if ver >= 2 else None,
        "fw_size": struct.unpack_from("<I", data, 8)[0],
    }


def corrupt_signature(data):
    b = bytearray(data)
    b[SIG_OFF] ^= 0x5A
    return bytes(b)


def truncate(data, keep_fraction):
    body = data[HEADER_V2:]
    return data[:HEADER_V2] + body[: int(len(body) * keep_fraction)]


def load_private_pem():
    p = os.path.join(REPO, "ota", "ota_keys.py")
    if not os.path.exists(p):
        return None
    spec = importlib.util.spec_from_file_location("ota_keys", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return getattr(m, "OTA_EC_PRIVATE_PEM", None)


def _sign(prefix, pem):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature
    assert len(prefix) == SIG_OFF
    priv = serialization.load_pem_private_key(pem.encode(), password=None)
    der = priv.sign(hashlib.sha256(prefix).digest(), ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(der)
    return prefix + r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _verify(data, pub):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature
    r = int.from_bytes(data[SIG_OFF:SIG_OFF + 32], "big")
    s = int.from_bytes(data[SIG_OFF + 32:HEADER_V2], "big")
    try:
        pub.verify(encode_dss_signature(r, s), hashlib.sha256(data[:SIG_OFF]).digest(),
                   ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except InvalidSignature:
        return False


def with_svn(data, svn, pem):
    prefix = bytearray(data[:SIG_OFF])
    struct.pack_into("<H", prefix, SVN_OFF, svn)
    return _sign(bytes(prefix), pem) + data[HEADER_V2:]
