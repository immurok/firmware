import sys, os, unittest, hashlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from lib import oracle
from tests.fake_app import FakeApp, reply
from lib.hooks import Hooks


class OracleTest(unittest.TestCase):
    def test_diff_respects_mutates(self):
        a = {"connected": True, "fw": "1", "fp": 3, "slot_bitmap": 1, "slot_active": 1,
             "paired": True, "keys": {"ssh": 1, "otp": 2, "api": 0}}
        b = dict(a, fp=7, keys={"ssh": 1, "otp": 3, "api": 0})
        self.assertEqual(oracle.diff(a, b, ("fp", "keys")), [])
        d = oracle.diff(a, b, ("fp",))
        self.assertEqual(len(d), 1)
        self.assertIn("keys.otp", d[0])
        self.assertEqual(oracle.diff(a, b, ("all",)), [])

    def test_diff_ignores_unknown_key_count(self):
        # KEY_COUNT 读失败时 snapshot 记 -1；这种情况下不该报变化
        a = {"connected": True, "fw": "1", "fp": 0, "slot_bitmap": 1, "slot_active": 1,
             "paired": True, "keys": {"ssh": -1, "otp": 2, "api": 0}}
        b = dict(a, keys={"ssh": 3, "otp": 2, "api": 0})
        self.assertEqual(oracle.diff(a, b, ()), [])
        c = dict(a, keys={"ssh": -1, "otp": -1, "api": 0})
        self.assertEqual(oracle.diff(a, c, ()), [])

    def test_diff_disconnect(self):
        a = {"connected": True, "fw": "1", "fp": 0, "slot_bitmap": 1, "slot_active": 1,
             "paired": True, "keys": {}}
        self.assertTrue(oracle.diff(a, {"connected": False}, ()))
        self.assertEqual(oracle.diff(a, {"connected": False}, ("link",)), [])

    def test_snapshot_from_hooks(self):
        app = FakeApp({
            "STATE": reply('OK:{"connected":true,"fw":"1.8.3","fp_bitmap":5,"paired":true,'
                           '"slot_bitmap":1,"slot_active":1}'),
            "CMD": lambda req, c: c.sendall(b"OK:0002\n"),
        })
        s = oracle.snapshot(Hooks(app.path))
        app.close()
        self.assertEqual(s["fp"], 5)
        self.assertEqual(s["keys"], {"ssh": 2, "otp": 2, "api": 2})

    def test_totp_rfc6238_vector(self):
        # RFC 6238 附录 B：secret "12345678901234567890"，T=59 → 94287082（8 位）；取后 6 位 287082
        self.assertEqual(oracle.totp(b"12345678901234567890", t=59), "287082")
        self.assertIn("287082", oracle.totp_window(b"12345678901234567890", t=59))

    def test_totp_accepts_float_time(self):
        # t 常来自 time.time()（float）；应与 int 结果一致，不应因 struct.pack 报错
        self.assertEqual(oracle.totp(b"12345678901234567890", t=59.0),
                          oracle.totp(b"12345678901234567890", t=59))

    def test_ecdsa_roundtrip(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, Prehashed
        from cryptography.hazmat.primitives import hashes
        k = ec.generate_private_key(ec.SECP256R1())
        digest = hashlib.sha256(b"x").digest()
        der = k.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        r, s = decode_dss_signature(der)
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        n = k.public_key().public_numbers()
        pub = n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")
        self.assertTrue(oracle.verify_ecdsa(pub, digest, sig))
        self.assertFalse(oracle.verify_ecdsa(pub, digest, sig[:-1] + bytes([sig[-1] ^ 1])))

    def test_apple_params(self):
        self.assertTrue(oracle.apple_params_ok(40, 29, 600))    # 50ms×30×3=4500 < 6000
        self.assertFalse(oracle.apple_params_ok(40, 29, 400))


if __name__ == "__main__":
    unittest.main()
