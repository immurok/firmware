import sys, os, unittest, struct, hashlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from lib import imfw


def make_pkg(svn=2, pem=None):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    k = ec.generate_private_key(ec.SECP256R1())
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption()).decode()
    body = bytes(range(256)) * 4
    prefix = struct.pack("<IBBHIHH", 0x494D4657, 2, 0, 0x0592, len(body), svn, 0)
    prefix += b"\x11" * 16 + hashlib.sha256(body).digest()
    return imfw._sign(prefix, pem) + body, pem, k.public_key()


class ImfwTest(unittest.TestCase):
    def test_info(self):
        data, _, _ = make_pkg(svn=2)
        i = imfw.info(data)
        self.assertEqual((i["version"], i["svn"], i["fw_size"]), (2, 2, 1024))

    def test_corrupt_signature_changes_only_sig(self):
        data, _, _ = make_pkg()
        bad = imfw.corrupt_signature(data)
        self.assertNotEqual(bad[0x40], data[0x40])
        self.assertEqual(bad[:0x40], data[:0x40])
        self.assertEqual(bad[0x80:], data[0x80:])

    def test_with_svn_resigns(self):
        data, pem, pub = make_pkg(svn=2)
        low = imfw.with_svn(data, 1, pem)
        self.assertEqual(imfw.info(low)["svn"], 1)
        self.assertTrue(imfw._verify(low, pub))
        self.assertFalse(imfw._verify(imfw.corrupt_signature(low), pub))

    def test_truncate(self):
        data, _, _ = make_pkg()
        t = imfw.truncate(data, 0.5)
        self.assertEqual(len(t), 0x80 + 512)


if __name__ == "__main__":
    unittest.main()
