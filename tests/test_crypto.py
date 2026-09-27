import sys
import unittest

sys.path.insert(0, "src")

from aes_gcm import generate_key, encrypt, decrypt
from rsa_signatures import generate_key_pair, sign, verify
from password_hashing import hash_password, verify_password


class CryptoTests(unittest.TestCase):

    def test_aes_round_trip(self):
        key = generate_key()
        plaintext = b"test message"
        aad = b"metadata"
        payload = encrypt(key, plaintext, aad)
        self.assertEqual(decrypt(key, payload, aad), plaintext)

    def test_aes_nonce_is_random(self):
        key = generate_key()
        p1 = encrypt(key, b"same")
        p2 = encrypt(key, b"same")
        self.assertNotEqual(p1["nonce"], p2["nonce"])

    def test_rsa_signature(self):
        private_key, public_key = generate_key_pair()
        message = b"signed content"
        signature = sign(private_key, message)
        self.assertTrue(verify(public_key, message, signature))
        self.assertFalse(verify(public_key, b"changed", signature))

    def test_bcrypt(self):
        password = "correct horse battery staple"
        stored = hash_password(password)
        self.assertTrue(verify_password(password, stored))
        self.assertFalse(verify_password("wrong", stored))
        self.assertNotEqual(stored, password)


if __name__ == "__main__":
    unittest.main()
