import unittest

from cryptocore.aead import EncryptThenMAC
from cryptocore.authentication import AuthenticationError


MASTER_KEY = bytes.fromhex("00112233445566778899aabbccddeeff")
IV = bytes.fromhex("102132435465768798a9bacbdcedfe0f")


class EncryptThenMacTests(unittest.TestCase):
    def test_round_trip_and_output_format(self) -> None:
        plaintext = bytes(range(256)) + b"partial"
        aad = b"file-name:report.pdf"
        scheme = EncryptThenMAC(MASTER_KEY, IV)
        combined = scheme.encrypt(plaintext, aad)
        self.assertEqual(combined[:16], IV)
        self.assertEqual(len(combined), 16 + len(plaintext) + 32)
        self.assertEqual(scheme.decrypt(combined, aad), plaintext)

    def test_encryption_and_mac_keys_are_separated(self) -> None:
        scheme = EncryptThenMAC(MASTER_KEY, IV)
        self.assertEqual(len(scheme.encryption_key), 16)
        self.assertEqual(len(scheme.mac_key), 32)
        self.assertNotEqual(scheme.encryption_key, scheme.mac_key[:16])

    def test_wrong_aad_ciphertext_iv_and_tag_are_rejected(self) -> None:
        aad = b"metadata"
        scheme = EncryptThenMAC(MASTER_KEY, IV)
        combined = scheme.encrypt(b"secret", aad)
        candidates = []
        for position in (0, 16, -1):
            tampered = bytearray(combined)
            tampered[position] ^= 1
            candidates.append((bytes(tampered), aad))
        candidates.append((combined, b"wrong"))

        for data, supplied_aad in candidates:
            with self.subTest(data=data, aad=supplied_aad):
                with self.assertRaises(AuthenticationError):
                    scheme.decrypt(data, supplied_aad)

    def test_random_iv_changes_ciphertext(self) -> None:
        first = EncryptThenMAC(MASTER_KEY).encrypt(b"same", b"aad")
        second = EncryptThenMAC(MASTER_KEY).encrypt(b"same", b"aad")
        self.assertNotEqual(first[:16], second[:16])
        self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()
