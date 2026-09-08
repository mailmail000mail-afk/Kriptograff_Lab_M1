import unittest

from cryptocore.modes.ecb import (
    decrypt_ecb,
    encrypt_blocks,
    encrypt_ecb,
    pkcs7_pad,
    pkcs7_unpad,
)


class EcbTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    def test_nist_aes_128_block_vector(self) -> None:
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(encrypt_blocks(plaintext, self.key), expected)

    def test_round_trip_text(self) -> None:
        data = "Учебная проверка CryptoCore".encode("utf-8")
        self.assertEqual(decrypt_ecb(encrypt_ecb(data, self.key), self.key), data)

    def test_round_trip_binary_and_empty_data(self) -> None:
        for data in (bytes(range(256)), b""):
            with self.subTest(length=len(data)):
                self.assertEqual(decrypt_ecb(encrypt_ecb(data, self.key), self.key), data)

    def test_pkcs7_adds_full_block_when_aligned(self) -> None:
        padded = pkcs7_pad(b"A" * 16)
        self.assertEqual(len(padded), 32)
        self.assertEqual(padded[-16:], bytes([16]) * 16)
        self.assertEqual(pkcs7_unpad(padded), b"A" * 16)

    def test_invalid_padding_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "PKCS#7"):
            pkcs7_unpad(b"A" * 15 + b"\x02")


if __name__ == "__main__":
    unittest.main()
