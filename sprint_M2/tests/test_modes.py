import unittest

from cryptocore.modes.cbc import decrypt_cbc, encrypt_cbc
from cryptocore.modes.cfb import decrypt_cfb, encrypt_cfb
from cryptocore.modes.ctr import decrypt_ctr, encrypt_ctr
from cryptocore.modes.ofb import decrypt_ofb, encrypt_ofb


KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
CTR_IV = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
PLAINTEXT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)


class ModeVectorTests(unittest.TestCase):
    def test_cbc_nist_vector_and_round_trip(self) -> None:
        expected = bytes.fromhex(
            "7649abac8119b246cee98e9b12e9197d"
            "5086cb9b507219ee95db113a917678b2"
            "73bed6b8e3c1743b7116e69e22229516"
            "3ff1caa1681fac09120eca307586e1a7"
        )
        encrypted = encrypt_cbc(PLAINTEXT, KEY, IV)
        self.assertEqual(encrypted[: len(expected)], expected)
        self.assertEqual(len(encrypted), len(PLAINTEXT) + 16)
        self.assertEqual(decrypt_cbc(encrypted, KEY, IV), PLAINTEXT)

    def test_cfb128_nist_vector(self) -> None:
        expected = bytes.fromhex(
            "3b3fd92eb72dad20333449f8e83cfb4a"
            "c8a64537a0b3a93fcde3cdad9f1ce58b"
            "26751f67a3cbb140b1808cf187a4f4df"
            "c04b05357c5d1c0eeac4c66f9ff7f2e6"
        )
        self.assertEqual(encrypt_cfb(PLAINTEXT, KEY, IV), expected)
        self.assertEqual(decrypt_cfb(expected, KEY, IV), PLAINTEXT)

    def test_ofb_nist_vector(self) -> None:
        expected = bytes.fromhex(
            "3b3fd92eb72dad20333449f8e83cfb4a"
            "7789508d16918f03f53c52dac54ed825"
            "9740051e9c5fecf64344f7a82260edcc"
            "304c6528f659c77866a510d9c1d6ae5e"
        )
        self.assertEqual(encrypt_ofb(PLAINTEXT, KEY, IV), expected)
        self.assertEqual(decrypt_ofb(expected, KEY, IV), PLAINTEXT)

    def test_ctr_nist_vector(self) -> None:
        expected = bytes.fromhex(
            "874d6191b620e3261bef6864990db6ce"
            "9806f66b7970fdff8617187bb9fffdff"
            "5ae4df3edbd5d35e5b4f09020db03eab"
            "1e031dda2fbe03d1792170a0f3009cee"
        )
        self.assertEqual(encrypt_ctr(PLAINTEXT, KEY, CTR_IV), expected)
        self.assertEqual(decrypt_ctr(expected, KEY, CTR_IV), PLAINTEXT)

    def test_stream_modes_preserve_partial_block_length(self) -> None:
        modes = (
            (encrypt_cfb, decrypt_cfb),
            (encrypt_ofb, decrypt_ofb),
            (encrypt_ctr, decrypt_ctr),
        )
        for length in (0, 1, 15, 16, 17, 31, 33):
            data = bytes(range(length))
            for encrypt, decrypt in modes:
                with self.subTest(length=length, mode=encrypt.__name__):
                    encrypted = encrypt(data, KEY, IV)
                    self.assertEqual(len(encrypted), len(data))
                    self.assertEqual(decrypt(encrypted, KEY, IV), data)

    def test_invalid_iv_is_rejected(self) -> None:
        for function in (encrypt_cbc, encrypt_cfb, encrypt_ofb, encrypt_ctr):
            with self.subTest(mode=function.__name__):
                with self.assertRaisesRegex(ValueError, "IV"):
                    function(b"data", KEY, b"short")


if __name__ == "__main__":
    unittest.main()
