from io import BytesIO
from pathlib import Path
import tempfile
import unittest

from cryptocore.mac import AESCMAC, generate_subkeys
from cryptocore.mac.file_mac import (
    MacOperationError,
    cmac_stream,
    read_expected_cmac,
)


KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
BLOCKS = (
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)


class CmacNistTests(unittest.TestCase):
    def test_nist_sp_800_38b_aes_128_vectors(self) -> None:
        data = bytes.fromhex(BLOCKS)
        cases = (
            (b"", "bb1d6929e95937287fa37d129b756746"),
            (data[:16], "070a16b46b4d4144f79bdd9dd04a287c"),
            (data[:40], "dfa66747de9ae63030ca32611497c827"),
            (data, "51f0bebf7e3b9d92fc49741779363cfe"),
        )
        for message, expected in cases:
            with self.subTest(length=len(message)):
                self.assertEqual(AESCMAC(KEY, message).hexdigest(), expected)

    def test_nist_subkeys(self) -> None:
        first, second = generate_subkeys(KEY)
        self.assertEqual(first.hex(), "fbeed618357133667c85e08f7236a8de")
        self.assertEqual(second.hex(), "f7ddac306ae266ccf90bc11ee46d513b")

    def test_streaming_chunk_boundaries(self) -> None:
        message = bytes(range(256)) * 5 + b"partial"
        expected = AESCMAC(KEY, message).hexdigest()
        for chunk_size in (1, 7, 15, 16, 17, 64, 257):
            with self.subTest(chunk_size=chunk_size):
                mac = AESCMAC(KEY)
                for start in range(0, len(message), chunk_size):
                    mac.update(message[start : start + chunk_size])
                self.assertEqual(mac.hexdigest(), expected)

    def test_digest_does_not_finish_original_object(self) -> None:
        mac = AESCMAC(KEY, b"first")
        first = mac.hexdigest()
        self.assertEqual(first, AESCMAC(KEY, b"first").hexdigest())
        mac.update(b" second")
        self.assertEqual(mac.hexdigest(), AESCMAC(KEY, b"first second").hexdigest())

    def test_invalid_key_lengths_are_rejected(self) -> None:
        for key in (b"", b"a" * 15, b"a" * 17, b"a" * 32):
            with self.subTest(length=len(key)):
                with self.assertRaisesRegex(ValueError, "16 байт"):
                    AESCMAC(key)


class CmacIoTests(unittest.TestCase):
    def test_stream_and_expected_file_parser(self) -> None:
        message = bytes.fromhex(BLOCKS)[:40]
        expected = "dfa66747de9ae63030ca32611497c827"
        self.assertEqual(cmac_stream(BytesIO(message), KEY, chunk_size=9), expected)

        with tempfile.TemporaryDirectory() as directory:
            expected_file = Path(directory) / "expected.cmac"
            expected_file.write_text(
                f"  {expected.upper()}    ignored-file-name.bin  \n",
                encoding="utf-8",
            )
            self.assertEqual(read_expected_cmac(expected_file), bytes.fromhex(expected))

    def test_invalid_stream_chunk_and_expected_value(self) -> None:
        with self.assertRaisesRegex(ValueError, "положительным"):
            cmac_stream(BytesIO(b"data"), KEY, chunk_size=0)

        with tempfile.TemporaryDirectory() as directory:
            expected_file = Path(directory) / "bad.cmac"
            expected_file.write_text("abcd message.bin", encoding="utf-8")
            with self.assertRaisesRegex(MacOperationError, "32 hex-символа"):
                read_expected_cmac(expected_file)


if __name__ == "__main__":
    unittest.main()
