import hashlib
import hmac
from io import BytesIO
from pathlib import Path
import tempfile
from unittest import mock
import unittest

from cryptocore.mac import HMACSHA256
from cryptocore.mac.file_mac import (
    MacOperationError,
    constant_time_equal,
    hmac_stream,
    read_expected_hmac,
)


class VirtualLargeStream:
    """Виртуальный поток больше 1 ГиБ без большого файла на диске."""

    def __init__(self, total_size: int) -> None:
        self.remaining = total_size
        self.maximum_request = 0
        self._full_chunk = b"m" * 8192

    def read(self, size: int) -> bytes:
        self.maximum_request = max(self.maximum_request, size)
        if self.remaining == 0:
            return b""
        amount = min(size, self.remaining)
        self.remaining -= amount
        return self._full_chunk if amount == len(self._full_chunk) else b"m" * amount


class CountingMac:
    def __init__(self) -> None:
        self.total = 0

    def update(self, data: bytes) -> None:
        self.total += len(data)

    def hexdigest(self) -> str:
        return f"{self.total:064x}"


class HmacKnownAnswerTests(unittest.TestCase):
    def test_rfc_4231_cases_1_to_4(self) -> None:
        cases = (
            (
                bytes.fromhex("0b" * 20),
                b"Hi There",
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                bytes.fromhex("aa" * 20),
                bytes.fromhex("dd" * 50),
                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            ),
            (
                bytes(range(1, 26)),
                bytes.fromhex("cd" * 50),
                "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            ),
        )
        for number, (key, data, expected) in enumerate(cases, start=1):
            with self.subTest(case=number):
                self.assertEqual(HMACSHA256(key, data).hexdigest(), expected)

    def test_short_equal_and_long_keys_match_reference(self) -> None:
        message = bytes(range(256)) * 3
        for key in (b"k" * 16, b"k" * 64, b"k" * 100):
            with self.subTest(key_length=len(key)):
                expected = hmac.new(key, message, hashlib.sha256).hexdigest()
                self.assertEqual(HMACSHA256(key, message).hexdigest(), expected)

    def test_empty_key_and_empty_message(self) -> None:
        expected = hmac.new(b"", b"", hashlib.sha256).hexdigest()
        self.assertEqual(HMACSHA256(b"").hexdigest(), expected)

    def test_streaming_updates_match_reference(self) -> None:
        key = bytes.fromhex("00112233445566778899aabbccddeeff")
        message = bytes((index * 29 + 7) % 256 for index in range(2049))
        mac = HMACSHA256(key)
        for start in range(0, len(message), 17):
            mac.update(message[start : start + 17])
        self.assertEqual(mac.hexdigest(), hmac.new(key, message, hashlib.sha256).hexdigest())


class HmacIoTests(unittest.TestCase):
    def test_stream_and_expected_file_parser(self) -> None:
        key = b"student key"
        data = b"binary\x00data\xff"
        expected = hmac.new(key, data, hashlib.sha256).hexdigest()
        self.assertEqual(hmac_stream(BytesIO(data), key), expected)

        with tempfile.TemporaryDirectory() as directory:
            expected_file = Path(directory) / "expected.txt"
            expected_file.write_text(
                f"  {expected.upper()}    ignored-file-name.bin  \n",
                encoding="utf-8",
            )
            self.assertEqual(read_expected_hmac(expected_file), bytes.fromhex(expected))

    def test_invalid_expected_hmac_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            expected_file = Path(directory) / "bad.txt"
            expected_file.write_text("not-a-valid-hmac file.bin", encoding="utf-8")
            with self.assertRaisesRegex(MacOperationError, "64 hex-символа"):
                read_expected_hmac(expected_file)

    def test_constant_time_comparison(self) -> None:
        value = bytes.fromhex("ab" * 32)
        self.assertTrue(constant_time_equal(value, value))
        self.assertFalse(constant_time_equal(value, bytes.fromhex("ac" + "ab" * 31)))
        self.assertFalse(constant_time_equal(value, value[:-1]))

    def test_virtual_stream_larger_than_one_gibibyte_is_chunked(self) -> None:
        total_size = 1024 ** 3 + 321
        stream = VirtualLargeStream(total_size)
        counter = CountingMac()
        with mock.patch("cryptocore.mac.file_mac.create_hmac", return_value=counter):
            result = hmac_stream(stream, b"key")
        self.assertEqual(counter.total, total_size)
        self.assertEqual(stream.maximum_request, 8192)
        self.assertEqual(result, f"{total_size:064x}")


if __name__ == "__main__":
    unittest.main()
