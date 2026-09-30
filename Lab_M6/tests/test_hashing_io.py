from io import BytesIO
from pathlib import Path
import tempfile
from unittest import mock
import unittest

from cryptocore.hashing import HashOperationError, hash_file, hash_stream, write_digest_line


class VirtualLargeStream:
    """Поток больше 1 ГиБ без создания большого файла в памяти или на диске."""

    def __init__(self, total_size: int) -> None:
        self.remaining = total_size
        self.maximum_request = 0
        self._full_chunk = b"x" * 8192

    def read(self, size: int) -> bytes:
        self.maximum_request = max(self.maximum_request, size)
        if self.remaining == 0:
            return b""
        amount = min(size, self.remaining)
        self.remaining -= amount
        return self._full_chunk if amount == len(self._full_chunk) else b"x" * amount


class CountingHasher:
    def __init__(self) -> None:
        self.total = 0

    def update(self, data: bytes) -> None:
        self.total += len(data)

    def hexdigest(self) -> str:
        return f"{self.total:064x}"


class HashingIoTests(unittest.TestCase):
    def test_binary_file_and_empty_stream(self) -> None:
        payload = bytes(range(256)) + b"\x00\xffCryptoCore"
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "binary.dat"
            source.write_bytes(payload)
            self.assertEqual(
                hash_file(source, "sha256"),
                "ca19600b6eb4e2bdd051944acb8932c141ef972d640204abe03477170a83e3f6",
            )
        self.assertEqual(
            hash_stream(BytesIO(b""), "sha3-256"),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        )

    def test_output_file_contains_exact_line(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "digest.txt"
            line = "ab" * 32 + " sample.bin"
            write_digest_line(output, line)
            self.assertEqual(output.read_bytes(), (line + "\n").encode("utf-8"))

    def test_missing_input_has_clear_error(self) -> None:
        with self.assertRaisesRegex(HashOperationError, "не удалось прочитать файл"):
            hash_file(Path("definitely-missing-file.bin"), "sha256")

    def test_virtual_stream_larger_than_one_gibibyte_is_chunked(self) -> None:
        total_size = 1024 ** 3 + 123
        stream = VirtualLargeStream(total_size)
        counter = CountingHasher()
        with mock.patch("cryptocore.hashing.create_hasher", return_value=counter):
            digest = hash_stream(stream, "sha256")
        self.assertEqual(counter.total, total_size)
        self.assertEqual(stream.maximum_request, 8192)
        self.assertEqual(digest, f"{total_size:064x}")


if __name__ == "__main__":
    unittest.main()
