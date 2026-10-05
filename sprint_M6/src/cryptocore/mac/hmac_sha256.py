"""Потоковая реализация HMAC-SHA-256 по RFC 2104."""

from typing import Union

from ..hashes import SHA256


BytesLike = Union[bytes, bytearray, memoryview]
BLOCK_SIZE = 64
INNER_PAD = 0x36
OUTER_PAD = 0x5C


def _xor_with_byte(data: bytes, value: int) -> bytes:
    return bytes(byte ^ value for byte in data)


class HMACSHA256:
    """HMAC с ручной SHA-256 из Sprint 4."""

    block_size = BLOCK_SIZE
    digest_size = 32
    name = "hmac-sha256"

    def __init__(self, key: BytesLike, data: BytesLike = b"") -> None:
        processed_key = bytes(key)
        if len(processed_key) > BLOCK_SIZE:
            processed_key = SHA256(processed_key).digest()
        processed_key = processed_key.ljust(BLOCK_SIZE, b"\x00")

        self._inner = SHA256(_xor_with_byte(processed_key, INNER_PAD))
        self._outer = SHA256(_xor_with_byte(processed_key, OUTER_PAD))
        if data:
            self.update(data)

    def copy(self) -> "HMACSHA256":
        other = object.__new__(HMACSHA256)
        other._inner = self._inner.copy()
        other._outer = self._outer.copy()
        return other

    def update(self, data: BytesLike) -> "HMACSHA256":
        self._inner.update(data)
        return self

    def digest(self) -> bytes:
        outer = self._outer.copy()
        outer.update(self._inner.digest())
        return outer.digest()

    def hexdigest(self) -> str:
        return self.digest().hex()
