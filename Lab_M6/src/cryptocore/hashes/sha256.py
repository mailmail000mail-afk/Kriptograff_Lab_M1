"""Потоковая реализация SHA-256 по FIPS 180-4 без готовой хеш-функции."""

from typing import Union


BytesLike = Union[bytes, bytearray, memoryview]
MASK32 = 0xFFFFFFFF

_INITIAL_HASH = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)

_ROUND_CONSTANTS = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)


def _rotate_right(value: int, count: int) -> int:
    return ((value >> count) | (value << (32 - count))) & MASK32


class SHA256:
    """Потоковый интерфейс SHA-256 с методами update, digest и hexdigest."""

    block_size = 64
    digest_size = 32
    name = "sha256"

    def __init__(self, data: BytesLike = b"") -> None:
        self._hash = list(_INITIAL_HASH)
        self._buffer = bytearray()
        self._message_length = 0
        if data:
            self.update(data)

    def copy(self) -> "SHA256":
        other = SHA256()
        other._hash = self._hash.copy()
        other._buffer = self._buffer.copy()
        other._message_length = self._message_length
        return other

    def update(self, data: BytesLike) -> "SHA256":
        chunk = bytes(data)
        self._message_length += len(chunk)
        self._buffer.extend(chunk)

        complete_length = len(self._buffer) - len(self._buffer) % self.block_size
        for start in range(0, complete_length, self.block_size):
            self._process_block(bytes(self._buffer[start : start + self.block_size]))
        if complete_length:
            del self._buffer[:complete_length]
        return self

    def _process_block(self, block: bytes) -> None:
        words = [
            int.from_bytes(block[index : index + 4], "big")
            for index in range(0, self.block_size, 4)
        ]
        for index in range(16, 64):
            previous_15 = words[index - 15]
            previous_2 = words[index - 2]
            sigma0 = (
                _rotate_right(previous_15, 7)
                ^ _rotate_right(previous_15, 18)
                ^ (previous_15 >> 3)
            )
            sigma1 = (
                _rotate_right(previous_2, 17)
                ^ _rotate_right(previous_2, 19)
                ^ (previous_2 >> 10)
            )
            words.append(
                (words[index - 16] + sigma0 + words[index - 7] + sigma1) & MASK32
            )

        a, b, c, d, e, f, g, h = self._hash
        for index in range(64):
            sum1 = _rotate_right(e, 6) ^ _rotate_right(e, 11) ^ _rotate_right(e, 25)
            choice = (e & f) ^ ((~e) & g)
            temporary1 = (h + sum1 + choice + _ROUND_CONSTANTS[index] + words[index]) & MASK32
            sum0 = _rotate_right(a, 2) ^ _rotate_right(a, 13) ^ _rotate_right(a, 22)
            majority = (a & b) ^ (a & c) ^ (b & c)
            temporary2 = (sum0 + majority) & MASK32

            h = g
            g = f
            f = e
            e = (d + temporary1) & MASK32
            d = c
            c = b
            b = a
            a = (temporary1 + temporary2) & MASK32

        working = (a, b, c, d, e, f, g, h)
        self._hash = [
            (current + addition) & MASK32
            for current, addition in zip(self._hash, working)
        ]

    def digest(self) -> bytes:
        final = self.copy()
        bit_length = (final._message_length * 8) & 0xFFFFFFFFFFFFFFFF
        zero_count = (56 - (final._message_length + 1) % 64) % 64
        final.update(b"\x80" + b"\x00" * zero_count + bit_length.to_bytes(8, "big"))
        return b"".join(word.to_bytes(4, "big") for word in final._hash)

    def hexdigest(self) -> str:
        return self.digest().hex()
