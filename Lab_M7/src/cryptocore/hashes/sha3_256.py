"""Потоковая реализация SHA3-256 по FIPS 202 без готовой хеш-функции."""

from typing import Union


BytesLike = Union[bytes, bytearray, memoryview]
MASK64 = 0xFFFFFFFFFFFFFFFF

_ROTATION_OFFSETS = (
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
)

_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008,
)


def _rotate_left(value: int, count: int) -> int:
    if count == 0:
        return value
    return ((value << count) | (value >> (64 - count))) & MASK64


def _keccak_f1600(state: list[int]) -> None:
    for round_constant in _ROUND_CONSTANTS:
        columns = [
            state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
            for x in range(5)
        ]
        differences = [
            columns[(x - 1) % 5] ^ _rotate_left(columns[(x + 1) % 5], 1)
            for x in range(5)
        ]
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] ^= differences[x]

        moved = [0] * 25
        for y in range(5):
            for x in range(5):
                destination_x = y
                destination_y = (2 * x + 3 * y) % 5
                lane = state[x + 5 * y]
                moved[destination_x + 5 * destination_y] = _rotate_left(
                    lane, _ROTATION_OFFSETS[x + 5 * y]
                )

        for y in range(5):
            row = 5 * y
            for x in range(5):
                state[row + x] = (
                    moved[row + x]
                    ^ ((~moved[row + (x + 1) % 5]) & moved[row + (x + 2) % 5])
                ) & MASK64

        state[0] ^= round_constant


class SHA3_256:
    """Потоковый интерфейс SHA3-256 с методами update, digest и hexdigest."""

    block_size = 136
    digest_size = 32
    name = "sha3_256"

    def __init__(self, data: BytesLike = b"") -> None:
        self._state = [0] * 25
        self._buffer = bytearray()
        if data:
            self.update(data)

    def copy(self) -> "SHA3_256":
        other = SHA3_256()
        other._state = self._state.copy()
        other._buffer = self._buffer.copy()
        return other

    def update(self, data: BytesLike) -> "SHA3_256":
        self._buffer.extend(bytes(data))
        complete_length = len(self._buffer) - len(self._buffer) % self.block_size
        for start in range(0, complete_length, self.block_size):
            self._absorb_block(bytes(self._buffer[start : start + self.block_size]))
        if complete_length:
            del self._buffer[:complete_length]
        return self

    def _absorb_block(self, block: bytes) -> None:
        for lane_index in range(self.block_size // 8):
            start = lane_index * 8
            self._state[lane_index] ^= int.from_bytes(block[start : start + 8], "little")
        _keccak_f1600(self._state)

    def digest(self) -> bytes:
        final = self.copy()
        padding_length = self.block_size - len(final._buffer)
        padding = bytearray(padding_length)
        padding[0] = 0x06
        padding[-1] |= 0x80
        final.update(padding)

        output = bytearray()
        for lane in final._state[: self.block_size // 8]:
            output.extend(lane.to_bytes(8, "little"))
        return bytes(output[: self.digest_size])

    def hexdigest(self) -> str:
        return self.digest().hex()
