"""AES-GCM по NIST SP 800-38D поверх AES-примитива прошлых спринтов."""

from typing import BinaryIO, Iterable, Optional, Union

from ..authentication import AuthenticationError
from ..csprng import generate_random_bytes
from ..mac.file_mac import constant_time_equal
from .common import BLOCK_SIZE, new_aes_primitive, xor_bytes


BytesLike = Union[bytes, bytearray, memoryview]
NONCE_SIZE = 12
TAG_SIZE = 16
DEFAULT_CHUNK_SIZE = 8192
_REDUCTION_CONSTANT = 0xE1000000000000000000000000000000
_MAX_64_BIT_LENGTH = (1 << 64) - 1


def multiply_gf128(x: int, y: int) -> int:
    """Умножить два элемента GF(2^128) для полинома GCM."""
    if not 0 <= x < (1 << 128) or not 0 <= y < (1 << 128):
        raise ValueError("элемент GF(2^128) должен занимать не более 128 бит")

    product = 0
    value = y
    for bit_index in range(127, -1, -1):
        if (x >> bit_index) & 1:
            product ^= value
        if value & 1:
            value = (value >> 1) ^ _REDUCTION_CONSTANT
        else:
            value >>= 1
    return product


class GHASH:
    """Потоковый GHASH, который хранит не более одного неполного блока."""

    def __init__(self, hash_subkey: bytes) -> None:
        if len(hash_subkey) != BLOCK_SIZE:
            raise ValueError("подключ GHASH должен иметь длину 16 байт")
        self._h = int.from_bytes(hash_subkey, "big")
        self._value = 0
        self._aad_buffer = bytearray()
        self._ciphertext_buffer = bytearray()
        self._aad_length = 0
        self._ciphertext_length = 0
        self._aad_finished = False
        self._digest: Optional[bytes] = None

    def _process_block(self, block: bytes) -> None:
        self._value = multiply_gf128(
            self._value ^ int.from_bytes(block, "big"), self._h
        )

    def _drain_full_blocks(self, buffer: bytearray) -> None:
        complete = len(buffer) - len(buffer) % BLOCK_SIZE
        for offset in range(0, complete, BLOCK_SIZE):
            self._process_block(bytes(buffer[offset : offset + BLOCK_SIZE]))
        if complete:
            del buffer[:complete]

    @staticmethod
    def _checked_length(current: int, addition: int) -> int:
        result = current + addition
        if result * 8 > _MAX_64_BIT_LENGTH:
            raise ValueError("длина данных GCM не помещается в 64-битное поле")
        return result

    def update_aad(self, data: BytesLike) -> "GHASH":
        if self._aad_finished:
            raise ValueError("AAD нельзя добавлять после начала шифротекста")
        if self._digest is not None:
            raise ValueError("GHASH уже завершён")
        chunk = bytes(data)
        self._aad_length = self._checked_length(self._aad_length, len(chunk))
        self._aad_buffer.extend(chunk)
        self._drain_full_blocks(self._aad_buffer)
        return self

    def finish_aad(self) -> None:
        if self._aad_finished:
            return
        if self._aad_buffer:
            padded = bytes(self._aad_buffer).ljust(BLOCK_SIZE, b"\x00")
            self._process_block(padded)
            self._aad_buffer.clear()
        self._aad_finished = True

    def update_ciphertext(self, data: BytesLike) -> "GHASH":
        if self._digest is not None:
            raise ValueError("GHASH уже завершён")
        self.finish_aad()
        chunk = bytes(data)
        self._ciphertext_length = self._checked_length(
            self._ciphertext_length, len(chunk)
        )
        self._ciphertext_buffer.extend(chunk)
        self._drain_full_blocks(self._ciphertext_buffer)
        return self

    def digest(self) -> bytes:
        if self._digest is not None:
            return self._digest
        self.finish_aad()
        if self._ciphertext_buffer:
            padded = bytes(self._ciphertext_buffer).ljust(BLOCK_SIZE, b"\x00")
            self._process_block(padded)
            self._ciphertext_buffer.clear()
        lengths = (self._aad_length * 8).to_bytes(8, "big") + (
            self._ciphertext_length * 8
        ).to_bytes(8, "big")
        self._process_block(lengths)
        self._digest = self._value.to_bytes(BLOCK_SIZE, "big")
        return self._digest


def update_ghash_from_stream(
    accumulator: object,
    input_stream: BinaryIO,
    *,
    aad: bool,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> int:
    """Передать поток в GHASH частями и вернуть число обработанных байтов."""
    if chunk_size <= 0:
        raise ValueError("размер блока чтения должен быть положительным")
    update = accumulator.update_aad if aad else accumulator.update_ciphertext
    total = 0
    while True:
        chunk = input_stream.read(chunk_size)
        if not chunk:
            break
        update(chunk)
        total += len(chunk)
    return total


def _chunks(data: BytesLike) -> Iterable[memoryview]:
    view = memoryview(data)
    for offset in range(0, len(view), DEFAULT_CHUNK_SIZE):
        yield view[offset : offset + DEFAULT_CHUNK_SIZE]


class GCM:
    """AES-GCM с 128-битным тегом и объединённым форматом nonce || C || tag."""

    def __init__(self, key: bytes, nonce: Optional[bytes] = None) -> None:
        self._cipher = new_aes_primitive(key)
        self.nonce = generate_random_bytes(NONCE_SIZE) if nonce is None else bytes(nonce)
        if not self.nonce:
            raise ValueError("nonce GCM не может быть пустым")
        self._hash_subkey = self._cipher.encrypt(bytes(BLOCK_SIZE))

    def _ghash(self, aad: BytesLike, ciphertext: BytesLike) -> bytes:
        accumulator = GHASH(self._hash_subkey)
        for chunk in _chunks(aad):
            accumulator.update_aad(chunk)
        for chunk in _chunks(ciphertext):
            accumulator.update_ciphertext(chunk)
        return accumulator.digest()

    def _initial_counter(self, nonce: bytes) -> bytes:
        if len(nonce) == NONCE_SIZE:
            return nonce + b"\x00\x00\x00\x01"
        return self._ghash(b"", nonce)

    @staticmethod
    def _increment_counter(counter: bytes) -> bytes:
        prefix = counter[:12]
        value = (int.from_bytes(counter[12:], "big") + 1) & 0xFFFFFFFF
        return prefix + value.to_bytes(4, "big")

    def _gctr(self, initial_counter: bytes, data: BytesLike) -> bytes:
        if len(initial_counter) != BLOCK_SIZE:
            raise ValueError("счётчик GCM должен иметь длину 16 байт")
        source = memoryview(data)
        if len(source) > ((1 << 32) - 2) * BLOCK_SIZE:
            raise ValueError("сообщение слишком длинное для одного nonce GCM")

        counter = initial_counter
        result = bytearray()
        for offset in range(0, len(source), BLOCK_SIZE):
            block = bytes(source[offset : offset + BLOCK_SIZE])
            keystream = self._cipher.encrypt(counter)
            result.extend(xor_bytes(block, keystream[: len(block)]))
            counter = self._increment_counter(counter)
        return bytes(result)

    def encrypt_detached(
        self, plaintext: BytesLike, aad: BytesLike = b""
    ) -> tuple[bytes, bytes]:
        j0 = self._initial_counter(self.nonce)
        ciphertext = self._gctr(self._increment_counter(j0), plaintext)
        authentication = self._ghash(aad, ciphertext)
        tag = self._gctr(j0, authentication)
        return ciphertext, tag

    def encrypt(self, plaintext: BytesLike, aad: BytesLike = b"") -> bytes:
        ciphertext, tag = self.encrypt_detached(plaintext, aad)
        return self.nonce + ciphertext + tag

    def decrypt_detached(
        self,
        ciphertext_and_tag: BytesLike,
        aad: BytesLike = b"",
        nonce: Optional[bytes] = None,
    ) -> bytes:
        data = bytes(ciphertext_and_tag)
        if len(data) < TAG_SIZE:
            raise ValueError("данные GCM короче 16-байтного тега")
        actual_nonce = self.nonce if nonce is None else bytes(nonce)
        if not actual_nonce:
            raise ValueError("nonce GCM не может быть пустым")
        ciphertext, supplied_tag = data[:-TAG_SIZE], data[-TAG_SIZE:]
        j0 = self._initial_counter(actual_nonce)
        authentication = self._ghash(aad, ciphertext)
        expected_tag = self._gctr(j0, authentication)
        if not constant_time_equal(expected_tag, supplied_tag):
            raise AuthenticationError(
                "Authentication failed: AAD mismatch or ciphertext/tag tampered"
            )
        return self._gctr(self._increment_counter(j0), ciphertext)

    def decrypt(self, data: BytesLike, aad: BytesLike = b"") -> bytes:
        combined = bytes(data)
        nonce_size = len(self.nonce)
        if len(combined) < nonce_size + TAG_SIZE:
            raise ValueError("данные GCM не содержат полный nonce и тег")
        nonce = combined[:nonce_size]
        return self.decrypt_detached(combined[nonce_size:], aad, nonce)
