"""AES-CMAC по NIST SP 800-38B без готовой реализации CMAC."""

from typing import Union

from ..block_cipher import BLOCK_SIZE, new_aes_primitive, validate_key, xor_bytes


BytesLike = Union[bytes, bytearray, memoryview]
RB = 0x87


def _double_block(block: bytes) -> bytes:
    """Умножить 128-битный блок на x в поле GF(2^128)."""
    if len(block) != BLOCK_SIZE:
        raise ValueError("для удвоения требуется 16-байтный блок")
    value = int.from_bytes(block, "big")
    carry = value >> 127
    value = (value << 1) & ((1 << 128) - 1)
    if carry:
        value ^= RB
    return value.to_bytes(BLOCK_SIZE, "big")


def generate_subkeys(key: BytesLike) -> tuple[bytes, bytes]:
    """Получить подключи K1 и K2 по разделу 6.1 NIST SP 800-38B."""
    key_value = bytes(key)
    validate_key(key_value)
    cipher = new_aes_primitive(key_value)
    first = _double_block(cipher.encrypt(bytes(BLOCK_SIZE)))
    second = _double_block(first)
    return first, second


class AESCMAC:
    """Потоковый AES-CMAC с 128-битным ключом и тегом."""

    name = "aes-cmac"
    digest_size = BLOCK_SIZE
    block_size = BLOCK_SIZE

    def __init__(self, key: BytesLike, data: BytesLike = b"") -> None:
        self._key = bytes(key)
        validate_key(self._key)
        self._cipher = new_aes_primitive(self._key)
        self._k1, self._k2 = generate_subkeys(self._key)
        self._chain = bytes(BLOCK_SIZE)
        self._buffer = bytearray()
        if data:
            self.update(data)

    def update(self, data: BytesLike) -> "AESCMAC":
        """Добавить данные, сохраняя последний блок до вызова digest."""
        self._buffer.extend(bytes(data))
        while len(self._buffer) > BLOCK_SIZE:
            block = bytes(self._buffer[:BLOCK_SIZE])
            del self._buffer[:BLOCK_SIZE]
            self._chain = self._cipher.encrypt(xor_bytes(self._chain, block))
        return self

    def copy(self) -> "AESCMAC":
        clone = AESCMAC(self._key)
        clone._chain = self._chain
        clone._buffer = self._buffer.copy()
        return clone

    def digest(self) -> bytes:
        """Вернуть тег, не завершая исходный потоковый объект."""
        state = self.copy()
        if len(state._buffer) == BLOCK_SIZE:
            last_block = xor_bytes(bytes(state._buffer), state._k1)
        else:
            padding_length = BLOCK_SIZE - len(state._buffer) - 1
            padded = bytes(state._buffer) + b"\x80" + bytes(padding_length)
            last_block = xor_bytes(padded, state._k2)
        return state._cipher.encrypt(xor_bytes(state._chain, last_block))

    def hexdigest(self) -> str:
        return self.digest().hex()
