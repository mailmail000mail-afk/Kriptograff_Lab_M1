"""PBKDF2-HMAC-SHA256 по RFC 8018."""

import string
from typing import Optional, Union

from ..csprng import generate_random_bytes
from ..mac import HMACSHA256


BytesLike = Union[bytes, bytearray, memoryview]
HASH_SIZE = 32
SALT_SIZE = 16
MAX_BLOCK_INDEX = (1 << 32) - 1


def _password_bytes(password: Union[str, BytesLike]) -> bytes:
    if isinstance(password, str):
        return password.encode("utf-8")
    return bytes(password)


def _salt_bytes(salt: Union[str, BytesLike]) -> bytes:
    if not isinstance(salt, str):
        return bytes(salt)
    is_hex = len(salt) % 2 == 0 and all(char in string.hexdigits for char in salt)
    return bytes.fromhex(salt) if is_hex else salt.encode("utf-8")


def _prf(template: HMACSHA256, data: bytes) -> bytes:
    mac = template.copy()
    mac.update(data)
    return mac.digest()


def pbkdf2_hmac_sha256(
    password: Union[str, BytesLike],
    salt: Union[str, BytesLike],
    iterations: int,
    dklen: int,
) -> bytes:
    """Выработать ключ заданной длины с помощью PBKDF2-HMAC-SHA256."""
    if isinstance(iterations, bool) or not isinstance(iterations, int) or iterations < 1:
        raise ValueError("число итераций PBKDF2 должно быть положительным")
    if isinstance(dklen, bool) or not isinstance(dklen, int) or dklen < 1:
        raise ValueError("длина производного ключа должна быть положительной")

    blocks_needed = (dklen + HASH_SIZE - 1) // HASH_SIZE
    if blocks_needed > MAX_BLOCK_INDEX:
        raise ValueError("запрошенная длина ключа превышает предел PBKDF2")

    password_value = _password_bytes(password)
    salt_value = _salt_bytes(salt)
    template = HMACSHA256(password_value)
    derived = bytearray()

    for block_index in range(1, blocks_needed + 1):
        current = _prf(template, salt_value + block_index.to_bytes(4, "big"))
        combined = int.from_bytes(current, "big")
        for _ in range(1, iterations):
            current = _prf(template, current)
            combined ^= int.from_bytes(current, "big")
        derived.extend(combined.to_bytes(HASH_SIZE, "big"))

    return bytes(derived[:dklen])


def derive_password_key(
    password: Union[str, BytesLike],
    salt: Optional[BytesLike] = None,
    iterations: int = 100_000,
    length: int = 32,
) -> tuple[bytes, bytes]:
    """Выработать ключ и вернуть фактически использованную соль."""
    actual_salt = generate_random_bytes(SALT_SIZE) if salt is None else bytes(salt)
    key = pbkdf2_hmac_sha256(password, actual_salt, iterations, length)
    return key, actual_salt
