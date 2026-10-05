"""Cryptographically secure random bytes for keys and IVs."""

import os
from typing import Optional


class CSPRNGError(RuntimeError):
    """The operating system could not provide secure random bytes."""


def generate_random_bytes(num_bytes: int) -> bytes:
    """Return *num_bytes* from the operating system CSPRNG."""
    if isinstance(num_bytes, bool) or not isinstance(num_bytes, int):
        raise TypeError("размер случайной последовательности должен быть целым числом")
    if num_bytes < 0:
        raise ValueError("размер случайной последовательности не может быть отрицательным")

    try:
        random_bytes = os.urandom(num_bytes)
    except OSError as error:
        raise CSPRNGError(
            f"операционная система не смогла предоставить случайные данные: {error}"
        ) from error

    if len(random_bytes) != num_bytes:
        raise CSPRNGError(
            "операционная система вернула неверное количество случайных байтов"
        )
    return random_bytes


def weak_key_reason(key: bytes) -> Optional[str]:
    """Describe a simple, visibly weak AES-128 key pattern, if detected."""
    if len(set(key)) == 1:
        return "все байты ключа одинаковы"
    if key == bytes(range(16)) or key == bytes(range(15, -1, -1)):
        return "байты ключа образуют последовательность"
    return None
