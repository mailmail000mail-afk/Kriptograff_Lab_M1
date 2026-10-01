"""Учебная HMAC-схема для построения иерархии ключей."""

from typing import Union

from ..mac import HMACSHA256


BytesLike = Union[bytes, bytearray, memoryview]
HASH_SIZE = 32
MAX_BLOCK_INDEX = (1 << 32) - 1


def derive_key(
    master_key: BytesLike,
    context: Union[str, BytesLike],
    length: int = 32,
) -> bytes:
    """Детерминированно получить ключ как HMAC(master, context || counter)."""
    master = bytes(master_key)
    if not master:
        raise ValueError("мастер-ключ не может быть пустым")
    context_value = context.encode("utf-8") if isinstance(context, str) else bytes(context)
    if not context_value:
        raise ValueError("контекст назначения ключа не может быть пустым")
    if isinstance(length, bool) or not isinstance(length, int) or length < 1:
        raise ValueError("длина производного ключа должна быть положительной")

    blocks_needed = (length + HASH_SIZE - 1) // HASH_SIZE
    if blocks_needed > MAX_BLOCK_INDEX:
        raise ValueError("запрошенная длина ключа превышает предел счётчика")

    template = HMACSHA256(master)
    derived = bytearray()
    for counter in range(1, blocks_needed + 1):
        mac = template.copy()
        mac.update(context_value + counter.to_bytes(4, "big"))
        derived.extend(mac.digest())
    return bytes(derived[:length])
