from ..block_cipher import BLOCK_SIZE, new_aes_primitive, validate_key, xor_bytes


def validate_iv(iv: bytes) -> None:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV должен иметь длину 16 байт")


__all__ = [
    "BLOCK_SIZE",
    "new_aes_primitive",
    "validate_iv",
    "validate_key",
    "xor_bytes",
]
