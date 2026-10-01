"""Общий AES-128 примитив для режимов шифрования и AES-CMAC."""

from Crypto.Cipher import AES


BLOCK_SIZE = 16


def validate_key(key: bytes) -> None:
    if len(key) != BLOCK_SIZE:
        raise ValueError("ключ AES-128 должен иметь длину 16 байт")


def new_aes_primitive(key: bytes):
    """Создать блочный AES-примитив без готового режима CMAC."""
    validate_key(key)
    return AES.new(key, AES.MODE_ECB)


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("для XOR требуются последовательности одинаковой длины")
    return bytes(a ^ b for a, b in zip(left, right))
