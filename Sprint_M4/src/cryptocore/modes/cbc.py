from .common import BLOCK_SIZE, new_aes_primitive, validate_iv, xor_bytes
from .padding import pkcs7_pad, pkcs7_unpad


def encrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    validate_iv(iv)
    cipher = new_aes_primitive(key)
    previous = iv
    result = bytearray()
    padded = pkcs7_pad(data)

    for offset in range(0, len(padded), BLOCK_SIZE):
        block = padded[offset : offset + BLOCK_SIZE]
        encrypted = cipher.encrypt(xor_bytes(block, previous))
        result.extend(encrypted)
        previous = encrypted

    return bytes(result)


def decrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    validate_iv(iv)
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("шифротекст CBC должен состоять из полных 16-байтных блоков")

    cipher = new_aes_primitive(key)
    previous = iv
    result = bytearray()

    for offset in range(0, len(data), BLOCK_SIZE):
        block = data[offset : offset + BLOCK_SIZE]
        result.extend(xor_bytes(cipher.decrypt(block), previous))
        previous = block

    return pkcs7_unpad(bytes(result))
