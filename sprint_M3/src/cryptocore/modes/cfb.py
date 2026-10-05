from .common import BLOCK_SIZE, new_aes_primitive, validate_iv, xor_bytes


def encrypt_cfb(data: bytes, key: bytes, iv: bytes) -> bytes:
    validate_iv(iv)
    cipher = new_aes_primitive(key)
    feedback = iv
    result = bytearray()

    for offset in range(0, len(data), BLOCK_SIZE):
        block = data[offset : offset + BLOCK_SIZE]
        keystream = cipher.encrypt(feedback)
        encrypted = xor_bytes(block, keystream[: len(block)])
        result.extend(encrypted)
        feedback = encrypted

    return bytes(result)


def decrypt_cfb(data: bytes, key: bytes, iv: bytes) -> bytes:
    validate_iv(iv)
    cipher = new_aes_primitive(key)
    feedback = iv
    result = bytearray()

    for offset in range(0, len(data), BLOCK_SIZE):
        block = data[offset : offset + BLOCK_SIZE]
        keystream = cipher.encrypt(feedback)
        result.extend(xor_bytes(block, keystream[: len(block)]))
        feedback = block

    return bytes(result)
