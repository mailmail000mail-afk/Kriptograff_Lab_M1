from .common import BLOCK_SIZE, new_aes_primitive, validate_iv, xor_bytes


def process_ofb(data: bytes, key: bytes, iv: bytes) -> bytes:
    validate_iv(iv)
    cipher = new_aes_primitive(key)
    feedback = iv
    result = bytearray()

    for offset in range(0, len(data), BLOCK_SIZE):
        block = data[offset : offset + BLOCK_SIZE]
        feedback = cipher.encrypt(feedback)
        result.extend(xor_bytes(block, feedback[: len(block)]))

    return bytes(result)


def encrypt_ofb(data: bytes, key: bytes, iv: bytes) -> bytes:
    return process_ofb(data, key, iv)


def decrypt_ofb(data: bytes, key: bytes, iv: bytes) -> bytes:
    return process_ofb(data, key, iv)
