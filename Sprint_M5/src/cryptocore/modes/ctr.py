from .common import BLOCK_SIZE, new_aes_primitive, validate_iv, xor_bytes


COUNTER_MODULUS = 1 << (BLOCK_SIZE * 8)


def process_ctr(data: bytes, key: bytes, iv: bytes) -> bytes:
    validate_iv(iv)
    cipher = new_aes_primitive(key)
    counter = int.from_bytes(iv, byteorder="big")
    result = bytearray()

    for offset in range(0, len(data), BLOCK_SIZE):
        block = data[offset : offset + BLOCK_SIZE]
        counter_block = counter.to_bytes(BLOCK_SIZE, byteorder="big")
        keystream = cipher.encrypt(counter_block)
        result.extend(xor_bytes(block, keystream[: len(block)]))
        counter = (counter + 1) % COUNTER_MODULUS

    return bytes(result)


def encrypt_ctr(data: bytes, key: bytes, iv: bytes) -> bytes:
    return process_ctr(data, key, iv)


def decrypt_ctr(data: bytes, key: bytes, iv: bytes) -> bytes:
    return process_ctr(data, key, iv)
