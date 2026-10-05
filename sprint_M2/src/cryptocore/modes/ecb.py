from .common import BLOCK_SIZE, new_aes_primitive, validate_key
from .padding import pkcs7_pad, pkcs7_unpad


def _process_blocks(data: bytes, key: bytes, encrypt: bool) -> bytes:
    cipher = new_aes_primitive(key)
    result = bytearray()

    # Логика ECB реализована явно: каждый 16-байтный блок обрабатывается отдельно.
    for offset in range(0, len(data), BLOCK_SIZE):
        block = data[offset : offset + BLOCK_SIZE]
        if encrypt:
            result.extend(cipher.encrypt(block))
        else:
            result.extend(cipher.decrypt(block))

    return bytes(result)


def encrypt_blocks(data: bytes, key: bytes) -> bytes:
    """Шифрует полные блоки без дополнения; используется для проверки ECB."""
    validate_key(key)
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("длина данных должна быть кратна 16 байтам")
    return _process_blocks(data, key, encrypt=True)


def encrypt_ecb(data: bytes, key: bytes) -> bytes:
    validate_key(key)
    return _process_blocks(pkcs7_pad(data), key, encrypt=True)


def decrypt_ecb(data: bytes, key: bytes) -> bytes:
    validate_key(key)
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("некорректная длина зашифрованных данных")
    decrypted = _process_blocks(data, key, encrypt=False)
    return pkcs7_unpad(decrypted)
