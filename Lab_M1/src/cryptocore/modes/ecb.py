from Crypto.Cipher import AES


BLOCK_SIZE = 16


def _validate_key(key: bytes) -> None:
    if len(key) != BLOCK_SIZE:
        raise ValueError("ключ AES-128 должен иметь длину 16 байт")


def pkcs7_pad(data: bytes) -> bytes:
    padding_length = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_length]) * padding_length


def pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("некорректная длина зашифрованных данных")

    padding_length = data[-1]
    if padding_length < 1 or padding_length > BLOCK_SIZE:
        raise ValueError("неверное дополнение PKCS#7")
    if data[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValueError("неверное дополнение PKCS#7")

    return data[:-padding_length]


def _process_blocks(data: bytes, key: bytes, encrypt: bool) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
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
    _validate_key(key)
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("длина данных должна быть кратна 16 байтам")
    return _process_blocks(data, key, encrypt=True)


def encrypt_ecb(data: bytes, key: bytes) -> bytes:
    _validate_key(key)
    return _process_blocks(pkcs7_pad(data), key, encrypt=True)


def decrypt_ecb(data: bytes, key: bytes) -> bytes:
    _validate_key(key)
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("некорректная длина зашифрованных данных")
    decrypted = _process_blocks(data, key, encrypt=False)
    return pkcs7_unpad(decrypted)
