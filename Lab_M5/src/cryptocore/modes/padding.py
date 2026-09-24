from .common import BLOCK_SIZE


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
