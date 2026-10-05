"""Учебная схема Encrypt-then-MAC на AES-CTR и HMAC-SHA-256."""

from typing import Optional, Union

from ..authentication import AuthenticationError
from ..csprng import generate_random_bytes
from ..mac.file_mac import constant_time_equal
from ..mac.hmac_sha256 import HMACSHA256
from ..modes.ctr import decrypt_ctr, encrypt_ctr


BytesLike = Union[bytes, bytearray, memoryview]
IV_SIZE = 16
TAG_SIZE = 32


def _derive_keys(master_key: bytes) -> tuple[bytes, bytes]:
    if not master_key:
        raise ValueError("мастер-ключ Encrypt-then-MAC не может быть пустым")
    encryption_key = HMACSHA256(
        master_key, b"CryptoCore Sprint 6 encryption key"
    ).digest()[:16]
    mac_key = HMACSHA256(master_key, b"CryptoCore Sprint 6 MAC key").digest()
    return encryption_key, mac_key


class EncryptThenMAC:
    """Сначала шифрует AES-CTR, затем проверяет HMAC до расшифрования."""

    def __init__(self, master_key: bytes, iv: Optional[bytes] = None) -> None:
        self.encryption_key, self.mac_key = _derive_keys(bytes(master_key))
        self.iv = generate_random_bytes(IV_SIZE) if iv is None else bytes(iv)
        if len(self.iv) != IV_SIZE:
            raise ValueError("IV Encrypt-then-MAC должен иметь длину 16 байт")

    def encrypt(self, plaintext: BytesLike, aad: BytesLike = b"") -> bytes:
        ciphertext = encrypt_ctr(bytes(plaintext), self.encryption_key, self.iv)
        authenticated_ciphertext = self.iv + ciphertext
        tag = HMACSHA256(
            self.mac_key, authenticated_ciphertext + bytes(aad)
        ).digest()
        return authenticated_ciphertext + tag

    def decrypt(self, data: BytesLike, aad: BytesLike = b"") -> bytes:
        combined = bytes(data)
        if len(combined) < IV_SIZE + TAG_SIZE:
            raise ValueError("данные Encrypt-then-MAC не содержат полный IV и тег")
        iv = combined[:IV_SIZE]
        ciphertext = combined[IV_SIZE:-TAG_SIZE]
        supplied_tag = combined[-TAG_SIZE:]
        expected_tag = HMACSHA256(
            self.mac_key, combined[:-TAG_SIZE] + bytes(aad)
        ).digest()
        if not constant_time_equal(expected_tag, supplied_tag):
            raise AuthenticationError(
                "Authentication failed: AAD mismatch or ciphertext/tag tampered"
            )
        return decrypt_ctr(ciphertext, self.encryption_key, iv)
