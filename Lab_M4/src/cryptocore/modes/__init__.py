"""Режимы работы блочного шифра."""
from typing import Optional

from .cbc import decrypt_cbc, encrypt_cbc
from .cfb import decrypt_cfb, encrypt_cfb
from .ctr import decrypt_ctr, encrypt_ctr
from .ecb import decrypt_ecb, encrypt_ecb
from .ofb import decrypt_ofb, encrypt_ofb


ENCRYPTORS = {
    "cbc": encrypt_cbc,
    "cfb": encrypt_cfb,
    "ofb": encrypt_ofb,
    "ctr": encrypt_ctr,
}

DECRYPTORS = {
    "cbc": decrypt_cbc,
    "cfb": decrypt_cfb,
    "ofb": decrypt_ofb,
    "ctr": decrypt_ctr,
}


def encrypt_mode(data: bytes, key: bytes, mode: str, iv: Optional[bytes] = None) -> bytes:
    if mode == "ecb":
        return encrypt_ecb(data, key)
    if iv is None:
        raise ValueError(f"для режима {mode.upper()} требуется IV")
    try:
        return ENCRYPTORS[mode](data, key, iv)
    except KeyError as error:
        raise ValueError(f"неподдерживаемый режим: {mode}") from error


def decrypt_mode(data: bytes, key: bytes, mode: str, iv: Optional[bytes] = None) -> bytes:
    if mode == "ecb":
        return decrypt_ecb(data, key)
    if iv is None:
        raise ValueError(f"для режима {mode.upper()} требуется IV")
    try:
        return DECRYPTORS[mode](data, key, iv)
    except KeyError as error:
        raise ValueError(f"неподдерживаемый режим: {mode}") from error
