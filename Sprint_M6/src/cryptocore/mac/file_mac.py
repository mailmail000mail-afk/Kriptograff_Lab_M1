"""Потоковое вычисление и проверка HMAC для файлов."""

from itertools import zip_longest
from pathlib import Path
from typing import BinaryIO, Protocol

from .hmac_sha256 import HMACSHA256


DEFAULT_CHUNK_SIZE = 8192


class MacOperationError(Exception):
    """Ошибка чтения данных для HMAC."""


class MacLike(Protocol):
    def update(self, data: bytes) -> object:
        ...

    def hexdigest(self) -> str:
        ...


def create_hmac(key: bytes) -> MacLike:
    return HMACSHA256(key)


def hmac_stream(
    input_stream: BinaryIO,
    key: bytes,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> str:
    if chunk_size <= 0:
        raise ValueError("размер блока чтения должен быть положительным")

    mac = create_hmac(key)
    while True:
        chunk = input_stream.read(chunk_size)
        if not chunk:
            break
        mac.update(chunk)
    return mac.hexdigest()


def hmac_file(path: Path, key: bytes) -> str:
    try:
        with path.open("rb") as input_file:
            return hmac_stream(input_file, key)
    except OSError as error:
        raise MacOperationError(f"не удалось прочитать файл '{path}': {error}") from error


def read_expected_hmac(path: Path) -> bytes:
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise MacOperationError(
            f"не удалось прочитать файл HMAC '{path}': {error}"
        ) from error

    parts = content.split()
    if not parts:
        raise MacOperationError(f"файл HMAC '{path}' пуст")

    value = parts[0]
    if len(value) != 64:
        raise MacOperationError("ожидаемый HMAC должен содержать 64 hex-символа")
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise MacOperationError(
            "ожидаемый HMAC должен быть шестнадцатеричной строкой"
        ) from error


def constant_time_equal(left: bytes, right: bytes) -> bool:
    difference = len(left) ^ len(right)
    for left_byte, right_byte in zip_longest(left, right, fillvalue=0):
        difference |= left_byte ^ right_byte
    return difference == 0
