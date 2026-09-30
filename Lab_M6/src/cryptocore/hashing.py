"""Потоковое вычисление хеша для файлов и стандартного ввода."""

from pathlib import Path
from typing import BinaryIO, Protocol

from .hashes import SHA256, SHA3_256


DEFAULT_CHUNK_SIZE = 8192


class HashOperationError(Exception):
    """Ошибка чтения входа или записи результата хеширования."""


class Hasher(Protocol):
    def update(self, data: bytes) -> object:
        ...

    def hexdigest(self) -> str:
        ...


def create_hasher(algorithm: str) -> Hasher:
    if algorithm == "sha256":
        return SHA256()
    if algorithm == "sha3-256":
        return SHA3_256()
    raise ValueError(f"неподдерживаемый алгоритм хеширования: {algorithm}")


def hash_stream(
    input_stream: BinaryIO,
    algorithm: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> str:
    if chunk_size <= 0:
        raise ValueError("размер блока чтения должен быть положительным")

    hasher = create_hasher(algorithm)
    while True:
        chunk = input_stream.read(chunk_size)
        if not chunk:
            break
        hasher.update(chunk)
    return hasher.hexdigest()


def hash_file(path: Path, algorithm: str) -> str:
    try:
        with path.open("rb") as input_file:
            return hash_stream(input_file, algorithm)
    except OSError as error:
        raise HashOperationError(f"не удалось прочитать файл '{path}': {error}") from error


def write_digest_line(path: Path, line: str) -> None:
    try:
        with path.open("w", encoding="utf-8", newline="\n") as output_file:
            output_file.write(line + "\n")
    except OSError as error:
        raise HashOperationError(f"не удалось записать файл '{path}': {error}") from error
