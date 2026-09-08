from pathlib import Path


class FileOperationError(Exception):
    """Ошибка чтения или записи файла."""


def read_binary(path: Path) -> bytes:
    try:
        with path.open("rb") as input_file:
            return input_file.read()
    except OSError as error:
        raise FileOperationError(f"не удалось прочитать файл '{path}': {error}") from error


def write_binary(path: Path, data: bytes) -> None:
    try:
        with path.open("wb") as output_file:
            output_file.write(data)
    except OSError as error:
        raise FileOperationError(f"не удалось записать файл '{path}': {error}") from error
