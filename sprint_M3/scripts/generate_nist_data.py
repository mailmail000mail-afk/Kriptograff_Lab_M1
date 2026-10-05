"""Generate a binary sample from CryptoCore CSPRNG for NIST STS."""

import argparse
import hashlib
from pathlib import Path
from typing import Optional

from cryptocore.csprng import CSPRNGError, generate_random_bytes


DEFAULT_SIZE_MIB = 10
CHUNK_SIZE = 64 * 1024


def write_random_file(path: Path, total_bytes: int) -> str:
    """Write exactly *total_bytes* and return its SHA-256 digest."""
    if total_bytes <= 0:
        raise ValueError("размер файла должен быть положительным")

    digest = hashlib.sha256()
    written = 0
    try:
        with path.open("wb") as output:
            while written < total_bytes:
                chunk = generate_random_bytes(min(CHUNK_SIZE, total_bytes - written))
                output.write(chunk)
                digest.update(chunk)
                written += len(chunk)
    except OSError as error:
        raise OSError(f"не удалось записать файл '{path}': {error}") from error
    return digest.hexdigest()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Подготовка бинарной выборки CryptoCore для NIST STS."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("nist_test_data.bin"),
        help="выходной бинарный файл",
    )
    parser.add_argument(
        "--size-mib",
        type=int,
        default=DEFAULT_SIZE_MIB,
        help="размер выборки в мебибайтах (по умолчанию 10)",
    )
    return parser


def main(arguments: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(arguments)
    if args.size_mib <= 0:
        raise SystemExit("Ошибка: --size-mib должен быть положительным")

    total_bytes = args.size_mib * 1024 * 1024
    try:
        digest = write_random_file(args.output, total_bytes)
    except (CSPRNGError, OSError, ValueError) as error:
        raise SystemExit(f"Ошибка: {error}") from error

    print(f"Создано байтов: {total_bytes}")
    print(f"Файл: {args.output}")
    print(f"SHA-256: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
