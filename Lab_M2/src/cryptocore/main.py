import os
import sys
from typing import Optional, Tuple

from .cli_parser import parse_args
from .file_io import FileOperationError, read_binary, write_binary
from .modes import decrypt_mode, encrypt_mode


IV_SIZE = 16


def _split_iv(input_data: bytes, provided_iv: Optional[bytes]) -> Tuple[bytes, bytes]:
    if provided_iv is not None:
        return provided_iv, input_data
    if len(input_data) < IV_SIZE:
        raise ValueError("входной файл слишком короткий: отсутствует полный 16-байтный IV")
    return input_data[:IV_SIZE], input_data[IV_SIZE:]


def run(arguments: Optional[list[str]] = None) -> int:
    args = parse_args(arguments)

    try:
        input_data = read_binary(args.input)
        if args.mode == "ecb":
            result = (
                encrypt_mode(input_data, args.key, args.mode)
                if args.encrypt
                else decrypt_mode(input_data, args.key, args.mode)
            )
        elif args.encrypt:
            iv = os.urandom(IV_SIZE)
            ciphertext = encrypt_mode(input_data, args.key, args.mode, iv)
            result = iv + ciphertext
        else:
            iv, ciphertext = _split_iv(input_data, args.iv)
            result = decrypt_mode(ciphertext, args.key, args.mode, iv)
        write_binary(args.output, result)
    except (FileOperationError, ValueError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1

    operation = "Шифрование" if args.encrypt else "Расшифрование"
    print(f"{operation} завершено. Результат: {args.output}")
    return 0


def main() -> None:
    raise SystemExit(run())
