import sys

from .cli_parser import parse_args
from .file_io import FileOperationError, read_binary, write_binary
from .modes.ecb import decrypt_ecb, encrypt_ecb


def run(arguments: list[str] | None = None) -> int:
    args = parse_args(arguments)

    try:
        input_data = read_binary(args.input)
        if args.encrypt:
            result = encrypt_ecb(input_data, args.key)
        else:
            result = decrypt_ecb(input_data, args.key)
        write_binary(args.output, result)
    except (FileOperationError, ValueError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1

    operation = "Шифрование" if args.encrypt else "Расшифрование"
    print(f"{operation} завершено. Результат: {args.output}")
    return 0


def main() -> None:
    raise SystemExit(run())
