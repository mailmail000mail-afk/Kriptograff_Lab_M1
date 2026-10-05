import sys
from typing import Optional, Tuple

from .cli_parser import parse_args
from .csprng import CSPRNGError, generate_random_bytes, weak_key_reason
from .file_io import FileOperationError, read_binary, write_binary
from .hashing import HashOperationError, hash_file, hash_stream, write_digest_line


IV_SIZE = 16
KEY_SIZE = 16


def _run_digest(args: object) -> int:
    input_path = args.input
    input_label = str(input_path)
    try:
        if input_label == "-":
            digest = hash_stream(sys.stdin.buffer, args.algorithm)
        else:
            digest = hash_file(input_path, args.algorithm)

        line = f"{digest} {input_label}"
        if args.output is None:
            print(line)
        else:
            write_digest_line(args.output, line)
    except (HashOperationError, OSError, ValueError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1
    return 0


def _split_iv(input_data: bytes, provided_iv: Optional[bytes]) -> Tuple[bytes, bytes]:
    if provided_iv is not None:
        return provided_iv, input_data
    if len(input_data) < IV_SIZE:
        raise ValueError("входной файл слишком короткий: отсутствует полный 16-байтный IV")
    return input_data[:IV_SIZE], input_data[IV_SIZE:]


def run(arguments: Optional[list[str]] = None) -> int:
    args = parse_args(arguments)

    if args.command == "dgst":
        return _run_digest(args)

    # Режимы AES загружаются только для старой команды шифрования.
    # Благодаря этому команда dgst остаётся отдельной от шифрования.
    from .modes import decrypt_mode, encrypt_mode

    try:
        input_data = read_binary(args.input)
        key = args.key
        if key is None:
            key = generate_random_bytes(KEY_SIZE)
            print(f"[INFO] Generated random key: {key.hex()}")
        else:
            weakness = weak_key_reason(key)
            if weakness is not None:
                print(
                    f"[WARNING] Предоставленный ключ выглядит слабым: {weakness}.",
                    file=sys.stderr,
                )

        if args.mode == "ecb":
            result = (
                encrypt_mode(input_data, key, args.mode)
                if args.encrypt
                else decrypt_mode(input_data, key, args.mode)
            )
        elif args.encrypt:
            iv = generate_random_bytes(IV_SIZE)
            ciphertext = encrypt_mode(input_data, key, args.mode, iv)
            result = iv + ciphertext
        else:
            iv, ciphertext = _split_iv(input_data, args.iv)
            result = decrypt_mode(ciphertext, key, args.mode, iv)
        write_binary(args.output, result)
    except (CSPRNGError, FileOperationError, ValueError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1

    operation = "Шифрование" if args.encrypt else "Расшифрование"
    print(f"{operation} завершено. Результат: {args.output}")
    return 0


def main() -> None:
    raise SystemExit(run())
