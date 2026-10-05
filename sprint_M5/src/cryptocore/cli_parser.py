import argparse
from pathlib import Path
import string
import sys
from typing import Optional


def parse_hex_key(value: str) -> bytes:
    if len(value) != 32:
        raise argparse.ArgumentTypeError(
            "ключ AES-128 должен содержать ровно 32 шестнадцатеричных символа"
        )

    try:
        key = bytes.fromhex(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "ключ должен быть записан шестнадцатеричными символами"
        ) from error

    if len(key) != 16:
        raise argparse.ArgumentTypeError("ключ AES-128 должен иметь длину 16 байт")

    return key


def parse_hex_iv(value: str) -> bytes:
    try:
        iv = bytes.fromhex(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "IV или nonce должен быть записан шестнадцатеричными символами"
        ) from error
    return iv


def parse_hex_aad(value: str) -> bytes:
    if len(value) % 2 != 0 or any(symbol not in string.hexdigits for symbol in value):
        raise argparse.ArgumentTypeError(
            "AAD должен быть шестнадцатеричной строкой чётной длины"
        )
    return bytes.fromhex(value)


def parse_hex_mac_key(value: str) -> bytes:
    if len(value) % 2 != 0 or any(symbol not in string.hexdigits for symbol in value):
        raise argparse.ArgumentTypeError(
            "ключ MAC должен быть шестнадцатеричной строкой чётной длины"
        )
    return bytes.fromhex(value)


def parse_hex_salt(value: str) -> bytes:
    if len(value) % 2 != 0 or any(symbol not in string.hexdigits for symbol in value):
        raise argparse.ArgumentTypeError(
            "соль должна быть шестнадцатеричной строкой чётной длины"
        )
    return bytes.fromhex(value)


def parse_positive_integer(value: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("значение должно быть целым числом") from error
    if number < 1:
        raise argparse.ArgumentTypeError("значение должно быть положительным")
    return number


def build_cipher_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description="Шифрование и расшифрование файлов с помощью AES-128.",
    )
    parser.add_argument(
        "--algorithm",
        required=True,
        choices=["aes"],
        help="алгоритм шифрования (aes)",
    )
    parser.add_argument(
        "--mode",
        required=True,
        choices=["ecb", "cbc", "cfb", "ofb", "ctr", "gcm"],
        help="режим работы AES",
    )

    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--encrypt", action="store_true", help="зашифровать файл")
    operation.add_argument("--decrypt", action="store_true", help="расшифровать файл")

    parser.add_argument(
        "--key",
        type=parse_hex_key,
        help=(
            "128-битный ключ в виде 32 шестнадцатеричных символов; "
            "при шифровании может быть создан автоматически"
        ),
    )
    parser.add_argument(
        "--iv", "--nonce",
        dest="iv",
        type=parse_hex_iv,
        help="IV или nonce в hex; --nonce является псевдонимом --iv",
    )
    parser.add_argument(
        "--aad",
        type=parse_hex_aad,
        help="связанные данные GCM в hex; по умолчанию пустые",
    )
    parser.add_argument("--input", required=True, type=Path, help="путь к входному файлу")
    parser.add_argument("--output", type=Path, help="путь к выходному файлу")
    return parser


def build_digest_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptocore dgst",
        description="Вычисление криптографического хеша файла или стандартного ввода.",
    )
    parser.add_argument(
        "--algorithm",
        required=True,
        choices=["sha256", "sha3-256", "aes"],
        help="алгоритм хеширования или AES для CMAC",
    )
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="путь к входному файлу или - для стандартного ввода",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="записать строку с хешем в указанный файл",
    )
    mac_mode = parser.add_mutually_exclusive_group()
    mac_mode.add_argument(
        "--hmac",
        action="store_true",
        help="вычислить HMAC-SHA-256 вместо обычного хеша",
    )
    mac_mode.add_argument(
        "--cmac",
        action="store_true",
        help="вычислить AES-CMAC вместо обычного хеша",
    )
    parser.add_argument(
        "--key",
        type=parse_hex_mac_key,
        help="ключ MAC в hex; AES-CMAC требует ровно 16 байт",
    )
    parser.add_argument(
        "--verify",
        type=Path,
        help="сравнить MAC с первым значением из указанного файла",
    )
    return parser


def build_derive_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptocore derive",
        description="Выработка ключа из пароля с помощью PBKDF2-HMAC-SHA256.",
    )
    parser.add_argument("--password", required=True, help="пароль в кодировке UTF-8")
    parser.add_argument(
        "--salt",
        type=parse_hex_salt,
        help="соль в hex; без параметра создаётся случайная 16-байтная соль",
    )
    parser.add_argument(
        "--iterations",
        type=parse_positive_integer,
        default=100_000,
        help="число итераций PBKDF2 (по умолчанию 100000)",
    )
    parser.add_argument(
        "--length",
        type=parse_positive_integer,
        default=32,
        help="длина производного ключа в байтах (по умолчанию 32)",
    )
    parser.add_argument(
        "--algorithm",
        choices=["pbkdf2"],
        default="pbkdf2",
        help="алгоритм KDF (pbkdf2)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="записать производный ключ в файл как двоичные данные",
    )
    return parser


def build_parser() -> argparse.ArgumentParser:
    """Сохранённое имя функции для совместимости с предыдущими спринтами."""
    return build_cipher_parser()


def default_output_path(input_path: Path, encrypt: bool) -> Path:
    suffix = ".enc" if encrypt else ".dec"
    return Path(f"{input_path}{suffix}")


def parse_args(arguments: Optional[list[str]] = None) -> argparse.Namespace:
    raw_arguments = sys.argv[1:] if arguments is None else list(arguments)
    if raw_arguments and raw_arguments[0] == "derive":
        parser = build_derive_parser()
        args = parser.parse_args(raw_arguments[1:])
        args.command = "derive"
        return args
    if raw_arguments and raw_arguments[0] == "dgst":
        parser = build_digest_parser()
        args = parser.parse_args(raw_arguments[1:])
        if args.hmac:
            if args.algorithm != "sha256":
                parser.error("--hmac поддерживает только --algorithm sha256")
            if args.key is None:
                parser.error("--key обязателен при использовании --hmac")
        elif args.cmac:
            if args.algorithm != "aes":
                parser.error("--cmac поддерживает только --algorithm aes")
            if args.key is None:
                parser.error("--key обязателен при использовании --cmac")
            if len(args.key) != 16:
                parser.error("ключ AES-CMAC должен иметь длину 16 байт")
        else:
            if args.key is not None:
                parser.error("--key допускается только вместе с --hmac или --cmac")
            if args.verify is not None:
                parser.error("--verify допускается только вместе с --hmac или --cmac")
            if args.algorithm == "aes":
                parser.error("--algorithm aes допускается только вместе с --cmac")
        if args.verify is not None and args.output is not None:
            parser.error("--output нельзя использовать вместе с --verify")
        args.command = "dgst"
        return args

    parser = build_cipher_parser()
    args = parser.parse_args(raw_arguments)
    args.command = "cipher"
    if args.encrypt and args.iv is not None and args.mode != "gcm":
        parser.error("--iv нельзя задавать при шифровании: IV создаётся автоматически")
    if args.mode == "ecb" and args.iv is not None:
        parser.error("--iv не применяется в режиме ECB")
    if args.mode == "gcm":
        if args.iv is not None and len(args.iv) != 12:
            parser.error("nonce GCM должен иметь длину 12 байт")
        if args.aad is None:
            args.aad = b""
    else:
        if args.aad is not None:
            parser.error("--aad допускается только в режиме GCM")
        if args.iv is not None and len(args.iv) != 16:
            parser.error("IV должен иметь длину 16 байт")
    if args.decrypt and args.key is None:
        parser.error("--key обязателен при расшифровании")
    if args.output is None:
        args.output = default_output_path(args.input, args.encrypt)
    return args
