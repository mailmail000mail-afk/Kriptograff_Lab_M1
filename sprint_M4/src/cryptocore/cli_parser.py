import argparse
from pathlib import Path
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
    if len(value) != 32:
        raise argparse.ArgumentTypeError(
            "IV должен содержать ровно 32 шестнадцатеричных символа"
        )

    try:
        iv = bytes.fromhex(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "IV должен быть записан шестнадцатеричными символами"
        ) from error

    if len(iv) != 16:
        raise argparse.ArgumentTypeError("IV должен иметь длину 16 байт")

    return iv


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
        choices=["ecb", "cbc", "cfb", "ofb", "ctr"],
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
        "--iv",
        type=parse_hex_iv,
        help="16-байтный IV в hex; допускается только при расшифровании не-ECB",
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
        choices=["sha256", "sha3-256"],
        help="алгоритм хеширования",
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
    return parser


def build_parser() -> argparse.ArgumentParser:
    """Сохранённое имя функции для совместимости с предыдущими спринтами."""
    return build_cipher_parser()


def default_output_path(input_path: Path, encrypt: bool) -> Path:
    suffix = ".enc" if encrypt else ".dec"
    return Path(f"{input_path}{suffix}")


def parse_args(arguments: Optional[list[str]] = None) -> argparse.Namespace:
    raw_arguments = sys.argv[1:] if arguments is None else list(arguments)
    if raw_arguments and raw_arguments[0] == "dgst":
        parser = build_digest_parser()
        args = parser.parse_args(raw_arguments[1:])
        args.command = "dgst"
        return args

    parser = build_cipher_parser()
    args = parser.parse_args(raw_arguments)
    args.command = "cipher"
    if args.encrypt and args.iv is not None:
        parser.error("--iv нельзя задавать при шифровании: IV создаётся автоматически")
    if args.mode == "ecb" and args.iv is not None:
        parser.error("--iv не применяется в режиме ECB")
    if args.decrypt and args.key is None:
        parser.error("--key обязателен при расшифровании")
    if args.output is None:
        args.output = default_output_path(args.input, args.encrypt)
    return args
