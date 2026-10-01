import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptocore.cli_parser import parse_args


class DeriveCliTests(unittest.TestCase):
    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        source_dir = Path(__file__).resolve().parents[1] / "src"
        existing_path = environment.get("PYTHONPATH", "")
        environment["PYTHONPATH"] = os.pathsep.join(
            item for item in (str(source_dir), existing_path) if item
        )
        environment["PYTHONUTF8"] = "1"
        return subprocess.run(
            [sys.executable, "-m", "cryptocore", *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=environment,
            check=False,
        )

    def test_fixed_salt_stdout_format_and_value(self) -> None:
        result = self.run_cli(
            "derive",
            "--password", "password",
            "--salt", "73616c74",
            "--iterations", "2",
            "--length", "20",
            "--algorithm", "pbkdf2",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8e 73616c74\n",
        )

    def test_auto_salt_has_sixteen_bytes(self) -> None:
        first = self.run_cli(
            "derive", "--password", "password", "--iterations", "1", "--length", "16"
        )
        second = self.run_cli(
            "derive", "--password", "password", "--iterations", "1", "--length", "16"
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        first_key, first_salt = first.stdout.split()
        second_key, second_salt = second.stdout.split()
        self.assertEqual(len(bytes.fromhex(first_key)), 16)
        self.assertEqual(len(bytes.fromhex(first_salt)), 16)
        self.assertEqual(len(bytes.fromhex(second_key)), 16)
        self.assertNotEqual(first_salt, second_salt)

    def test_output_file_contains_only_raw_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "derived.key"
            result = self.run_cli(
                "derive",
                "--password", "app_key",
                "--salt", "00112233445566778899aabbccddeeff",
                "--iterations", "5",
                "--length", "48",
                "--output", str(output),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            key_hex, salt_hex = result.stdout.split()
            self.assertEqual(output.read_bytes(), bytes.fromhex(key_hex))
            self.assertEqual(len(output.read_bytes()), 48)
            self.assertEqual(salt_hex, "00112233445566778899aabbccddeeff")

    def test_utf8_password_with_special_characters(self) -> None:
        password = "Пароль! 123"
        salt = "a1b2c3d4e5f601234567890123456789"
        result = self.run_cli(
            "derive", "--password", password, "--salt", salt,
            "--iterations", "3", "--length", "32",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt), 3, 32
        )
        self.assertEqual(result.stdout.split()[0], expected.hex())

    def test_defaults_are_parsed(self) -> None:
        args = parse_args(["derive", "--password", "password"])
        self.assertEqual(args.algorithm, "pbkdf2")
        self.assertEqual(args.iterations, 100_000)
        self.assertEqual(args.length, 32)
        self.assertIsNone(args.salt)
        self.assertIsNone(args.output)

    def test_invalid_arguments_are_rejected(self) -> None:
        cases = [
            ("--salt", "xyz"),
            ("--iterations", "0"),
            ("--length", "0"),
            ("--algorithm", "scrypt"),
        ]
        for option, value in cases:
            with self.subTest(option=option, value=value):
                result = self.run_cli(
                    "derive", "--password", "password", option, value
                )
                self.assertEqual(result.returncode, 2)

    def test_password_is_required(self) -> None:
        result = self.run_cli("derive", "--iterations", "1")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--password", result.stderr)


if __name__ == "__main__":
    unittest.main()
