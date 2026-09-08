import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


KEY = "000102030405060708090a0b0c0d0e0f"


class CliTests(unittest.TestCase):
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

    def test_cli_round_trip_binary_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.bin"
            encrypted = root / "source.bin.enc"
            decrypted = root / "restored.bin"
            original = bytes(range(256)) + b"\x00\xffCryptoCore"
            source.write_bytes(original)

            encryption = self.run_cli(
                "--algorithm", "aes", "--mode", "ecb", "--encrypt",
                "--key", KEY, "--input", str(source),
            )
            self.assertEqual(encryption.returncode, 0, encryption.stderr)
            self.assertTrue(encrypted.exists())

            decryption = self.run_cli(
                "--algorithm", "aes", "--mode", "ecb", "--decrypt",
                "--key", KEY, "--input", str(encrypted), "--output", str(decrypted),
            )
            self.assertEqual(decryption.returncode, 0, decryption.stderr)
            self.assertEqual(decrypted.read_bytes(), original)

    def test_missing_file_returns_error(self) -> None:
        result = self.run_cli(
            "--algorithm", "aes", "--mode", "ecb", "--encrypt",
            "--key", KEY, "--input", "missing-file.bin", "--output", "out.bin",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Ошибка:", result.stderr)

    def test_conflicting_operations_are_rejected(self) -> None:
        result = self.run_cli(
            "--algorithm", "aes", "--mode", "ecb", "--encrypt", "--decrypt",
            "--key", KEY, "--input", "input.bin", "--output", "out.bin",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not allowed", result.stderr)

    def test_malformed_key_is_rejected(self) -> None:
        result = self.run_cli(
            "--algorithm", "aes", "--mode", "ecb", "--encrypt",
            "--key", "not-a-key", "--input", "input.bin", "--output", "out.bin",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ключ AES-128", result.stderr)


if __name__ == "__main__":
    unittest.main()
