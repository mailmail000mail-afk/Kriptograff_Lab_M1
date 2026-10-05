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

    def test_new_modes_round_trip_and_prepend_iv(self) -> None:
        original = bytes(range(256)) + b"\x00\xffpartial-block"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.bin"
            source.write_bytes(original)

            for mode in ("cbc", "cfb", "ofb", "ctr"):
                with self.subTest(mode=mode):
                    encrypted = root / f"{mode}.bin"
                    restored = root / f"{mode}.restored"
                    encryption = self.run_cli(
                        "--algorithm", "aes", "--mode", mode, "--encrypt",
                        "--key", KEY, "--input", str(source), "--output", str(encrypted),
                    )
                    self.assertEqual(encryption.returncode, 0, encryption.stderr)
                    payload = encrypted.read_bytes()
                    self.assertGreaterEqual(len(payload), 16)
                    if mode in {"cfb", "ofb", "ctr"}:
                        self.assertEqual(len(payload), len(original) + 16)

                    decryption = self.run_cli(
                        "--algorithm", "aes", "--mode", mode, "--decrypt",
                        "--key", KEY, "--input", str(encrypted), "--output", str(restored),
                    )
                    self.assertEqual(decryption.returncode, 0, decryption.stderr)
                    self.assertEqual(restored.read_bytes(), original)

    def test_explicit_iv_uses_ciphertext_without_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "plain.bin"
            combined = root / "combined.bin"
            ciphertext = root / "ciphertext.bin"
            restored = root / "restored.bin"
            source.write_bytes(b"explicit IV check")

            encryption = self.run_cli(
                "--algorithm", "aes", "--mode", "ctr", "--encrypt",
                "--key", KEY, "--input", str(source), "--output", str(combined),
            )
            self.assertEqual(encryption.returncode, 0, encryption.stderr)
            payload = combined.read_bytes()
            iv_hex = payload[:16].hex()
            ciphertext.write_bytes(payload[16:])

            decryption = self.run_cli(
                "--algorithm", "aes", "--mode", "ctr", "--decrypt",
                "--key", KEY, "--iv", iv_hex, "--input", str(ciphertext),
                "--output", str(restored),
            )
            self.assertEqual(decryption.returncode, 0, decryption.stderr)
            self.assertEqual(restored.read_bytes(), source.read_bytes())

    def test_random_iv_changes_between_encryptions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "plain.bin"
            first = root / "first.bin"
            second = root / "second.bin"
            source.write_bytes(b"same plaintext")

            for output in (first, second):
                result = self.run_cli(
                    "--algorithm", "aes", "--mode", "cbc", "--encrypt",
                    "--key", KEY, "--input", str(source), "--output", str(output),
                )
                self.assertEqual(result.returncode, 0, result.stderr)

            self.assertNotEqual(first.read_bytes()[:16], second.read_bytes()[:16])

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

    def test_iv_is_rejected_during_encryption(self) -> None:
        result = self.run_cli(
            "--algorithm", "aes", "--mode", "cbc", "--encrypt",
            "--key", KEY, "--iv", "00" * 16,
            "--input", "input.bin", "--output", "out.bin",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("нельзя задавать при шифровании", result.stderr)

    def test_malformed_iv_is_rejected(self) -> None:
        result = self.run_cli(
            "--algorithm", "aes", "--mode", "cbc", "--decrypt",
            "--key", KEY, "--iv", "1234",
            "--input", "input.bin", "--output", "out.bin",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("IV должен", result.stderr)

    def test_too_short_iv_prefixed_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "short.bin"
            source.write_bytes(b"short")
            result = self.run_cli(
                "--algorithm", "aes", "--mode", "ofb", "--decrypt",
                "--key", KEY, "--input", str(source), "--output", str(root / "out.bin"),
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("16-байтный IV", result.stderr)


if __name__ == "__main__":
    unittest.main()
