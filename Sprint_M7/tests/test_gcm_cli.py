import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


KEY = "feffe9928665731c6d6a8f9467308308"
NONCE = "cafebabefacedbaddecaf888"
AAD = "3ad77bb40d7a3660a89ecaf32466ef97f5d3d585"


class GcmCliTests(unittest.TestCase):
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

    def test_round_trip_with_aad_and_combined_format(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "plain.bin"
            encrypted = root / "encrypted.bin"
            restored = root / "restored.bin"
            plaintext = bytes(range(256)) + b"GCM partial block"
            source.write_bytes(plaintext)

            result = self.run_cli(
                "--algorithm", "aes", "--mode", "gcm", "--encrypt",
                "--key", KEY, "--input", str(source), "--output", str(encrypted),
                "--aad", AAD,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(encrypted.read_bytes()), len(plaintext) + 12 + 16)

            result = self.run_cli(
                "--algorithm", "aes", "--mode", "gcm", "--decrypt",
                "--key", KEY, "--input", str(encrypted), "--output", str(restored),
                "--aad", AAD,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("[SUCCESS] Decryption completed successfully", result.stdout)
            self.assertEqual(restored.read_bytes(), plaintext)

    def test_explicit_nonce_matches_nist_empty_vector(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "empty.bin"
            output = root / "gcm.bin"
            source.write_bytes(b"")
            result = self.run_cli(
                "--algorithm", "aes", "--mode", "gcm", "--encrypt",
                "--key", KEY, "--nonce", NONCE, "--aad", "",
                "--input", str(source), "--output", str(output),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                output.read_bytes().hex(),
                NONCE + "3247184b3c4f69a44dbcd22887bbb418",
            )

    def test_explicit_nonce_decrypts_detached_ciphertext_and_tag(self) -> None:
        ciphertext_and_tag = bytes.fromhex(
            "42831ec2217774244b7221b784d0d49c"
            "e3aa212f2c02a4e035c17e2329aca12e"
            "21d514b25466931c7d8f6a5aac84aa05"
            "1ba30b396a0aac973d58e091"
            "f07c2528eea2fca1211f905e1b6a881b"
        )
        expected = bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b39"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "detached.bin"
            output = root / "plain.bin"
            source.write_bytes(ciphertext_and_tag)
            result = self.run_cli(
                "--algorithm", "aes", "--mode", "gcm", "--decrypt",
                "--key", KEY, "--iv", NONCE, "--aad", AAD,
                "--input", str(source), "--output", str(output),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_bytes(), expected)

    def test_wrong_aad_produces_no_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "plain.bin"
            encrypted = root / "encrypted.bin"
            output = root / "must-not-exist.bin"
            source.write_bytes(b"authenticated content")
            encryption = self.run_cli(
                "--algorithm", "aes", "--mode", "gcm", "--encrypt",
                "--key", KEY, "--input", str(source), "--output", str(encrypted),
                "--aad", AAD,
            )
            self.assertEqual(encryption.returncode, 0, encryption.stderr)
            result = self.run_cli(
                "--algorithm", "aes", "--mode", "gcm", "--decrypt",
                "--key", KEY, "--input", str(encrypted), "--output", str(output),
                "--aad", "00",
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("[ERROR] Authentication failed", result.stderr)
            self.assertFalse(output.exists())

    def test_ciphertext_and_tag_tampering_produce_no_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "plain.bin"
            encrypted = root / "encrypted.bin"
            source.write_bytes(b"message with enough bytes")
            encryption = self.run_cli(
                "--algorithm", "aes", "--mode", "gcm", "--encrypt",
                "--key", KEY, "--nonce", NONCE, "--input", str(source),
                "--output", str(encrypted),
            )
            self.assertEqual(encryption.returncode, 0, encryption.stderr)
            original = encrypted.read_bytes()

            for label, position in (("ciphertext", 12), ("tag", -1)):
                with self.subTest(label=label):
                    tampered = bytearray(original)
                    tampered[position] ^= 1
                    tampered_path = root / f"{label}.bin"
                    output = root / f"{label}.out"
                    tampered_path.write_bytes(tampered)
                    result = self.run_cli(
                        "--algorithm", "aes", "--mode", "gcm", "--decrypt",
                        "--key", KEY, "--input", str(tampered_path),
                        "--output", str(output),
                    )
                    self.assertEqual(result.returncode, 1)
                    self.assertIn("Authentication failed", result.stderr)
                    self.assertFalse(output.exists())

    def test_empty_aad_is_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "plain.bin"
            encrypted = root / "encrypted.bin"
            restored = root / "restored.bin"
            source.write_bytes(b"")
            encryption = self.run_cli(
                "--algorithm", "aes", "--mode", "gcm", "--encrypt",
                "--key", KEY, "--input", str(source), "--output", str(encrypted),
            )
            self.assertEqual(encryption.returncode, 0, encryption.stderr)
            decryption = self.run_cli(
                "--algorithm", "aes", "--mode", "gcm", "--decrypt",
                "--key", KEY, "--input", str(encrypted), "--output", str(restored),
            )
            self.assertEqual(decryption.returncode, 0, decryption.stderr)
            self.assertEqual(restored.read_bytes(), b"")

    def test_invalid_aad_nonce_and_context_are_rejected(self) -> None:
        invalid_aad = self.run_cli(
            "--algorithm", "aes", "--mode", "gcm", "--encrypt",
            "--key", KEY, "--aad", "not-hex", "--input", "in", "--output", "out",
        )
        self.assertEqual(invalid_aad.returncode, 2)
        self.assertIn("AAD", invalid_aad.stderr)

        invalid_nonce = self.run_cli(
            "--algorithm", "aes", "--mode", "gcm", "--encrypt",
            "--key", KEY, "--nonce", "00" * 16,
            "--input", "in", "--output", "out",
        )
        self.assertEqual(invalid_nonce.returncode, 2)
        self.assertIn("12 байт", invalid_nonce.stderr)

        wrong_mode = self.run_cli(
            "--algorithm", "aes", "--mode", "ctr", "--encrypt",
            "--key", KEY, "--aad", "00", "--input", "in", "--output", "out",
        )
        self.assertEqual(wrong_mode.returncode, 2)
        self.assertIn("только в режиме GCM", wrong_mode.stderr)


if __name__ == "__main__":
    unittest.main()
