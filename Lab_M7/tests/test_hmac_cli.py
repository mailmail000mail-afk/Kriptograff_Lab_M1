import hashlib
import hmac
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Optional
import unittest


def find_openssl():
    executable = shutil.which("openssl")
    if executable:
        return executable
    windows_git_openssl = Path(r"C:\Program Files\Git\mingw64\bin\openssl.exe")
    return str(windows_git_openssl) if windows_git_openssl.exists() else None


OPENSSL = find_openssl()
KEY = "00112233445566778899aabbccddeeff"


class HmacCliTests(unittest.TestCase):
    def run_cli(self, *arguments: str, input_data: Optional[bytes] = None):
        environment = os.environ.copy()
        source_dir = Path(__file__).resolve().parents[1] / "src"
        existing_path = environment.get("PYTHONPATH", "")
        environment["PYTHONPATH"] = os.pathsep.join(
            item for item in (str(source_dir), existing_path) if item
        )
        environment["PYTHONUTF8"] = "1"
        return subprocess.run(
            [sys.executable, "-m", "cryptocore", *arguments],
            input=input_data,
            capture_output=True,
            env=environment,
            check=False,
        )

    def test_generation_stdout_format(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "message.bin"
            source.write_bytes(b"authenticated data")
            result = self.run_cli(
                "dgst", "--algorithm", "sha256", "--hmac", "--key", KEY,
                "--input", str(source),
            )
            expected_value = hmac.new(
                bytes.fromhex(KEY), source.read_bytes(), hashlib.sha256
            ).hexdigest()
            expected = f"{expected_value} {source}{os.linesep}".encode()
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            self.assertEqual(result.stdout, expected)

    def test_output_file_and_successful_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "message.bin"
            mac_file = root / "message.hmac"
            source.write_bytes(bytes(range(256)) + b"HMAC")

            generated = self.run_cli(
                "dgst", "--algorithm", "sha256", "--hmac", "--key", KEY,
                "--input", str(source), "--output", str(mac_file),
            )
            self.assertEqual(generated.returncode, 0, generated.stderr.decode(errors="replace"))
            self.assertEqual(generated.stdout, b"")
            self.assertTrue(mac_file.read_text(encoding="utf-8").endswith(f" {source}\n"))

            verified = self.run_cli(
                "dgst", "--algorithm", "sha256", "--hmac", "--key", KEY,
                "--input", str(source), "--verify", str(mac_file),
            )
            self.assertEqual(verified.returncode, 0, verified.stderr.decode(errors="replace"))
            self.assertEqual(
                verified.stdout.decode(), f"[OK] HMAC verification successful{os.linesep}"
            )

    def test_tampered_file_and_wrong_key_are_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "message.bin"
            mac_file = root / "message.hmac"
            source.write_bytes(b"original content")
            generated = self.run_cli(
                "dgst", "--algorithm", "sha256", "--hmac", "--key", KEY,
                "--input", str(source), "--output", str(mac_file),
            )
            self.assertEqual(generated.returncode, 0)

            source.write_bytes(b"Original content")
            tampered = self.run_cli(
                "dgst", "--algorithm", "sha256", "--hmac", "--key", KEY,
                "--input", str(source), "--verify", str(mac_file),
            )
            self.assertEqual(tampered.returncode, 1)
            self.assertIn("verification failed", tampered.stderr.decode())

            source.write_bytes(b"original content")
            wrong_key = self.run_cli(
                "dgst", "--algorithm", "sha256", "--hmac", "--key", "ff" * 16,
                "--input", str(source), "--verify", str(mac_file),
            )
            self.assertEqual(wrong_key.returncode, 1)
            self.assertIn("verification failed", wrong_key.stderr.decode())

    def test_standard_input(self) -> None:
        payload = b"stdin hmac\x00\xff"
        result = self.run_cli(
            "dgst", "--algorithm", "sha256", "--hmac", "--key", KEY,
            "--input", "-", input_data=payload,
        )
        expected = hmac.new(bytes.fromhex(KEY), payload, hashlib.sha256).hexdigest()
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stdout.decode(), f"{expected} -{os.linesep}")

    def test_hmac_requires_key(self) -> None:
        result = self.run_cli(
            "dgst", "--algorithm", "sha256", "--hmac", "--input", "message.bin"
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("--key обязателен", result.stderr.decode("utf-8"))

    def test_invalid_key_and_sha3_hmac_are_rejected(self) -> None:
        malformed = self.run_cli(
            "dgst", "--algorithm", "sha256", "--hmac", "--key", "abc",
            "--input", "message.bin",
        )
        self.assertEqual(malformed.returncode, 2)
        self.assertIn("чётной длины", malformed.stderr.decode("utf-8"))

        sha3 = self.run_cli(
            "dgst", "--algorithm", "sha3-256", "--hmac", "--key", KEY,
            "--input", "message.bin",
        )
        self.assertEqual(sha3.returncode, 2)
        self.assertIn("только --algorithm sha256", sha3.stderr.decode("utf-8"))

    def test_bad_expected_file_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "message.bin"
            expected = root / "bad.hmac"
            source.write_bytes(b"message")
            expected.write_text("bad value", encoding="utf-8")
            result = self.run_cli(
                "dgst", "--algorithm", "sha256", "--hmac", "--key", KEY,
                "--input", str(source), "--verify", str(expected),
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("64 hex-символа", result.stderr.decode("utf-8"))

    @unittest.skipUnless(OPENSSL, "OpenSSL не найден")
    def test_matches_openssl(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "interop.bin"
            source.write_bytes(bytes(range(256)) * 4 + b"OpenSSL HMAC")
            ours = self.run_cli(
                "dgst", "--algorithm", "sha256", "--hmac", "--key", KEY,
                "--input", str(source),
            )
            reference = subprocess.run(
                [
                    OPENSSL, "dgst", "-sha256", "-mac", "HMAC",
                    "-macopt", f"hexkey:{KEY}", str(source),
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
            )
            self.assertEqual(ours.returncode, 0, ours.stderr.decode(errors="replace"))
            self.assertEqual(reference.returncode, 0, reference.stderr)
            actual = ours.stdout.decode().split(" ", 1)[0]
            expected = reference.stdout.strip().rsplit(" ", 1)[-1].lower()
            self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
