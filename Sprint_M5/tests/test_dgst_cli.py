import hashlib
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


class DigestCliTests(unittest.TestCase):
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

    def test_stdout_format_is_exact_and_lowercase(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "file.bin"
            source.write_bytes(b"abc")
            result = self.run_cli(
                "dgst", "--algorithm", "sha256", "--input", str(source)
            )
            expected = f"{hashlib.sha256(b'abc').hexdigest()} {source}{os.linesep}".encode()
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            self.assertEqual(result.stdout, expected)
            self.assertEqual(result.stderr, b"")

    def test_output_option_redirects_the_same_line_to_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "file.bin"
            output = root / "digest.txt"
            source.write_bytes(b"output option")
            result = self.run_cli(
                "dgst", "--algorithm", "sha3-256", "--input", str(source),
                "--output", str(output),
            )
            expected = f"{hashlib.sha3_256(source.read_bytes()).hexdigest()} {source}\n"
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            self.assertEqual(result.stdout, b"")
            self.assertEqual(output.read_text(encoding="utf-8"), expected)

    def test_standard_input(self) -> None:
        payload = b"data from stdin\x00\xff"
        result = self.run_cli(
            "dgst", "--algorithm", "sha256", "--input", "-", input_data=payload
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(
            result.stdout.decode(), f"{hashlib.sha256(payload).hexdigest()} -{os.linesep}"
        )

    def test_key_is_rejected_without_hmac(self) -> None:
        result = self.run_cli(
            "dgst", "--algorithm", "sha256", "--input", "file.bin",
            "--key", "00" * 16,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("только вместе с --hmac", result.stderr.decode("utf-8"))

    def test_missing_file_returns_clear_error(self) -> None:
        result = self.run_cli(
            "dgst", "--algorithm", "sha256", "--input", "missing.bin"
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Ошибка:", result.stderr.decode("utf-8"))

    @unittest.skipUnless(OPENSSL, "OpenSSL не найден")
    def test_both_algorithms_match_openssl(self) -> None:
        payload = bytes(range(256)) * 5 + "Совместимость".encode("utf-8")
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "interop.bin"
            source.write_bytes(payload)
            for algorithm, openssl_name in (("sha256", "-sha256"), ("sha3-256", "-sha3-256")):
                with self.subTest(algorithm=algorithm):
                    ours = self.run_cli(
                        "dgst", "--algorithm", algorithm, "--input", str(source)
                    )
                    reference = subprocess.run(
                        [OPENSSL, "dgst", openssl_name, str(source)],
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        check=False,
                    )
                    self.assertEqual(ours.returncode, 0, ours.stderr.decode(errors="replace"))
                    self.assertEqual(reference.returncode, 0, reference.stderr)
                    expected_hash = reference.stdout.strip().rsplit(" ", 1)[-1].lower()
                    actual_hash = ours.stdout.decode().split(" ", 1)[0]
                    self.assertEqual(actual_hash, expected_hash)


if __name__ == "__main__":
    unittest.main()
