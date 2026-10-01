import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


KEY = "000102030405060708090a0b0c0d0e0f"
IV = "aabbccddeeff00112233445566778899"
MODES = ("cbc", "cfb", "ofb", "ctr")


def find_openssl():
    executable = shutil.which("openssl")
    if executable:
        return executable
    windows_git_openssl = Path(r"C:\Program Files\Git\mingw64\bin\openssl.exe")
    return str(windows_git_openssl) if windows_git_openssl.exists() else None


OPENSSL = find_openssl()


@unittest.skipUnless(OPENSSL, "OpenSSL не найден")
class OpenSslInteropTests(unittest.TestCase):
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

    def run_openssl(self, *arguments: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [OPENSSL, "enc", *arguments],
            capture_output=True,
            check=False,
        )

    def test_cryptocore_to_openssl_for_all_new_modes(self) -> None:
        original = "Совместимость CryptoCore и OpenSSL".encode("utf-8") + bytes(range(37))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "plain.bin"
            source.write_bytes(original)

            for mode in MODES:
                with self.subTest(mode=mode):
                    combined = root / f"{mode}.combined"
                    ciphertext = root / f"{mode}.ciphertext"
                    restored = root / f"{mode}.openssl.restored"
                    result = self.run_cli(
                        "--algorithm", "aes", "--mode", mode, "--encrypt",
                        "--key", KEY, "--input", str(source), "--output", str(combined),
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    payload = combined.read_bytes()
                    iv_hex = payload[:16].hex()
                    ciphertext.write_bytes(payload[16:])

                    result = self.run_openssl(
                        f"-aes-128-{mode}", "-d", "-K", KEY, "-iv", iv_hex,
                        "-in", str(ciphertext), "-out", str(restored), "-nosalt",
                    )
                    self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
                    self.assertEqual(restored.read_bytes(), original)

    def test_openssl_to_cryptocore_for_all_new_modes(self) -> None:
        original = bytes(range(256)) + b"OpenSSL to CryptoCore"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "plain.bin"
            source.write_bytes(original)

            for mode in MODES:
                with self.subTest(mode=mode):
                    ciphertext = root / f"{mode}.openssl.ciphertext"
                    restored = root / f"{mode}.restored"
                    result = self.run_openssl(
                        f"-aes-128-{mode}", "-K", KEY, "-iv", IV,
                        "-in", str(source), "-out", str(ciphertext), "-nosalt",
                    )
                    self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))

                    result = self.run_cli(
                        "--algorithm", "aes", "--mode", mode, "--decrypt",
                        "--key", KEY, "--iv", IV, "--input", str(ciphertext),
                        "--output", str(restored),
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(restored.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
