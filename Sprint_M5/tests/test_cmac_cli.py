import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Optional
import unittest


KEY = "2b7e151628aed2a6abf7158809cf4f3c"
ONE_BLOCK = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
ONE_BLOCK_TAG = "070a16b46b4d4144f79bdd9dd04a287c"


class CmacCliTests(unittest.TestCase):
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

    def test_generation_uses_nist_vector_and_exact_format(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "message.bin"
            source.write_bytes(ONE_BLOCK)
            result = self.run_cli(
                "dgst", "--algorithm", "aes", "--cmac", "--key", KEY,
                "--input", str(source),
            )
            expected = f"{ONE_BLOCK_TAG} {source}{os.linesep}".encode()
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            self.assertEqual(result.stdout, expected)

    def test_empty_standard_input_matches_nist_vector(self) -> None:
        result = self.run_cli(
            "dgst", "--algorithm", "aes", "--cmac", "--key", KEY,
            "--input", "-", input_data=b"",
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(
            result.stdout.decode(),
            f"bb1d6929e95937287fa37d129b756746 -{os.linesep}",
        )

    def test_output_file_and_successful_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "message.bin"
            mac_file = root / "message.cmac"
            source.write_bytes(ONE_BLOCK)

            generated = self.run_cli(
                "dgst", "--algorithm", "aes", "--cmac", "--key", KEY,
                "--input", str(source), "--output", str(mac_file),
            )
            self.assertEqual(generated.returncode, 0, generated.stderr.decode(errors="replace"))
            self.assertEqual(generated.stdout, b"")
            self.assertEqual(
                mac_file.read_text(encoding="utf-8"),
                f"{ONE_BLOCK_TAG} {source}\n",
            )

            verified = self.run_cli(
                "dgst", "--algorithm", "aes", "--cmac", "--key", KEY,
                "--input", str(source), "--verify", str(mac_file),
            )
            self.assertEqual(verified.returncode, 0, verified.stderr.decode(errors="replace"))
            self.assertEqual(
                verified.stdout.decode(),
                f"[OK] CMAC verification successful{os.linesep}",
            )

    def test_tampered_file_and_wrong_key_are_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "message.bin"
            mac_file = root / "message.cmac"
            source.write_bytes(ONE_BLOCK)
            self.assertEqual(
                self.run_cli(
                    "dgst", "--algorithm", "aes", "--cmac", "--key", KEY,
                    "--input", str(source), "--output", str(mac_file),
                ).returncode,
                0,
            )

            source.write_bytes(b"X" + ONE_BLOCK[1:])
            tampered = self.run_cli(
                "dgst", "--algorithm", "aes", "--cmac", "--key", KEY,
                "--input", str(source), "--verify", str(mac_file),
            )
            self.assertEqual(tampered.returncode, 1)
            self.assertIn("CMAC verification failed", tampered.stderr.decode())

            source.write_bytes(ONE_BLOCK)
            wrong_key = self.run_cli(
                "dgst", "--algorithm", "aes", "--cmac", "--key", "00" * 16,
                "--input", str(source), "--verify", str(mac_file),
            )
            self.assertEqual(wrong_key.returncode, 1)
            self.assertIn("CMAC verification failed", wrong_key.stderr.decode())

    def test_invalid_combinations_and_key_length_are_rejected(self) -> None:
        cases = (
            (
                ("dgst", "--algorithm", "sha256", "--cmac", "--key", KEY,
                 "--input", "message.bin"),
                "только --algorithm aes",
            ),
            (
                ("dgst", "--algorithm", "aes", "--hmac", "--key", KEY,
                 "--input", "message.bin"),
                "только --algorithm sha256",
            ),
            (
                ("dgst", "--algorithm", "aes", "--input", "message.bin"),
                "только вместе с --cmac",
            ),
            (
                ("dgst", "--algorithm", "aes", "--cmac", "--key", "00" * 15,
                 "--input", "message.bin"),
                "16 байт",
            ),
            (
                ("dgst", "--algorithm", "aes", "--cmac", "--key", KEY,
                 "--input", "message.bin", "--hmac"),
                "not allowed with argument",
            ),
        )
        for arguments, expected in cases:
            with self.subTest(arguments=arguments):
                result = self.run_cli(*arguments)
                self.assertEqual(result.returncode, 2)
                self.assertIn(expected, result.stderr.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
