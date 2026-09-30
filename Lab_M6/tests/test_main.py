from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
from unittest import mock
import unittest

from cryptocore.main import run


class MainRandomnessIntegrationTests(unittest.TestCase):
    def test_generated_key_and_iv_use_the_csprng_module(self) -> None:
        key = bytes.fromhex("11223344556677889900aabbccddeeff")
        iv = bytes.fromhex("ffeeddccbbaa00998877665544332211")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "plain.bin"
            output = root / "cipher.bin"
            source.write_bytes(b"CSPRNG integration")
            stdout = StringIO()

            with mock.patch(
                "cryptocore.main.generate_random_bytes", side_effect=[key, iv]
            ) as generator, redirect_stdout(stdout):
                result = run(
                    [
                        "--algorithm", "aes", "--mode", "ctr", "--encrypt",
                        "--input", str(source), "--output", str(output),
                    ]
                )

            self.assertEqual(result, 0)
            self.assertEqual(generator.call_args_list, [mock.call(16), mock.call(16)])
            self.assertEqual(output.read_bytes()[:16], iv)
            self.assertEqual(stdout.getvalue().count("Generated random key:"), 1)
            self.assertIn(key.hex(), stdout.getvalue())

    def test_weak_user_key_warning_goes_to_stderr(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "plain.bin"
            output = root / "cipher.bin"
            source.write_bytes(b"weak key warning")
            stderr = StringIO()
            stdout = StringIO()

            with redirect_stderr(stderr), redirect_stdout(stdout):
                result = run(
                    [
                        "--algorithm", "aes", "--mode", "ecb", "--encrypt",
                        "--key", "00" * 16, "--input", str(source),
                        "--output", str(output),
                    ]
                )

            self.assertEqual(result, 0)
            self.assertIn("[WARNING]", stderr.getvalue())
            self.assertIn("слабым", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
