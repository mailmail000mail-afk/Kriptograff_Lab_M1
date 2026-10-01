import hashlib
import hmac
from pathlib import Path
import shutil
import subprocess
import unittest

from cryptocore.kdf import derive_key, derive_password_key, pbkdf2_hmac_sha256


def find_openssl():
    executable = shutil.which("openssl")
    if executable:
        return executable
    windows_git_openssl = Path(r"C:\Program Files\Git\mingw64\bin\openssl.exe")
    return str(windows_git_openssl) if windows_git_openssl.exists() else None


OPENSSL = find_openssl()


class Pbkdf2Tests(unittest.TestCase):
    def test_rfc_6070_parameter_sets_with_sha256(self) -> None:
        cases = [
            (b"password", b"salt", 1, 20, "120fb6cffcf8b32c43e7225256c4f837a86548c9"),
            (b"password", b"salt", 2, 20, "ae4d0c95af6b46d32d0adff928f06dd02a303f8e"),
            (b"password", b"salt", 4096, 20, "c5e478d59288c841aa530db6845c4c8d962893a0"),
            (
                b"passwordPASSWORDpassword",
                b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
                4096,
                25,
                "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c",
            ),
        ]
        for password, salt, iterations, length, expected in cases:
            with self.subTest(iterations=iterations, length=length):
                result = pbkdf2_hmac_sha256(password, salt, iterations, length)
                self.assertEqual(result.hex(), expected)

    def test_lengths_from_one_to_one_hundred_bytes(self) -> None:
        for length in range(1, 101):
            with self.subTest(length=length):
                result = pbkdf2_hmac_sha256(b"password", b"salt", 3, length)
                expected = hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 3, length)
                self.assertEqual(result, expected)

    def test_arbitrary_password_and_salt_lengths(self) -> None:
        cases = [
            (b"", b"", 1, 32),
            (b"p" * 100, b"s", 7, 64),
            ("пароль", b"salt" * 20, 11, 47),
            (b"binary\x00password", b"salt\x00value", 13, 80),
        ]
        for password, salt, iterations, length in cases:
            password_bytes = password.encode("utf-8") if isinstance(password, str) else password
            with self.subTest(iterations=iterations, length=length):
                expected = hashlib.pbkdf2_hmac(
                    "sha256", password_bytes, salt, iterations, length
                )
                self.assertEqual(
                    pbkdf2_hmac_sha256(password, salt, iterations, length), expected
                )

    def test_same_parameters_are_deterministic(self) -> None:
        first = pbkdf2_hmac_sha256(b"repeat", b"salt", 25, 48)
        second = pbkdf2_hmac_sha256(b"repeat", b"salt", 25, 48)
        self.assertEqual(first, second)

    def test_string_salt_supports_hex_and_text(self) -> None:
        self.assertEqual(
            pbkdf2_hmac_sha256("password", "73616c74", 2, 32),
            hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 2, 32),
        )
        self.assertEqual(
            pbkdf2_hmac_sha256("password", "not hex salt", 2, 32),
            hashlib.pbkdf2_hmac("sha256", b"password", b"not hex salt", 2, 32),
        )

    def test_invalid_parameters_are_rejected(self) -> None:
        for iterations in (0, -1, True, 1.5):
            with self.subTest(iterations=iterations):
                with self.assertRaises(ValueError):
                    pbkdf2_hmac_sha256(b"p", b"s", iterations, 32)
        for length in (0, -1, True, 1.5):
            with self.subTest(length=length):
                with self.assertRaises(ValueError):
                    pbkdf2_hmac_sha256(b"p", b"s", 1, length)

    def test_one_thousand_automatic_salts_have_no_duplicates(self) -> None:
        salts = {
            derive_password_key(b"password", iterations=1, length=1)[1]
            for _ in range(1000)
        }
        self.assertEqual(len(salts), 1000)
        self.assertTrue(all(len(salt) == 16 for salt in salts))

    @unittest.skipUnless(OPENSSL, "OpenSSL не найден")
    def test_matches_openssl_pbkdf2_sha256(self) -> None:
        password = "test"
        salt_hex = "1234567890abcdef"
        iterations = 1000
        length = 32
        result = subprocess.run(
            [
                OPENSSL,
                "kdf",
                "-keylen", str(length),
                "-kdfopt", "digest:SHA256",
                "-kdfopt", f"pass:{password}",
                "-kdfopt", f"hexsalt:{salt_hex}",
                "-kdfopt", f"iter:{iterations}",
                "PBKDF2",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = bytes.fromhex(result.stdout.replace(":", "").strip())
        self.assertEqual(
            pbkdf2_hmac_sha256(password, bytes.fromhex(salt_hex), iterations, length),
            expected,
        )


class KeyHierarchyTests(unittest.TestCase):
    @staticmethod
    def reference(master: bytes, context: bytes, length: int) -> bytes:
        result = bytearray()
        counter = 1
        while len(result) < length:
            result.extend(
                hmac.new(
                    master, context + counter.to_bytes(4, "big"), hashlib.sha256
                ).digest()
            )
            counter += 1
        return bytes(result[:length])

    def test_matches_reference_for_multiple_lengths(self) -> None:
        master = bytes(range(32))
        for length in (1, 31, 32, 33, 64, 100):
            with self.subTest(length=length):
                self.assertEqual(
                    derive_key(master, "encryption", length),
                    self.reference(master, b"encryption", length),
                )

    def test_is_deterministic_and_separates_contexts(self) -> None:
        master = b"0" * 32
        encryption = derive_key(master, "encryption", 32)
        repeated = derive_key(master, "encryption", 32)
        authentication = derive_key(master, "authentication", 32)
        self.assertEqual(encryption, repeated)
        self.assertNotEqual(encryption, authentication)
        differing_bytes = sum(a != b for a, b in zip(encryption, authentication))
        self.assertGreaterEqual(differing_bytes, 24)

    def test_invalid_hierarchy_parameters_are_rejected(self) -> None:
        for master, context, length in (
            (b"", "context", 32),
            (b"master", "", 32),
            (b"master", "context", 0),
        ):
            with self.subTest(master=master, context=context, length=length):
                with self.assertRaises(ValueError):
                    derive_key(master, context, length)


if __name__ == "__main__":
    unittest.main()
