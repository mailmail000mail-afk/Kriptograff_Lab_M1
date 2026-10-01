import hashlib
import unittest

from cryptocore.hashes import SHA256, SHA3_256


class KnownAnswerTests(unittest.TestCase):
    def test_sha256_nist_vectors(self) -> None:
        vectors = (
            (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            (b"a" * 1_000_000, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
        )
        for message, expected in vectors:
            with self.subTest(length=len(message)):
                self.assertEqual(SHA256(message).hexdigest(), expected)

    def test_sha3_256_nist_vectors(self) -> None:
        vectors = (
            (b"", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
            (b"abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
            ),
            (b"a" * 1_000_000, "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1"),
        )
        for message, expected in vectors:
            with self.subTest(length=len(message)):
                self.assertEqual(SHA3_256(message).hexdigest(), expected)


class StreamingHashTests(unittest.TestCase):
    def test_chunk_boundaries_match_python_reference(self) -> None:
        for length in (1, 55, 56, 63, 64, 65, 135, 136, 137, 1000):
            message = bytes((index * 37 + 11) % 256 for index in range(length))
            with self.subTest(length=length, algorithm="sha256"):
                hasher = SHA256()
                for index in range(0, len(message), 7):
                    hasher.update(message[index : index + 7])
                self.assertEqual(hasher.hexdigest(), hashlib.sha256(message).hexdigest())
            with self.subTest(length=length, algorithm="sha3-256"):
                hasher = SHA3_256()
                for index in range(0, len(message), 11):
                    hasher.update(message[index : index + 11])
                self.assertEqual(hasher.hexdigest(), hashlib.sha3_256(message).hexdigest())

    def test_digest_does_not_finish_original_object(self) -> None:
        for hasher_class, reference in (
            (SHA256, hashlib.sha256),
            (SHA3_256, hashlib.sha3_256),
        ):
            with self.subTest(hasher=hasher_class.__name__):
                hasher = hasher_class(b"first")
                first = hasher.hexdigest()
                hasher.update(b" second")
                self.assertEqual(first, reference(b"first").hexdigest())
                self.assertEqual(hasher.hexdigest(), reference(b"first second").hexdigest())

    def test_avalanche_effect_after_one_bit_change(self) -> None:
        original = bytearray(b"CryptoCore avalanche effect test message")
        changed = original.copy()
        changed[0] ^= 0x01

        for hasher_class in (SHA256, SHA3_256):
            with self.subTest(hasher=hasher_class.__name__):
                first = hasher_class(original).digest()
                second = hasher_class(changed).digest()
                changed_bits = sum(
                    bin(left ^ right).count("1") for left, right in zip(first, second)
                )
                self.assertGreaterEqual(changed_bits, 100)
                self.assertLessEqual(changed_bits, 156)


if __name__ == "__main__":
    unittest.main()
