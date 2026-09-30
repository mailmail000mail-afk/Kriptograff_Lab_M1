import unittest

from Crypto.Cipher import AES

from cryptocore.authentication import AuthenticationError
from cryptocore.modes.gcm import GCM, GHASH, update_ghash_from_stream


KEY = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
NONCE = bytes.fromhex("cafebabefacedbaddecaf888")
PLAINTEXT_64 = bytes.fromhex(
    "d9313225f88406e5a55909c5aff5269a"
    "86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525"
    "b16aedf5aa0de657ba637b391aafd255"
)
AAD_64 = bytes.fromhex(
    "3ad77bb40d7a3660a89ecaf32466ef97"
    "f5d3d58503b9699de785895a96fdbaaf"
    "43b1cd7f598ece23881b00e3ed030688"
    "7b0c785e27e8ad3f8223207104725dd4"
)
CIPHERTEXT_64 = bytes.fromhex(
    "42831ec2217774244b7221b784d0d49c"
    "e3aa212f2c02a4e035c17e2329aca12e"
    "21d514b25466931c7d8f6a5aac84aa05"
    "1ba30b396a0aac973d58e091473f5985"
)


class VirtualStream:
    def __init__(self, total_size: int) -> None:
        self.remaining = total_size
        self.largest_request = 0

    def read(self, size: int) -> bytes:
        self.largest_request = max(self.largest_request, size)
        count = min(size, self.remaining)
        self.remaining -= count
        return b"x" * count


class CountingAccumulator:
    def __init__(self) -> None:
        self.total = 0

    def update_aad(self, data: bytes) -> None:
        self.total += len(data)

    def update_ciphertext(self, data: bytes) -> None:
        self.total += len(data)


class GcmNistTests(unittest.TestCase):
    def test_nist_examples_1_to_5(self) -> None:
        aad_20 = AAD_64[:20]
        plaintext_60 = PLAINTEXT_64[:60]
        examples = (
            (b"", b"", b"", "3247184b3c4f69a44dbcd22887bbb418"),
            (
                b"",
                PLAINTEXT_64,
                CIPHERTEXT_64,
                "4d5c2af327cd64a62cf35abd2ba6fab4",
            ),
            (AAD_64, b"", b"", "5f91d77123ef5eb9997913849b8dc1e9"),
            (
                AAD_64,
                PLAINTEXT_64,
                CIPHERTEXT_64,
                "64c0232904af398a5b67c10b53a5024d",
            ),
            (
                aad_20,
                plaintext_60,
                CIPHERTEXT_64[:60],
                "f07c2528eea2fca1211f905e1b6a881b",
            ),
        )
        for number, (aad, plaintext, ciphertext, tag_hex) in enumerate(examples, 1):
            with self.subTest(example=number):
                combined = GCM(KEY, NONCE).encrypt(plaintext, aad)
                self.assertEqual(combined, NONCE + ciphertext + bytes.fromhex(tag_hex))
                self.assertEqual(GCM(KEY, NONCE).decrypt(combined, aad), plaintext)

    def test_reference_library_for_nonce_and_message_lengths(self) -> None:
        for nonce_length in (8, 12, 20):
            nonce = bytes(range(nonce_length))
            for message_length, aad_length in ((0, 0), (1, 7), (17, 16), (73, 35)):
                with self.subTest(
                    nonce_length=nonce_length,
                    message_length=message_length,
                    aad_length=aad_length,
                ):
                    plaintext = bytes(range(message_length))
                    aad = bytes((index * 7) & 0xFF for index in range(aad_length))
                    reference = AES.new(KEY, AES.MODE_GCM, nonce=nonce, mac_len=16)
                    reference.update(aad)
                    expected_ciphertext, expected_tag = reference.encrypt_and_digest(plaintext)
                    actual = GCM(KEY, nonce).encrypt(plaintext, aad)
                    self.assertEqual(
                        actual, nonce + expected_ciphertext + expected_tag
                    )
                    self.assertEqual(GCM(KEY, nonce).decrypt(actual, aad), plaintext)

    def test_tampering_and_wrong_aad_fail_before_plaintext(self) -> None:
        aad = b"document metadata"
        combined = GCM(KEY, NONCE).encrypt(b"top secret data", aad)
        candidates = []
        wrong_ciphertext = bytearray(combined)
        wrong_ciphertext[12] ^= 1
        candidates.append((bytes(wrong_ciphertext), aad))
        wrong_tag = bytearray(combined)
        wrong_tag[-1] ^= 1
        candidates.append((bytes(wrong_tag), aad))
        candidates.append((combined, b"wrong metadata"))

        for data, supplied_aad in candidates:
            with self.subTest(data=data, aad=supplied_aad):
                with self.assertRaises(AuthenticationError):
                    GCM(KEY, NONCE).decrypt(data, supplied_aad)

    def test_ghash_streaming_matches_single_update(self) -> None:
        cipher = AES.new(KEY, AES.MODE_ECB)
        subkey = cipher.encrypt(bytes(16))
        aad = bytes(range(251)) * 3
        ciphertext = bytes(range(193)) * 4

        whole = GHASH(subkey)
        whole.update_aad(aad)
        whole.update_ciphertext(ciphertext)

        streamed = GHASH(subkey)
        for offset in range(0, len(aad), 13):
            streamed.update_aad(aad[offset : offset + 13])
        for offset in range(0, len(ciphertext), 29):
            streamed.update_ciphertext(ciphertext[offset : offset + 29])
        self.assertEqual(streamed.digest(), whole.digest())

    def test_virtual_aad_larger_than_one_gibibyte_is_chunked(self) -> None:
        total_size = (1 << 30) + 321
        stream = VirtualStream(total_size)
        accumulator = CountingAccumulator()
        processed = update_ghash_from_stream(
            accumulator, stream, aad=True, chunk_size=8192
        )
        self.assertEqual(processed, total_size)
        self.assertEqual(accumulator.total, total_size)
        self.assertEqual(stream.remaining, 0)
        self.assertLessEqual(stream.largest_request, 8192)

    def test_one_thousand_generated_nonces_are_unique(self) -> None:
        nonces = {GCM(KEY).nonce for _ in range(1000)}
        self.assertEqual(len(nonces), 1000)
        self.assertTrue(all(len(nonce) == 12 for nonce in nonces))

    def test_short_payloads_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "nonce и тег"):
            GCM(KEY, NONCE).decrypt(b"short")
        with self.assertRaisesRegex(ValueError, "16-байтного тега"):
            GCM(KEY, NONCE).decrypt_detached(b"short")


if __name__ == "__main__":
    unittest.main()
