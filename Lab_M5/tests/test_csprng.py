from unittest import mock
import unittest

from cryptocore.csprng import CSPRNGError, generate_random_bytes, weak_key_reason


class CsprngTests(unittest.TestCase):
    def test_requested_length_and_empty_result(self) -> None:
        self.assertEqual(len(generate_random_bytes(16)), 16)
        self.assertEqual(generate_random_bytes(0), b"")

    def test_invalid_sizes_are_rejected(self) -> None:
        with self.assertRaises(TypeError):
            generate_random_bytes(1.5)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            generate_random_bytes(True)
        with self.assertRaises(ValueError):
            generate_random_bytes(-1)

    def test_operating_system_error_is_actionable(self) -> None:
        with mock.patch("cryptocore.csprng.os.urandom", side_effect=OSError("denied")):
            with self.assertRaisesRegex(CSPRNGError, "операционная система"):
                generate_random_bytes(16)

    def test_wrong_result_length_is_rejected(self) -> None:
        with mock.patch("cryptocore.csprng.os.urandom", return_value=b"short"):
            with self.assertRaisesRegex(CSPRNGError, "неверное количество"):
                generate_random_bytes(16)

    def test_one_thousand_keys_are_unique(self) -> None:
        keys = {generate_random_bytes(16) for _ in range(1000)}
        self.assertEqual(len(keys), 1000)

    def test_basic_hamming_weight_is_close_to_half(self) -> None:
        data = b"".join(generate_random_bytes(16) for _ in range(1000))
        ones = sum(bin(byte).count("1") for byte in data)
        ratio = ones / (len(data) * 8)
        self.assertGreater(ratio, 0.45)
        self.assertLess(ratio, 0.55)

    def test_simple_weak_key_patterns_are_detected(self) -> None:
        self.assertIsNotNone(weak_key_reason(bytes(16)))
        self.assertIsNotNone(weak_key_reason(bytes(range(16))))
        self.assertIsNotNone(weak_key_reason(bytes(range(15, -1, -1))))
        self.assertIsNone(weak_key_reason(bytes.fromhex("00112233445566778899aabbccddeeff")))


if __name__ == "__main__":
    unittest.main()
