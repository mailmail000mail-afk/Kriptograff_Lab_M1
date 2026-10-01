"""Измерить время ручной реализации PBKDF2-HMAC-SHA256."""

from time import perf_counter

from cryptocore.kdf import pbkdf2_hmac_sha256


def main() -> None:
    for iterations in (10_000, 100_000, 1_000_000):
        started = perf_counter()
        pbkdf2_hmac_sha256(
            b"performance", b"0123456789abcdef", iterations, 32
        )
        elapsed = perf_counter() - started
        print(f"{iterations}: {elapsed:.3f} seconds")


if __name__ == "__main__":
    main()
