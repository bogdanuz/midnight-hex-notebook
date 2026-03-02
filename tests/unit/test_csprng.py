"""Тесты CSPRNG (secrets)."""
import os
import pytest
from src.core.crypto.csprng import secure_random_int, secure_random_bytes


class TestCSPRNG:
    def test_secure_random_int_range(self) -> None:
        for _ in range(1000):
            val = secure_random_int(0, 100)
            assert 0 <= val <= 100

    def test_distribution_is_roughly_uniform(self) -> None:
        buckets = [0] * 10
        for _ in range(10000):
            val = secure_random_int(0, 9)
            buckets[val] += 1
        assert all(500 < b < 1500 for b in buckets), (
            f"Распределение неравномерно: {buckets}"
        )

    def test_secure_random_bytes_length(self) -> None:
        for size in (11, 12, 3, 0):
            result = secure_random_bytes(size)
            assert len(result) == size

    def test_no_math_random_in_codebase(self) -> None:
        """Убеждаемся что random.random / random.randint не в crypto/packet/protocol."""
        violations = []
        for root, dirs, files in os.walk("src"):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for fname in files:
                if not fname.endswith(".py"):
                    continue
                path = os.path.join(root, fname)
                with open(path, encoding="utf-8") as f:
                    source = f.read()
                if "random.random()" in source or "random.randint" in source:
                    if (
                        "crypto" in path
                        or "packet" in path
                        or "protocol" in path
                        or "config" in path
                    ):
                        violations.append(path)
        assert violations == [], f"Небезопасный random в крипто-коде: {violations}"
