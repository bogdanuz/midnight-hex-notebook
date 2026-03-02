"""Cryptographically secure PRNG — обёртки над secrets."""
import secrets
import logging

logger = logging.getLogger(__name__)


def secure_random_int(low: int, high: int) -> int:
    """Возвращает случайное int в [low, high] включительно (CSPRNG)."""
    if high < low:
        raise ValueError("high must be >= low")
    n = high - low + 1
    if n <= 0:
        return low
    return secrets.randbelow(n) + low


def secure_random_bytes(size: int) -> bytes:
    """Возвращает size криптографически стойких случайных байт."""
    if size < 0:
        raise ValueError("size must be >= 0")
    return secrets.token_bytes(size)
