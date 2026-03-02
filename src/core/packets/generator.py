"""Генерация junk-пакетов и паддинга по спеке AWG."""
import secrets
from typing import Union

from src.core.protocol.config import AWGConfig


def generate_junk_packet(size_min: int, size_max: int) -> bytes:
    """Генерирует один мусорный пакет криптографически стойким генератором."""
    if size_max < size_min:
        size_max = size_min
    size = secrets.randbelow(size_max - size_min + 1) + size_min
    return secrets.token_bytes(size)


def generate_junk_burst(config: AWGConfig) -> list[bytes]:
    """Генерирует серию junk пакетов перед хендшейком (AWG 1.5/2.0)."""
    if config.Jc <= 0:
        return []
    return [
        generate_junk_packet(config.Jmin, config.Jmax)
        for _ in range(config.Jc)
    ]


def get_header_value(h: Union[int, list]) -> int:
    """AWG 1.5: static int. AWG 2.0: случайное из диапазона [min, max]."""
    if isinstance(h, list):
        if len(h) < 2:
            return h[0] if h else 0
        lo, hi = int(h[0]), int(h[1])
        if hi <= lo:
            return lo
        return secrets.randbelow(hi - lo + 1) + lo
    return int(h)


def add_padding(data: bytes, pad_size: int) -> bytes:
    """Добавляет случайный паддинг к сообщению."""
    if pad_size <= 0:
        return data
    return data + secrets.token_bytes(pad_size)
