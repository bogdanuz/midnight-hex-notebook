"""Конфигурация протокола с валидацией (спека февраль 2026)."""
import secrets
import logging
from dataclasses import dataclass, field
from typing import Union

logger = logging.getLogger(__name__)

# --- Константы протокола (docs.amnezia.org) ---
AWG_15_JUNK_COUNT_MAX = 10
AWG_20_S4_MAX = 32
AWG_PADDING_MAX = 64
AWG_DEFAULT_MTU = 1420
AWG_JMIN_MIN = 64
AWG_JMAX_MAX = 1024


@dataclass
class AWGConfig:
    """Конфигурация протокола с валидацией по спеке."""

    version: str  # "1.5" или "2.0"

    # Junk packets (1.5 и 2.0)
    Jc: int = 4
    Jmin: int = 64
    Jmax: int = 256

    # Padding
    S1: int = 0
    S2: int = 0
    S3: int = 0  # только 2.0
    S4: int = 0  # только 2.0, ≤ 32

    # Headers — статика для 1.5, диапазоны [min, max] для 2.0
    H1: Union[int, list] = 1
    H2: Union[int, list] = 2
    H3: Union[int, list] = 3
    H4: Union[int, list] = 4

    # Signature packets (bytes)
    I1: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    I2: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    I3: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    I4: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    I5: bytes = field(default_factory=lambda: secrets.token_bytes(32))

    def validate(self) -> list[str]:
        errors = []
        if self.S1 + 56 == self.S2:
            errors.append(
                f"CRITICAL: S1+56 == S2 ({self.S1}+56={self.S2}) — "
                "это совпадает со стандартным WireGuard, DPI обнаружит!"
            )
        if self.S4 > AWG_20_S4_MAX:
            errors.append(f"S4={self.S4} превышает максимум {AWG_20_S4_MAX}")
        if self.Jmax >= AWG_DEFAULT_MTU:
            errors.append(
                f"Jmax={self.Jmax} >= MTU={AWG_DEFAULT_MTU}, пакеты будут фрагментированы"
            )
        if self.Jmin > self.Jmax:
            errors.append(f"Jmin={self.Jmin} > Jmax={self.Jmax}")
        if self.Jc > AWG_15_JUNK_COUNT_MAX:
            errors.append(f"Jc={self.Jc} превышает максимум {AWG_15_JUNK_COUNT_MAX}")
        if self.version == "2.0":
            for name, val in [
                ("H1", self.H1),
                ("H2", self.H2),
                ("H3", self.H3),
                ("H4", self.H4),
            ]:
                if isinstance(val, int):
                    errors.append(
                        f"{name} должен быть диапазоном [min,max] в AWG 2.0, получен int"
                    )
        return errors


def generate_awg20_config_defaults() -> AWGConfig:
    """Генерирует безопасные дефолтные параметры для AWG 2.0."""
    base = secrets.randbelow(0x7FFFFFFF - 0x10000) + 0x10000
    step = secrets.randbelow(0x1000) + 0x100

    Jmin = secrets.randbelow(200) + AWG_JMIN_MIN
    Jmax = Jmin + secrets.randbelow(min(AWG_JMAX_MAX - Jmin, 400))
    if Jmax > AWG_JMAX_MAX:
        Jmax = AWG_JMAX_MAX

    cfg = AWGConfig(
        version="2.0",
        Jc=secrets.randbelow(AWG_15_JUNK_COUNT_MAX + 1),
        Jmin=Jmin,
        Jmax=Jmax,
        S1=secrets.randbelow(50) + 5,
        S2=0,
        S3=secrets.randbelow(AWG_PADDING_MAX + 1),
        S4=secrets.randbelow(AWG_20_S4_MAX + 1),
        H1=[base, base + step - 1],
        H2=[base + step, base + 2 * step - 1],
        H3=[base + 2 * step, base + 3 * step - 1],
        H4=[base + 3 * step, base + 4 * step - 1],
    )
    cfg.S2 = cfg.S1 + 57
    if cfg.S2 > AWG_PADDING_MAX:
        cfg.S2 = cfg.S1 - 1 if cfg.S1 > 0 else 1

    errors = cfg.validate()
    if errors:
        for e in errors:
            logger.error("Config validation: %s", e)
        raise ValueError(f"Сгенерированный конфиг не прошёл валидацию: {errors}")

    return cfg
