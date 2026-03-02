"""Валидация конфига AWG — обёртка над AWGConfig.validate."""
from src.core.protocol.config import AWGConfig


def validate_config(config: AWGConfig) -> list[str]:
    """Возвращает список ошибок валидации; пустой список — конфиг корректен."""
    return config.validate()
