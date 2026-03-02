"""Настройка логгера для приложения."""
import logging


def setup_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    log = logging.getLogger(name)
    log.setLevel(level)
    if not log.handlers:
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
        log.addHandler(h)
    return log
