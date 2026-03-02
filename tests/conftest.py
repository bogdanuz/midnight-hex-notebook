"""Pytest fixtures для AWG тестов."""
import pytest
from src.core.protocol.config import AWGConfig


@pytest.fixture
def awg15_config() -> AWGConfig:
    return AWGConfig(
        version="1.5",
        Jc=4,
        Jmin=40,
        Jmax=70,
        S1=15,
        S2=56 + 1,
        H1=1234567890,
        H2=987654321,
        H3=111222333,
        H4=444555666,
    )


@pytest.fixture
def awg20_config() -> AWGConfig:
    return AWGConfig(
        version="2.0",
        Jc=5,
        Jmin=64,
        Jmax=256,
        S1=20,
        S2=30,
        S3=15,
        S4=8,
        H1=[100, 199],
        H2=[200, 299],
        H3=[300, 399],
        H4=[400, 499],
    )


@pytest.fixture
def invalid_config_s1s2() -> AWGConfig:
    """S1 + 56 == S2 — должна провалить валидацию."""
    return AWGConfig(
        version="1.5",
        S1=0,
        S2=56,
        H1=1,
        H2=2,
        H3=3,
        H4=4,
    )
